/*
 * Copyright (c) 2022 NVIDIA Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <stdint.h>

#include "conntrack-offload.h"
#include "conntrack-private.h"
#include "conntrack-tp.h"
#include "conntrack.h"
#include "coverage.h"
#include "ct-dist.h"
#include "ct-dist-msg.h"
#include "ct-dist-private.h"
#include "ct-dist-thread.h"
#include "ct-dist.h"
#include "dp-packet.h"
#include "dpif.h"
#include "dpif-netdev-private.h"
#include "mpsc-queue.h"
#include "netlink.h"
#include "openvswitch/flow.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ovs-atomic.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "smap.h"
#include "timeval.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ctd_thread);

COVERAGE_DEFINE(ctd_long_cleanup);
COVERAGE_DEFINE(ctd_clean_10s_latency);
COVERAGE_DEFINE(ctd_clean_5s_latency);
COVERAGE_DEFINE(ctd_clean_2s_latency);
COVERAGE_DEFINE(ctd_clean_1s_latency);

#define CT_THREAD_BACKOFF_MIN 1
#define CT_THREAD_BACKOFF_MAX 64
#define CT_THREAD_QUIESCE_INTERVAL_MS 10

DEFINE_EXTERN_PER_THREAD_DATA(ct_thread_id, OVSTHREAD_ID_UNSET);
unsigned int ctd_n_threads;

void
ctd_send_msg_to_thread(struct ctd_msg *m, unsigned int id)
{
    struct ct_thread *thread;

    thread = &m->ct->threads[id];
    mpsc_queue_insert(&thread->queue, &m->node);
}

static void *
ct_thread_main(void *arg)
{
    struct ctd_msg_conn_clean *clean_msg = NULL;
    struct mpsc_queue_node *queue_node;
    struct ct_thread *thread = arg;
    struct dp_packet *pkt = NULL;
    long long int next_rcu_ms;
    long long int now_ms;
    struct ctd_msg *m;
    uint64_t backoff;

    *ct_thread_id_get() = thread - thread->ct->threads;
    mpsc_queue_acquire(&thread->queue);

    backoff = CT_THREAD_BACKOFF_MIN;
    next_rcu_ms = time_msec() + CT_THREAD_QUIESCE_INTERVAL_MS;

    for (;;) {
        queue_node = mpsc_queue_pop(&thread->queue);
        if (queue_node == NULL) {
            /* The thread is flagged as quiescent during xnanosleep(). */
            xnanosleep(backoff * 1E6);
            if (backoff < CT_THREAD_BACKOFF_MAX) {
                backoff <<= 1;
            }
            continue;
        }

        now_ms = time_msec();
        backoff = CT_THREAD_BACKOFF_MIN;

        m = CONTAINER_OF(queue_node, struct ctd_msg, node);
        // handle ctd_msg
        switch (m->msg_type) {
        case CTD_MSG_EXEC:
        case CTD_MSG_EXEC_NAT:
        case CTD_MSG_NAT_CANDIDATE_RESPONSE:
            pkt = CONTAINER_OF(m, struct dp_packet, cme);
            ctd_conntrack_execute(pkt);
            break;
        case CTD_MSG_NAT_CANDIDATE:
            pkt = CONTAINER_OF(m, struct dp_packet, cme);
            ctd_nat_candidate(pkt);
            break;
        case CTD_MSG_CLEAN:
            clean_msg = CONTAINER_OF(m, struct ctd_msg_conn_clean, hdr);
            ctd_conn_clean(clean_msg);
            break;
        default:
            OVS_NOT_REACHED();
        }

        switch (m->msg_fate) {
        case CTD_MSG_FATE_TBD:
        default:
            OVS_NOT_REACHED();
        case CTD_MSG_FATE_PMD:
            /* Send back to the PMD. */
            ctd_msg_fate_set(m, CTD_MSG_FATE_TBD);
            mpsc_queue_insert(&pkt->cme.pmd->ct2pmd.queue, &m->node);
            break;
        case CTD_MSG_FATE_CTD:
            ctd_msg_fate_set(m, CTD_MSG_FATE_TBD);
            ctd_send_msg_to_thread(m, ctd_h2tid(m->dest_hash));
            break;
        case CTD_MSG_FATE_SELF:
            ctd_msg_fate_set(m, CTD_MSG_FATE_TBD);
            ctd_send_msg_to_thread(m, ct_thread_id());
            break;
        case CTD_MSG_FATE_FREE:
            free(clean_msg);
            break;
        }

        /* Do RCU synchronization at fixed interval. */
        if (now_ms > next_rcu_ms) {
            ovsrcu_quiesce();
            next_rcu_ms = time_msec() + CT_THREAD_QUIESCE_INTERVAL_MS;
        }
    }

    mpsc_queue_release(&thread->queue);
    return NULL;
}

static void
ctd_conn_batch_clean(struct conntrack *ct,
                     struct conn **conns, size_t *batch_count,
                     long long int now)
{
    uint32_t hash;
    size_t i;

    if (*batch_count == 0) {
        return;
    }

    for (i = 0; i < *batch_count; i++) {
        long long int latency = now - conn_expiration(conns[i]);

        if (latency >= 10000) {
            COVERAGE_INC(ctd_clean_10s_latency);
        } else if (latency >= 5000) {
            COVERAGE_INC(ctd_clean_5s_latency);
        } else if (latency >= 2000) {
            COVERAGE_INC(ctd_clean_2s_latency);
        } else if (latency >= 1000) {
            COVERAGE_INC(ctd_clean_1s_latency);
        }

        hash = conn_key_hash(&conns[i]->key, ct->hash_basis);
        ctd_msg_conn_clean_send(ct, conns[i], hash);
    }

    *batch_count = 0;
}

#define CT_SWEEP_BATCH_SIZE 32
#define CT_SWEEP_QUIESCE_INTERVAL_MS 10
#define CT_SWEEP_TIMEOUT_MS (1000 - CT_SWEEP_QUIESCE_INTERVAL_MS - 1)

/* Delete the expired connections from 'ctb', up to 'limit'. Returns the
 * earliest expiration time among the remaining connections in 'ctb'.  Returns
 * LLONG_MAX if 'ctb' is empty.  The return value might be smaller than 'now',
 * if 'limit' is reached */
static long long
ctd_ct_sweep(struct conntrack *ct, long long now, size_t limit)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct conntrack_offload_class *offload_class = NULL;
    struct conn *conn_batch[CT_SWEEP_BATCH_SIZE];
    struct mpsc_queue_node *node;
    size_t batch_count = 0;
    long long min_expiration = LLONG_MAX;
    long long int next_rcu_quiesce;
    long long int start = now;
    size_t count = 0;
    int rv_active;

    next_rcu_quiesce = now + CT_SWEEP_QUIESCE_INTERVAL_MS;
    for (unsigned i = 0; i < N_CT_TM; i++) {
        struct conn *end_of_queue = NULL;

        if (now >= next_rcu_quiesce) {
rcu_quiesce:
            /* Do not delay further releasing batched conns if any. */
            ctd_conn_batch_clean(ct, conn_batch, &batch_count, now);
            ovsrcu_quiesce();
            now = time_msec();
            next_rcu_quiesce = now + CT_SWEEP_QUIESCE_INTERVAL_MS;
            offload_class = NULL;
        }
        if (!offload_class) {
            offload_class = ovsrcu_get(struct conntrack_offload_class *,
                                       &ct->offload_class);
        }

        MPSC_QUEUE_FOR_EACH_POP (node, &ct->exp_lists[i]) {
            long long int expiration;
            struct conn *conn;

            conn = CONTAINER_OF(node, struct conn, exp.node);
            if (conn_unref(conn)) {
                /* Node was destroyed by RCU calls. */
                continue;
            }

            if (conn == end_of_queue) {
                /* If we already re-enqueued this conn during this sweep,
                 * stop iterating this list and skip to the next.
                 */
                min_expiration = MIN(min_expiration, conn_expiration(conn));
                conn_expire_push_back(ct, conn);
                break;
            }

            if (now - start >= CT_SWEEP_TIMEOUT_MS) {
                min_expiration = MIN(min_expiration, conn_expiration(conn));
                conn_expire_push_back(ct, conn);
                goto out;
            }

            rv_active = conn_hw_update(ct, offload_class, conn,
                                       &conn->exp.tm, now);
            if (rv_active == EAGAIN) {
                /* Impossible to query offload status, try later. */
                conn_expire_push_front(ct, conn);
                goto rcu_quiesce;
            }

            expiration = conn_expiration(conn);

            if (now < expiration) {
                if (atomic_flag_test_and_set(&conn->exp.reschedule)) {
                    /* Reschedule was true, another thread marked
                     * this conn to be enqueued again.
                     * The conn is not yet expired, still valid, and
                     * this list should still be iterated.
                     */
                    conn_expire_push_back(ct, conn);
                    if (end_of_queue == NULL) {
                        end_of_queue = conn;
                    }
                } else {
                    /* This connection is still valid, while no other thread
                     * modified it: it means this list iteration is finished
                     * for now. Put front the connection within the list.
                     */
                    atomic_flag_clear(&conn->exp.reschedule);
                    conn_expire_push_front(ct, conn);
                    min_expiration = MIN(min_expiration, expiration);
                    break;
                }
            } else {
                conn_batch[batch_count++] = conn;
                if (batch_count == ARRAY_SIZE(conn_batch)) {
                    ctd_conn_batch_clean(ct, conn_batch, &batch_count, now);
                }
                count++;
                if (count >= limit) {
                    min_expiration = MIN(min_expiration, expiration);
                    /* Do not check other lists. */
                    COVERAGE_INC(ctd_long_cleanup);
                    goto out;
                }
            }

            /* Attempt quiescing at fixed interval. */
            if (time_msec() >= next_rcu_quiesce) {
                goto rcu_quiesce;
            }
        }
    }

out:
    ctd_conn_batch_clean(ct, conn_batch, &batch_count, now);
    if (count > 0) {
        VLOG_DBG("conntrack cleanup %"PRIuSIZE" entries in %lld msec", count,
                 time_msec() - start);
    }
    return min_expiration;
}

/* Cleans up old connection entries from 'ct'.  Returns the time when the
 * next expiration might happen.  The return value might be smaller than
 * 'now', meaning that an internal limit has been reached, and some expired
 * connections have not been deleted. */
static long long
ctd_conntrack_clean(struct conntrack *ct, long long now)
{
    unsigned int n_conn_limit;
    atomic_read_relaxed(&ct->n_conn_limit, &n_conn_limit);
    size_t clean_max = n_conn_limit > 10 ? n_conn_limit / 10 : 1;
    long long min_exp = ctd_ct_sweep(ct, now, clean_max);
    long long next_wakeup = MIN(min_exp, now + CT_DPIF_NETDEV_TP_MIN_MS);

    return next_wakeup;
}

/* Cleanup:
 *
 * We must call conntrack_clean() periodically.  conntrack_clean() return
 * value gives an hint on when the next cleanup must be done (either because
 * there is an actual connection that expires, or because a new connection
 * might be created with the minimum timeout).
 *
 * We want to reduce the number of wakeups and batch connection cleanup
 * when the load is not very high.  CT_CLEAN_INTERVAL ensures that if we
 * are coping with the current cleanup tasks, then we wait at least
 * 5 seconds to do further cleanup.
 */
#define CT_CLEAN_INTERVAL 5000 /* 5 seconds */

static void *
ctd_clean_thread_main(void *ct_)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct conntrack *ct = ct_;

    for (unsigned i = 0; i < N_CT_TM; i++) {
        mpsc_queue_acquire(&ct->exp_lists[i]);
    }

    while (!latch_is_set(&ct->clean_thread_exit)) {
        long long next_wake = ctd_conntrack_clean(ct, time_msec());
        long long now = time_msec();

        if (next_wake > now) {
            poll_timer_wait_until(MIN(next_wake, now + CT_CLEAN_INTERVAL));
        } else {
            poll_immediate_wake();
        }
        latch_wait(&ct->clean_thread_exit);
        poll_block();
    }

    for (unsigned i = 0; i < N_CT_TM; i++) {
        mpsc_queue_release(&ct->exp_lists[i]);
    }

    return NULL;
}

void
ctd_thread_create(struct conntrack *ct)
{
    unsigned int tid;

    ct->threads = xcalloc(ctd_n_threads, sizeof *ct->threads);

    for (tid = 0; tid < ctd_n_threads; tid++) {
        struct ct_thread *thread;

        thread = &ct->threads[tid];
        mpsc_queue_init(&thread->queue);
        thread->ct = ct;
        ovs_thread_create("ct", ct_thread_main, thread);
    }

    latch_set(&ct->clean_thread_exit);
    pthread_join(ct->clean_thread, NULL);
    latch_destroy(&ct->clean_thread_exit);
    latch_init(&ct->clean_thread_exit);
    ct->clean_thread = ovs_thread_create("ctd_clean", ctd_clean_thread_main,
                                         ct);
}
