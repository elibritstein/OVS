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

#include "conntrack-private.h"
#include "conntrack.h"
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
#include "openvswitch/vlog.h"
#include "ovs-atomic.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "smap.h"
#include "timeval.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ct_dist);

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
