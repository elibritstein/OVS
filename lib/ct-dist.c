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
#include "dp-packet.h"
#include "dpif.h"
#include "dpif-netdev-private.h"
#include "mpsc-queue.h"
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

static void *ct_thread_main(void *arg);
static unsigned int n_threads;
DEFINE_EXTERN_PER_THREAD_DATA(ct_thread_id, OVSTHREAD_ID_UNSET);

void
ct_dist_init(struct conntrack *ct, const struct smap *ovs_other_config)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    unsigned int tid;

    if (!ovsthread_once_start(&once)) {
        return;
    }

    n_threads = smap_get_ullong(ovs_other_config, "n-ct-threads",
                                DEFAULT_CT_DIST_THREAD_NB);
    if (n_threads > MAX_CT_DIST_THREAD_NB) {
        VLOG_WARN("Invalid number of threads requested: %u. Limiting to %u",
                  n_threads, MAX_CT_DIST_THREAD_NB);
        n_threads = MAX_CT_DIST_THREAD_NB;
    }

    ct->n_threads = n_threads;
    if (n_threads == 0) {
        goto out;
    }

    ct->threads = xcalloc(n_threads, sizeof *ct->threads);

    for (tid = 0; tid < n_threads; tid++) {
        struct ct_thread *thread;

        thread = &ct->threads[tid];
        mpsc_queue_init(&thread->queue);
        thread->ct = ct;
        ovs_thread_create("ct", ct_thread_main, thread);
    }

out:
    ovsthread_once_done(&once);
}

static void
ct_dist_exec_pkt(struct dp_packet *pkt)
{
    ctd_conntrack_execute(pkt);
}

static void *
ct_thread_main(void *arg)
{
    struct mpsc_queue_node *queue_node;
    struct ct_thread *thread = arg;
    long long int next_rcu_ms;
    struct dp_packet *pkt;
    long long int now_ms;
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

        pkt = CONTAINER_OF(queue_node, struct dp_packet, node);
        // handle pkt
        switch (pkt->ct_type) {
        case CT_TYPE_EXEC:
            ct_dist_exec_pkt(pkt);
            break;
        default:
            OVS_NOT_REACHED();
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
