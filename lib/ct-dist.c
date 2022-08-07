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
    struct ct_exec *e = &pkt->ct_exec;

    ctd_conntrack_execute(pkt);

    /* Send back to the PMD. */
    mpsc_queue_insert(&e->pmd->ct2pmd.queue, &pkt->node);
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

bool
ct_dist_exec(struct conntrack *conntrack,
             struct dp_netdev_pmd_thread *pmd,
             const struct flow *flow,
             struct dp_packet_batch *packets_,
             const struct nlattr *ct_action,
             struct dp_netdev_flow *dp_flow OVS_UNUSED,
             const struct nlattr *actions OVS_UNUSED,
             size_t actions_len OVS_UNUSED,
             uint32_t depth OVS_UNUSED)
{
    const struct ovs_key_ct_labels *setlabel = NULL;
    struct nat_action_info_t *nat_action_info_ref;
    struct nat_action_info_t nat_action_info;
    struct dp_packet OVS_UNUSED *packet;
    const uint32_t *setmark = NULL;
    const char *helper = NULL;
    bool nat_config = false;
    const struct nlattr *b;
    bool commit = false;
    bool force = false;
    uint32_t tp_id = 0;
    unsigned int left;
    uint16_t zone = 0;

    nat_action_info_ref = NULL;
    NL_ATTR_FOR_EACH_UNSAFE (b, left, nl_attr_get(ct_action),
                             nl_attr_get_size(ct_action)) {
        enum ovs_ct_attr sub_type = nl_attr_type(b);

        switch(sub_type) {
        case OVS_CT_ATTR_FORCE_COMMIT:
            force = true;
            /* fall through. */
        case OVS_CT_ATTR_COMMIT:
            commit = true;
            break;
        case OVS_CT_ATTR_ZONE:
            zone = nl_attr_get_u16(b);
            break;
        case OVS_CT_ATTR_HELPER:
            helper = nl_attr_get_string(b);
            break;
        case OVS_CT_ATTR_MARK:
            setmark = nl_attr_get(b);
            break;
        case OVS_CT_ATTR_LABELS:
            setlabel = nl_attr_get(b);
            break;
        case OVS_CT_ATTR_EVENTMASK:
            /* Silently ignored, as userspace datapath does not generate
             * netlink events. */
            break;
        case OVS_CT_ATTR_TIMEOUT:
            if (!str_to_uint(nl_attr_get_string(b), 10, &tp_id)) {
                VLOG_WARN("Invalid Timeout Policy ID: %s.",
                          nl_attr_get_string(b));
                tp_id = DEFAULT_TP_ID;
            }
            break;
        case OVS_CT_ATTR_NAT: {
            const struct nlattr *b_nest;
            unsigned int left_nest;
            bool ip_min_specified = false;
            bool proto_num_min_specified = false;
            bool ip_max_specified = false;
            bool proto_num_max_specified = false;
            memset(&nat_action_info, 0, sizeof nat_action_info);
            nat_action_info_ref = &nat_action_info;

            NL_NESTED_FOR_EACH_UNSAFE (b_nest, left_nest, b) {
                enum ovs_nat_attr sub_type_nest = nl_attr_type(b_nest);

                switch (sub_type_nest) {
                case OVS_NAT_ATTR_SRC:
                case OVS_NAT_ATTR_DST:
                    nat_config = true;
                    nat_action_info.nat_action |=
                        ((sub_type_nest == OVS_NAT_ATTR_SRC)
                            ? NAT_ACTION_SRC : NAT_ACTION_DST);
                    break;
                case OVS_NAT_ATTR_IP_MIN:
                    memcpy(&nat_action_info.min_addr,
                           nl_attr_get(b_nest),
                           nl_attr_get_size(b_nest));
                    ip_min_specified = true;
                    break;
                case OVS_NAT_ATTR_IP_MAX:
                    memcpy(&nat_action_info.max_addr,
                           nl_attr_get(b_nest),
                           nl_attr_get_size(b_nest));
                    ip_max_specified = true;
                    break;
                case OVS_NAT_ATTR_PROTO_MIN:
                    nat_action_info.min_port =
                        nl_attr_get_u16(b_nest);
                    proto_num_min_specified = true;
                    break;
                case OVS_NAT_ATTR_PROTO_MAX:
                    nat_action_info.max_port =
                        nl_attr_get_u16(b_nest);
                    proto_num_max_specified = true;
                    break;
                case OVS_NAT_ATTR_PERSISTENT:
                case OVS_NAT_ATTR_PROTO_HASH:
                case OVS_NAT_ATTR_PROTO_RANDOM:
                    break;
                case OVS_NAT_ATTR_UNSPEC:
                case __OVS_NAT_ATTR_MAX:
                    OVS_NOT_REACHED();
                }
            }

            if (ip_min_specified && !ip_max_specified) {
                nat_action_info.max_addr = nat_action_info.min_addr;
            }
            if (proto_num_min_specified && !proto_num_max_specified) {
                nat_action_info.max_port = nat_action_info.min_port;
            }
            if (proto_num_min_specified || proto_num_max_specified) {
                if (nat_action_info.nat_action & NAT_ACTION_SRC) {
                    nat_action_info.nat_action |= NAT_ACTION_SRC_PORT;
                } else if (nat_action_info.nat_action & NAT_ACTION_DST) {
                    nat_action_info.nat_action |= NAT_ACTION_DST_PORT;
                }
            }
            break;
        }
        case OVS_CT_ATTR_UNSPEC:
        case __OVS_CT_ATTR_MAX:
            OVS_NOT_REACHED();
        }
    }

    /* We won't be able to function properly in this case, hence
     * complain loudly. */
    if (nat_config && !commit) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        VLOG_WARN_RL(&rl, "NAT specified without commit.");
    }

    if (n_threads == 0) {
        conntrack_execute(conntrack, packets_, flow->dl_type, force,
                          commit, zone, setmark, setlabel, flow->tp_src,
                          flow->tp_dst, helper, nat_action_info_ref,
                          pmd->ctx.now, tp_id);
        return false;
    }

    /* Each packet is sent separately on a message to the appropriate
     * ct-thread (by its ct-hash).
     * Batching it is TBD.
     */
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        struct ct_exec *e = &packet->ct_exec;

        packet->ct_type = CT_TYPE_EXEC;
        packet->timestamp_ms = pmd->ctx.now / 1000;
        *e = (struct ct_exec) {
            .ct = conntrack,
            .dl_type = flow->dl_type,
            .force = force,
            .commit = commit,
            .zone = zone,
            .setmark = setmark,
            .setlabel = setlabel,
            .tp_src = flow->tp_src,
            .tp_dst = flow->tp_dst,
            .helper = helper,
            .nat_action_info = nat_action_info,
            .nat_action_info_ref = NULL,
            .tp_id = tp_id,
            .pmd = pmd,
            .flow = dp_flow,
            .actions_len = actions_len,
            .depth = depth,
        };
        if (nat_action_info_ref) {
            e->nat_action_info_ref = &e->nat_action_info;
        }
        conn_key_extract(conntrack, packet, e->dl_type, &e->ct_lookup_ctx,
                         e->zone);

        if (dp_flow) {
            dp_netdev_flow_ref(dp_flow);
        }
        memcpy(e->actions_buf, actions, actions_len);
        send_pkt_to_ct_thread(packet, e->ct_lookup_ctx.hash);
    }

    /* Empty the batch, to stop its processing in this context.
     * It will be completed in the ct2pmd context.
     */
    dp_packet_batch_init(packets_);

    return true;
}

unsigned int
ct_dist_hash_to_thread_id(uint32_t hash)
{
    return fastrange32(hash, n_threads);
}

void
send_pkt_to_ct_thread(struct dp_packet *packet, uint32_t hash)
{
    struct ct_exec *e = &packet->ct_exec;
    struct ct_thread *thread;
    unsigned int tid;

    tid = ct_dist_hash_to_thread_id(hash);
    thread = &e->ct->threads[tid];
    mpsc_queue_insert(&thread->queue, &packet->node);
}
