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

#ifndef CT_DIST_H
#define CT_DIST_H 1

#include "mpsc-queue.h"
#include "ovs-atomic.h"
#include "ovs-thread.h"
#include "util.h"

struct conntrack;
struct dp_netdev_flow;
struct dp_netdev_pmd_thread;
struct dp_packet;
struct dp_packet_batch;
struct flow;
struct nlattr;
struct smap;

#define DEFAULT_CT_DIST_THREAD_NB 0
#define MAX_CT_DIST_THREAD_NB     10
DECLARE_EXTERN_PER_THREAD_DATA(unsigned int, ct_thread_id);

#ifdef  __cplusplus
extern "C" {
#endif

struct ct_thread {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct mpsc_queue queue;
        struct conntrack *ct;
    );
};

void
ct_dist_init(struct conntrack *ct, const struct smap *ovs_other_config);

static inline unsigned int
ct_thread_id(void)
{
    unsigned int id;

    id = *ct_thread_id_get();
    ovs_assert(id != OVSTHREAD_ID_UNSET);

    return id;
}

bool
ct_dist_exec(struct conntrack *conntrack,
             struct dp_netdev_pmd_thread *pmd,
             const struct flow *flow,
             struct dp_packet_batch *packets_,
             const struct nlattr *ct_action,
             struct dp_netdev_flow *dp_flow,
             const struct nlattr *actions,
             size_t actions_len,
             uint32_t depth);
unsigned int
ct_dist_hash_to_thread_id(uint32_t hash);
void
send_pkt_to_ct_thread(struct dp_packet *pkt, uint32_t hash);

#ifdef  __cplusplus
}
#endif

#endif /* CT_DIST_H */
