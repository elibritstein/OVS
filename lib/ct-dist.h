/*
 * Copyright (c) 2023 NVIDIA Corporation.
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
#define CT_DIST_H

#include <stdint.h>

#include "conntrack.h"
#include "ct-dist-msg.h"
#include "ct-dist-private.h"
#include "smap.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct dp_netdev_flow;
struct dp_netdev_pmd_thread;
struct dp_packet;
struct dp_packet_batch;
struct flow;
struct nlattr;

void ctd_init(struct conntrack *ct, const struct smap *ovs_other_config);
bool ctd_exec(struct conntrack *conntrack,
              struct dp_netdev_pmd_thread *pmd,
              const struct flow *flow,
              struct dp_packet_batch *packets_,
              const struct nlattr *ct_action,
              struct dp_netdev_flow *dp_flow,
              const struct nlattr *actions,
              size_t actions_len,
              uint32_t depth);
int ctd_flush(struct conntrack *, const uint16_t *zone);
int ctd_flush_tuple(struct conntrack *, const struct ct_dpif_tuple *,
                    uint16_t zone);

#ifdef  __cplusplus
}
#endif

#endif /* CT_DIST_H */
