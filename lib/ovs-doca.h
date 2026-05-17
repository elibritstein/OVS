/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef OVS_DOCA_H
#define OVS_DOCA_H

#include "netdev.h"
#include "ovs-thread.h"
#include "smap.h"
#include "util.h"
#include "vswitch-idl.h"

#ifdef DOCA_NETDEV

#include <doca_dev.h>
#include <doca_flow.h>

#define AUX_QUEUE 0
#define OVS_DOCA_MAX_OFFLOAD_QUEUES 1
#define OVS_DOCA_QUEUE_DEPTH 32
#define OVS_DOCA_ENTRY_PROCESS_TIMEOUT_US 1000

/* Estimated maximum number of megaflows */
#define OVS_DOCA_MAX_MEGAFLOWS_COUNTERS (1 << 19)

#define OVS_DOCA_MAX_PIPE_NAME_LEN 32

struct netdev_doca_esw_ctx;

struct ovs_doca_offload_queue {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        unsigned int n_waiting_entries;
    );
};

struct ovs_doca_flow_actions {
    struct doca_flow_actions d;
    ovs_be32 mark;
};
BUILD_ASSERT_DECL(offsetof(struct ovs_doca_flow_actions, d) == 0);

struct ovs_doca_flow_match {
    struct doca_flow_match d;
};
BUILD_ASSERT_DECL(offsetof(struct ovs_doca_flow_match, d) == 0);

doca_error_t ovs_doca_add_entry(struct netdev *,
                                unsigned int qid,
                                struct doca_flow_pipe *,
                                const struct ovs_doca_flow_match *,
                                const struct ovs_doca_flow_actions *,
                                const struct doca_flow_monitor *,
                                const struct doca_flow_fwd *,
                                uint32_t flags,
                                struct doca_flow_pipe_entry **pentry);

doca_error_t ovs_doca_remove_entry(struct netdev_doca_esw_ctx *esw,
                                   unsigned int qid, uint32_t flags,
                                   struct doca_flow_pipe_entry **entry);

void ovs_doca_destroy_pipe(struct doca_flow_pipe **ppipe);

doca_error_t ovs_doca_pipe_create(struct netdev *netdev,
                                  struct ovs_doca_flow_match *ovs_match,
                                  struct ovs_doca_flow_match *ovs_match_mask,
                                  struct doca_flow_monitor *,
                                  struct ovs_doca_flow_actions *ovs_actions,
                                  struct ovs_doca_flow_actions
                                      *ovs_actions_mask,
                                  struct doca_flow_action_desc *,
                                  struct doca_flow_fwd *fwd,
                                  struct doca_flow_fwd *fwd_miss,
                                  uint32_t nr_entries,
                                  bool is_egress, bool is_root,
                                  uint64_t queues_bitmap,
                                  const char *pipe_str,
                                  struct doca_flow_pipe **pipe);

doca_error_t ovs_doca_pipe_cfg_allow_queues(struct doca_flow_pipe_cfg *cfg,
                                            uint64_t queues_bitmap);

unsigned int ovs_doca_max_counters(void);

void ovs_doca_flow_limit_config_changed(unsigned int cfg_flow_limit);

#endif /* DOCA_NETDEV */

void ovs_doca_init(const struct smap *ovs_other_config);
void print_doca_version(void);
void ovs_doca_status(const struct ovsrec_open_vswitch *);

#endif /* OVS_DOCA_H */
