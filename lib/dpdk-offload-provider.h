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

#ifndef DPDK_OFFLOAD_PROVIDER_H
#define DPDK_OFFLOAD_PROVIDER_H

#include <stdbool.h>
#include <stdint.h>

#include <rte_flow.h>

#include "netdev-provider.h"
#include "dp-packet.h"

#define CT_TABLE_ID      0xfc000000
#define CTNAT_TABLE_ID   0xfc100000
#define POSTCT_TABLE_ID  0xfd000000
#define E2E_BASE_TABLE_ID  0xfe000000
#define MISS_TABLE_ID    (UINT32_MAX - 1)
#define MIN_TABLE_ID     1
#define MAX_TABLE_ID     0xf0000000
#define NUM_TABLE_ID     (MAX_TABLE_ID - MIN_TABLE_ID + 1)

struct dpdk_offload_recovery_info {
    uint32_t flow_miss_id;
    uint32_t ct_miss_id;
    uint32_t sflow_id;
};

enum dpdk_reg_id {
    REG_FIELD_CT_STATE,
    REG_FIELD_CT_ZONE,
    REG_FIELD_CT_MARK,
    REG_FIELD_CT_LABEL_ID,
    REG_FIELD_TUN_INFO,
    REG_FIELD_CT_CTX,
    REG_FIELD_SFLOW_CTX,
    REG_FIELD_NUM,
};

enum reg_type {
    REG_TYPE_TAG,
    REG_TYPE_META,
};

struct reg_field {
    enum reg_type type;
    uint8_t index;
    uint32_t offset;
    uint32_t mask;
};

#define REG_TAG_INDEX_NUM 3

struct dpdk_offload_api {
    /* Per-threads API. */
    void (*per_thread_upkeep)(unsigned int tid);

    /* Offload insertion / deletion */
    struct rte_flow *(*create)(struct netdev *netdev,
                               const struct rte_flow_attr *attr,
                               const struct rte_flow_item *items,
                               const struct rte_flow_action *actions,
                               struct rte_flow_error *error);
    int (*destroy)(struct netdev *netdev,
                   struct rte_flow *rte_flow,
                   struct rte_flow_error *error,
                   bool esw_port_id);
    int (*query_count)(struct netdev *netdev,
                       struct rte_flow *rte_flow,
                       struct rte_flow_query_count *query,
                       struct rte_flow_error *error);

    struct rte_flow_action_handle *(*shared_create)(struct netdev *netdev,
                           const struct rte_flow_action *action,
                           struct rte_flow_error *error);
    int (*shared_destroy)(int port_id,
                          struct rte_flow_action_handle *act_hdl,
                          struct rte_flow_error *error);
    int (*shared_query)(int port_id,
                        struct rte_flow_action_handle *act_hdl,
                        void *data,
                        struct rte_flow_error *error);

    void (*get_packet_recover_info)(struct dp_packet *p,
                                    struct dpdk_offload_recovery_info *info);

    struct reg_field *(*reg_fields)(void);

    int (*netdev_data_destroy)(void *data);

    void (*update_stats)(struct dpif_flow_stats *stats,
                         struct dpif_flow_attrs *attrs,
                         struct rte_flow_query_count *query);
};

extern struct dpdk_offload_api dpdk_offload_api_rte;

#endif /* DPDK_OFFLOAD_PROVIDER_H */
