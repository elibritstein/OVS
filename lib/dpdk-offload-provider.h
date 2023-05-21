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
#define MIN_ZONE_ID     1
#define MAX_ZONE_ID     0x00000008
#define NUM_ZONE_ID     (MAX_ZONE_ID - MIN_ZONE_ID + 1)

struct doca_ctl_pipe_ctx;
struct doca_flow_pipe_entry;

struct raw_encap_data {
    struct rte_flow_action_raw_encap conf;
    uint8_t headroom[8];
    uint8_t data[TNL_PUSH_HEADER_SIZE - 8];
    uint32_t tnl_type;
};
BUILD_ASSERT_DECL(offsetof(struct raw_encap_data, conf) == 0);

struct doca_flow_handle_resources {
    uint32_t group;
    struct doca_ctl_pipe_ctx *self_pipe_ctx;
    uint32_t next_group;
    struct doca_ctl_pipe_ctx *next_pipe_ctx;
};

struct doca_flow_handle {
    struct doca_flow_pipe_entry *flow;
    struct doca_flow_handle_resources flow_res;
};

struct dpdk_offload_handle {
    union {
        struct rte_flow *rte_flow;
        struct doca_flow_handle dfh;
    };
    bool valid;
};
BUILD_ASSERT_DECL(offsetof(struct dpdk_offload_handle, rte_flow) ==
                  offsetof(struct dpdk_offload_handle, dfh.flow));
BUILD_ASSERT_DECL(MEMBER_SIZEOF(struct dpdk_offload_handle, rte_flow) ==
                  MEMBER_SIZEOF(struct dpdk_offload_handle, dfh.flow));

struct fixed_rule {
    struct dpdk_offload_handle doh;
};

struct netdev_offload_dpdk_data {
    struct cmap ufid_to_rte_flow;
    uint64_t *offload_counters;
    uint64_t *flow_counters;
    uint64_t *conn_counters;
    struct ovs_mutex map_lock;
    struct ovsthread_once aux_tables_once;
    struct fixed_rule ct_nat_miss;
    struct fixed_rule zone_flows[2][2][MAX_ZONE_ID + 1];
    struct fixed_rule hairpin;
    void *eswitch_ctx;
};

/* Proprietary rte-flow action enums. */
enum {
    OVS_RTE_FLOW_ACTION_TYPE_FLOW_INFO = INT_MIN,
    OVS_RTE_FLOW_ACTION_TYPE_CT_INFO,
    OVS_RTE_FLOW_ACTION_TYPE_PRE_CT_END,
};

#define OVS_RTE_FLOW_ACTION_TYPE(TYPE) \
    ((enum rte_flow_action_type) OVS_RTE_FLOW_ACTION_TYPE_##TYPE)

/* Proprietary rte-flow item enums. */
enum {
    OVS_RTE_FLOW_ITEM_TYPE_FLOW_INFO = INT_MIN,
};

#define OVS_RTE_FLOW_ITEM_TYPE(TYPE) \
    ((enum rte_flow_item_type) OVS_RTE_FLOW_ITEM_TYPE_##TYPE)

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
    REG_FIELD_FLOW_INFO,
    REG_FIELD_NUM,
};

enum reg_type {
    REG_TYPE_TAG,
    REG_TYPE_META,
    REG_TYPE_MARK,
};

struct reg_field {
    enum reg_type type;
    uint8_t index;
    uint32_t offset;
    uint32_t mask;
};

#define REG_TAG_INDEX_NUM 3

struct dpdk_offload_api {
    void (*upkeep)(struct netdev *netdev, bool quiescing);

    /* Offload insertion / deletion */
    int (*create)(struct netdev *netdev,
                  const struct rte_flow_attr *attr,
                  struct rte_flow_item *items,
                  struct rte_flow_action *actions,
                  struct dpdk_offload_handle *doh,
                  struct rte_flow_error *error);
    int (*destroy)(struct netdev *netdev,
                   struct dpdk_offload_handle *doh,
                   struct rte_flow_error *error,
                   bool esw_port_id);
    int (*query_count)(struct netdev *netdev,
                       struct dpdk_offload_handle *doh,
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
    int (*aux_tables_init)(struct netdev *netdev);
    void (*aux_tables_uninit)(struct netdev *netdev);
};

extern struct dpdk_offload_api dpdk_offload_api_rte;
extern struct dpdk_offload_api dpdk_offload_api_doca;

bool
dpdk_offload_get_reg_field(struct dp_packet *packet,
                           enum dpdk_reg_id reg_id,
                           uint32_t *val);

void *
find_raw_encap_spec(const struct raw_encap_data *raw_encap_data,
                    enum rte_flow_item_type type);

static inline void
dpdk_offload_counter_inc(struct netdev *netdev)
{
    unsigned int tid = netdev_offload_thread_id();
    struct netdev_offload_dpdk_data *data;

    data = (struct netdev_offload_dpdk_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);
    data->offload_counters[tid]++;
}

static inline void
dpdk_offload_counter_dec(struct netdev *netdev)
{
    unsigned int tid = netdev_offload_thread_id();
    struct netdev_offload_dpdk_data *data;

    data = (struct netdev_offload_dpdk_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);
    data->offload_counters[tid]--;
}

#endif /* DPDK_OFFLOAD_PROVIDER_H */
