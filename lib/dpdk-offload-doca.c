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

#include <config.h>

#include <doca_flow.h>
#include <rte_flow.h>
#include <sys/types.h>

#include "ovs-doca.h"
#include "dp-packet.h"
#include "dpdk-offload-provider.h"

static struct reg_field *
dpdk_offload_doca_get_reg_fields(void)
{
    return NULL;
}

static struct rte_flow *
dpdk_offload_doca_create(struct netdev *netdev OVS_UNUSED,
                         const struct rte_flow_attr *attr OVS_UNUSED,
                         const struct rte_flow_item *items OVS_UNUSED,
                         const struct rte_flow_action *actions OVS_UNUSED,
                         struct rte_flow_error *error OVS_UNUSED)
{
    return NULL;
}

static int
dpdk_offload_doca_destroy(struct netdev *netdev OVS_UNUSED,
                          struct rte_flow *rte_flow OVS_UNUSED,
                          struct rte_flow_error *error OVS_UNUSED,
                          bool esw_port_id OVS_UNUSED)
{
    return -1;
}

static int
dpdk_offload_doca_query_count(struct netdev *netdev OVS_UNUSED,
                              struct rte_flow *rte_flow OVS_UNUSED,
                              struct rte_flow_query_count *query OVS_UNUSED,
                              struct rte_flow_error *error OVS_UNUSED)
{
    return -1;
}

static struct rte_flow_action_handle *
dpdk_offload_doca_shared_create(struct netdev *netdev OVS_UNUSED,
                                const struct rte_flow_action *action OVS_UNUSED,
                                struct rte_flow_error *error OVS_UNUSED)
{
    return NULL;
}

static int
dpdk_offload_doca_shared_destroy(int port_id OVS_UNUSED,
                                 struct rte_flow_action_handle *act_hdl OVS_UNUSED,
                                 struct rte_flow_error *error OVS_UNUSED)
{
    return -1;
}

static int
dpdk_offload_doca_shared_query(int port_id OVS_UNUSED,
                               struct rte_flow_action_handle *act_hdl OVS_UNUSED,
                               void *data OVS_UNUSED,
                               struct rte_flow_error *error OVS_UNUSED)
{
    return -1;
}

static void
dpdk_offload_doca_get_pkt_recover_info(struct dp_packet *p OVS_UNUSED,
                                       struct dpdk_offload_recovery_info *info)
{
    memset(info, 0, sizeof *info);
    return;
}

static int
dpdk_offload_doca_netdev_data_destroy(void *data OVS_UNUSED)
{
    return -1;
}

static void
dpdk_offload_doca_update_stats(struct dpif_flow_stats *stats OVS_UNUSED,
                               struct dpif_flow_attrs *attrs,
                               struct rte_flow_query_count *query OVS_UNUSED)
{
    attrs->dp_layer = "doca";
    return;
}

struct dpdk_offload_api dpdk_offload_api_doca = {
    .create = dpdk_offload_doca_create,
    .destroy = dpdk_offload_doca_destroy,
    .query_count = dpdk_offload_doca_query_count,
    .shared_create = dpdk_offload_doca_shared_create,
    .shared_destroy = dpdk_offload_doca_shared_destroy,
    .shared_query = dpdk_offload_doca_shared_query,
    .get_packet_recover_info = dpdk_offload_doca_get_pkt_recover_info,
    .reg_fields = dpdk_offload_doca_get_reg_fields,
    .netdev_data_destroy = dpdk_offload_doca_netdev_data_destroy,
    .update_stats = dpdk_offload_doca_update_stats,
};
