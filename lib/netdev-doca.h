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

#ifndef NETDEV_DOCA_H
#define NETDEV_DOCA_H

#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_pci.h>

#include <doca_flow.h>

#include "netdev-provider.h"
#include "ovs-doca.h"
#include "util.h"

#include "openvswitch/list.h"

extern struct ovs_mutex doca_mutex;
#define NETDEV_DPDK_GLOBAL_MUTEX_NAME doca_mutex
#include "netdev-dpdk-private.h"

struct doca_mp;
struct rte_ring;

enum netdev_doca_rss_type {
    NETDEV_DOCA_RSS_IPV4_TCP,
    NETDEV_DOCA_RSS_IPV4_UDP,
    NETDEV_DOCA_RSS_IPV4_ICMP,
    NETDEV_DOCA_RSS_IPV4_ESP,
    NETDEV_DOCA_RSS_IPV4_OTHER,
    NETDEV_DOCA_RSS_IPV6_TCP,
    NETDEV_DOCA_RSS_IPV6_UDP,
    NETDEV_DOCA_RSS_IPV6_ICMP,
    NETDEV_DOCA_RSS_IPV6_ESP,
    NETDEV_DOCA_RSS_IPV6_OTHER,
    NETDEV_DOCA_RSS_OTHER,  /* Must be the last enum type. */
};
#define NETDEV_DOCA_RSS_NUM_ENTRIES (NETDEV_DOCA_RSS_OTHER + 1)

struct netdev_doca_tx_stats {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        atomic_uint64_t n_packets;
        atomic_uint64_t n_bytes;
    );
};

enum pre_miss_types {
    PRE_MISS_TYPE_LACP,
    PRE_MISS_TYPE_LLDP,
    PRE_MISS_N_TYPES,
};

struct netdev_doca_port_queue {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct rte_ring *ring;
        atomic_uint64_t n_packets;
        atomic_uint64_t n_bytes;
    );
};

struct netdev_doca_esw_ctx {
    struct netdev_doca_port_queue *port_queues[RTE_MAX_ETHPORTS];
    dpdk_port_t port_id;
    struct ovs_doca_offload_queue
        offload_queues[OVS_DOCA_MAX_OFFLOAD_QUEUES];
    struct doca_flow_port *esw_port;
    struct netdev *esw_netdev;

    /* miss-path */
    struct doca_flow_pipe *egress_pipe;
    struct doca_flow_pipe *rss_pipe;
    struct doca_flow_pipe *meta_tag0_pipe;
    struct doca_flow_pipe_entry *meta_tag0_entry;
    struct doca_flow_pipe *pre_miss_pipe;
    struct doca_flow_pipe_entry *pre_miss_entries[PRE_MISS_N_TYPES];
    struct doca_flow_pipe *root_pipe;

    unsigned int n_rxq;
    char pci_addr[PCI_PRI_STR_SIZE];
    struct doca_dev *dev;
    uint32_t op_state;
    int cmd_fd;
};

struct netdev_doca {
    struct netdev_dpdk_common common;

    struct doca_mp *doca_mp;
    dpdk_port_t esw_mgr_port_id;
    struct netdev_doca_tx_stats *sw_tx_stats;

    PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline10,
        struct doca_flow_port *port;
        struct netdev_doca_esw_ctx *esw_ctx;
        struct doca_flow_pipe_entry *rss_entries[NETDEV_DOCA_RSS_NUM_ENTRIES];
        struct doca_flow_pipe_entry *egress_entry;
        char *peer_name;
        struct doca_dev_rep *dev_rep;
    );
};
BUILD_ASSERT_DECL(offsetof(struct netdev_doca, common) == 0);

void netdev_doca_register(void);

struct netdev_doca *
netdev_doca_cast(const struct netdev *netdev);

#endif /* NETDEV_DOCA_H */
