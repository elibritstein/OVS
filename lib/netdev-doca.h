/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NETDEV_DOCA_H
#define NETDEV_DOCA_H

#include <config.h>

#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_pci.h>

#include <doca_flow.h>

#include "netdev-provider.h"
#include "ovs-doca.h"
#include "util.h"

#include "openvswitch/list.h"

struct doca_tx_queue;
struct netdev_doca_sw_stats;
extern struct ovs_mutex doca_mutex;
#define NETDEV_DPDK_TX_Q_TYPE  struct doca_tx_queue
#define NETDEV_DPDK_SW_STATS_TYPE  struct netdev_doca_sw_stats
#define NETDEV_DPDK_GLOBAL_MUTEX doca_mutex
#include "netdev-dpdk-private.h"

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
    NETDEV_DOCA_RSS_OTHER,
};
/* Must be the last enum type. */
#define NETDEV_DOCA_RSS_NUM_ENTRIES (NETDEV_DOCA_RSS_OTHER + 1)

/* Custom software stats for dpdk ports */
struct netdev_doca_sw_stats {
    /* No. of retries when unable to transmit. */
    uint64_t tx_retries;
    /* Packet drops when unable to transmit; Probably Tx queue is full. */
    uint64_t tx_failure_drops;
    /* Packet length greater than device MTU. */
    uint64_t tx_mtu_exceeded_drops;
    /* Packet drops in HWOL processing. */
    uint64_t tx_invalid_hwol_drops;
};

struct netdev_doca_tx_stats {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        atomic_uint64_t n_packets;
        atomic_uint64_t n_bytes;
    );
};

enum netdev_doca_port_dir {
    NETDEV_DOCA_PORT_DIR_RX,
    NETDEV_DOCA_PORT_DIR_TX,
    NUM_NETDEV_DOCA_PORT_DIR,
};

enum pre_miss_types {
    SEND_TO_KERNEL_LACP,
    SEND_TO_KERNEL_LLDP,
    NUM_SEND_TO_KERNEL,
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
    struct {
        struct doca_flow_pipe *egress_pipe;
        struct doca_flow_pipe *rss_pipe;
        struct doca_flow_pipe *meta_tag0_pipe;
        struct doca_flow_pipe_entry *meta_tag0_entry;
        struct doca_flow_pipe *pre_miss_pipe;
        struct doca_flow_pipe_entry *pre_miss_entries[NUM_SEND_TO_KERNEL];
        struct doca_flow_pipe *root_pipe;
    };
    unsigned int n_rxq;
    char pci_addr[PCI_PRI_STR_SIZE];
    struct doca_dev *dev;
    uint32_t op_state;
    int cmd_fd;
};

/* There should be one 'struct doca_tx_queue' created for
 * each netdev tx queue. */
struct doca_tx_queue {
    /* Padding to make doca_tx_queue exactly one cache line long. */
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        /* Protects the members and the NIC queue from concurrent access.
         * It is used only if the queue is shared among different pmd threads
         * (see 'concurrent_txq'). */
        rte_spinlock_t tx_lock;
    );
};

struct netdev_doca {
    struct netdev_dpdk_common common; /* Must be first (offset 0). */

    dpdk_port_t esw_mgr_port_id;
    struct netdev_doca_tx_stats *sw_tx_stats;

    PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline10,
        struct doca_flow_port *port;
        struct netdev_doca_esw_ctx *esw_ctx;
        struct doca_flow_pipe_entry *rss_entries[NETDEV_DOCA_RSS_NUM_ENTRIES];
        struct doca_flow_pipe_entry *egress_entry;
        char *peer_name;
        enum netdev_doca_port_dir port_dir;
        struct doca_dev_rep *dev_rep;
    );
};

void netdev_doca_register(void);

struct netdev_doca *
netdev_doca_cast(const struct netdev *netdev);

#endif /* NETDEV_DOCA_H */
