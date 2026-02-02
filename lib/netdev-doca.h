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

struct dpdk_mp;
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
    uint16_t port_id;
    struct ovs_mutex mgmt_queue_lock;
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
    PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline0,
        struct eth_addr hwaddr;
        uint16_t port_id;
        int mtu;
        int socket_id;
        int max_packet_len;
        enum netdev_flags flags;
        int link_reset_cnt;
        char *devargs;
        struct doca_tx_queue *tx_q;
        struct rte_eth_link link;
        /* 2 pad bytes here. */
        uint16_t esw_mgr_port_id;
        /* If true, device was attached by rte_eth_dev_attach(). */
        bool attached;
        /* If true, rte_eth_dev_start() was successfully called */
        atomic_bool started;
    );

    PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline1,
        struct ovs_mutex mutex;
        struct dpdk_mp *dpdk_mp;
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct netdev up;
        /* In dpdk_list. */
        struct ovs_list list_node;

        /* Ensures that Rx metadata delivery is configured only once. */
        bool rx_metadata_delivery_configured;
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct netdev_stats stats;
        struct netdev_doca_sw_stats *sw_stats;
        struct netdev_doca_tx_stats *sw_tx_stats;
        /* Protects stats */
        rte_spinlock_t stats_lock;
        /* 8 pad bytes here. */
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        /* The following properties cannot be changed when a device is running,
         * so we remember the request and update them next time
         * netdev_doca*_reconfigure() is called */
        int requested_mtu;
        int requested_n_txq;
        /* User input for n_rxq (see dpdk_set_rxq_config). */
        int user_n_rxq;
        /* user_n_rxq + an optional rx steering queue (see
         * netdev_doca_reconfigure). This field is different from the other
         * requested_* fields as it may contain a different value than the user
         * input. */
        int requested_n_rxq;
        int requested_rxq_size;
        int requested_txq_size;

        /* Number of rx/tx descriptors for physical devices */
        int rxq_size;
        int txq_size;

        /* Socket ID detected when vHost device is brought up */
        int requested_socket_id;

        /* DPDK-ETH Flow control */
        struct rte_eth_fc_conf fc_conf;

        /* DPDK-ETH hardware offload features,
         * from the enum set 'dpdk_hw_ol_features' */
        uint32_t hw_ol_features;

        /* Properties for link state change detection mode.
         * If lsc_interrupt_mode is set to false, poll mode is used,
         * otherwise interrupt mode is used. */
        bool requested_lsc_interrupt_mode;
        bool lsc_interrupt_mode;

        /* VF configuration. */
        struct eth_addr requested_hwaddr;
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        /* Names of all XSTATS counters */
        struct rte_eth_xstat_name *rte_xstats_names;
        int rte_xstats_names_size;
        int rte_xstats_ids_size;
        uint64_t *rte_xstats_ids;
    );

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
