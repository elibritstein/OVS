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

#ifndef NETDEV_DPDK_PRIVATE_H
#define NETDEV_DPDK_PRIVATE_H

#include <config.h>

#include <rte_config.h>
#include <rte_ethdev.h>
#include <rte_spinlock.h>

#include "netdev-provider.h"
#include "util.h"

#include "openvswitch/thread.h"

extern const struct rte_eth_conf port_conf;

/* Defines. */

#define SOCKET0              0

/*
 * need to reserve tons of extra space in the mbufs so we can align the
 * DMA addresses to 4KB.
 * The minimum mbuf size is limited to avoid scatter behaviour and drop in
 * performance for standard Ethernet MTU.
 */
#define ETHER_HDR_MAX_LEN           (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN \
                                     + (2 * VLAN_HEADER_LEN))
#define MTU_TO_FRAME_LEN(mtu)       ((mtu) + RTE_ETHER_HDR_LEN + \
                                     RTE_ETHER_CRC_LEN)
#define MTU_TO_MAX_FRAME_LEN(mtu)   ((mtu) + ETHER_HDR_MAX_LEN)
#define FRAME_LEN_TO_MTU(frame_len) ((frame_len)                    \
                                     - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN)
#define NETDEV_DPDK_MBUF_ALIGN      1024

#define MP_CACHE_SZ          RTE_MEMPOOL_CACHE_MAX_SIZE

/* Default size of Physical NIC RXQ */
#define NIC_PORT_DEFAULT_RXQ_SIZE 2048
/* Default size of Physical NIC TXQ */
#define NIC_PORT_DEFAULT_TXQ_SIZE 2048

#define DPDK_ETH_PORT_ID_INVALID    RTE_MAX_ETHPORTS

/* DPDK library uses uint16_t for port_id. */
typedef uint16_t dpdk_port_t;
#define DPDK_PORT_ID_FMT "%"PRIu16

/* Enums. */

enum dpdk_hw_ol_features {
    NETDEV_RX_CHECKSUM_OFFLOAD = 1 << 0,
    NETDEV_RX_HW_CRC_STRIP = 1 << 1,
    NETDEV_RX_HW_SCATTER = 1 << 2,
    NETDEV_TX_IPV4_CKSUM_OFFLOAD = 1 << 3,
    NETDEV_TX_TCP_CKSUM_OFFLOAD = 1 << 4,
    NETDEV_TX_UDP_CKSUM_OFFLOAD = 1 << 5,
    NETDEV_TX_SCTP_CKSUM_OFFLOAD = 1 << 6,
    NETDEV_TX_TSO_OFFLOAD = 1 << 7,
    NETDEV_TX_VXLAN_TNL_TSO_OFFLOAD = 1 << 8,
    NETDEV_TX_GENEVE_TNL_TSO_OFFLOAD = 1 << 9,
    NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD = 1 << 10,
    NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD = 1 << 11,
    NETDEV_TX_GRE_TNL_TSO_OFFLOAD = 1 << 12,
};

/* Structs. */

#ifndef NETDEV_DPDK_TX_Q_TYPE
#error "NETDEV_DPDK_TX_Q_TYPE must be defined before"  \
       "including netdev-dpdk-private.h"
#endif

#ifndef NETDEV_DPDK_SW_STATS_TYPE
#error "NETDEV_DPDK_SW_STATS_TYPE must be defined before" \
       "including netdev-dpdk-private.h"
#endif

#ifndef NETDEV_DPDK_GLOBAL_MUTEX
#error "NETDEV_DPDK_GLOBAL_MUTEX must be defined before" \
       "including netdev-dpdk-private.h"
#endif

struct netdev_rxq_dpdk {
    struct netdev_rxq up;
    dpdk_port_t port_id;
};

struct netdev_dpdk_common {
    PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline0,
        uint16_t port_id;
        bool attached;
        bool is_representor;
        bool started;
        struct eth_addr hwaddr;
        int mtu;
        int socket_id;
        int max_packet_len;
        enum netdev_flags flags;
        int link_reset_cnt;
        char *devargs;
        NETDEV_DPDK_TX_Q_TYPE *tx_q;
        struct rte_eth_link link;
    );

    PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline1,
        struct ovs_mutex mutex OVS_ACQ_AFTER(NETDEV_DPDK_GLOBAL_MUTEX);
        struct dpdk_mp *dpdk_mp;
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct netdev up;
        struct ovs_list list_node OVS_GUARDED_BY(NETDEV_DPDK_GLOBAL_MUTEX);
        bool rx_metadata_delivery_configured;
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct netdev_stats stats;
        NETDEV_DPDK_SW_STATS_TYPE *sw_stats;
        rte_spinlock_t stats_lock;
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        /* Configuration fields */
        int requested_mtu;
        int requested_n_txq;
        int user_n_rxq;
        int requested_n_rxq;
        int requested_rxq_size;
        int requested_txq_size;
        int rxq_size;
        int txq_size;
        int requested_socket_id;
        struct rte_eth_fc_conf fc_conf;
        uint32_t hw_ol_features;
        bool requested_lsc_interrupt_mode;
        bool lsc_interrupt_mode;
        struct eth_addr requested_hwaddr;
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct rte_eth_xstat_name *rte_xstats_names;
        int rte_xstats_names_size;
        int rte_xstats_ids_size;
        uint64_t *rte_xstats_ids;
    );
};

static inline struct netdev_dpdk_common *
netdev_dpdk_common_cast(const struct netdev *netdev)
{
    return CONTAINER_OF(netdev, struct netdev_dpdk_common, up);
}

#endif /* NETDEV_DPDK_PRIVATE_H */
