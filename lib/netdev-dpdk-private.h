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

struct dp_packet;
struct dp_packet_batch;
struct eth_addr;
struct netdev;
struct netdev_stats;
struct rte_eth_xstat;
struct rte_eth_xstat_name;
struct smap;
enum netdev_features;

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

struct netdev_dpdk_watchdog_params {
    struct ovs_mutex *mutex;
    struct ovs_list *list;
};

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

static inline struct netdev_rxq_dpdk *
netdev_rxq_dpdk_cast(const struct netdev_rxq *rxq)
{
    return CONTAINER_OF(rxq, struct netdev_rxq_dpdk, up);
}

struct netdev_dpdk_common {
    PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline0,
        uint16_t port_id;
        bool attached;
        bool is_representor;
        atomic_bool started;
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
        struct rte_mempool *mp;
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

static inline bool
dpdk_dev_is_started(struct netdev_dpdk_common *common)
{
    bool started;

    atomic_read(&common->started, &started);
    return started;
}

/* Common functions shared between netdev-dpdk and netdev-doca. */

/* Type-independent helpers. */
struct rte_mempool *netdev_dpdk_mp_create_pool(const char *pool_name,
                                               uint32_t n_mbufs,
                                               uint32_t mbuf_size,
                                               int socket_id);
uint32_t netdev_dpdk_buf_size(int mtu);
size_t netdev_dpdk_copy_batch_to_mbuf(struct netdev_dpdk_common *common,
                                      struct dp_packet_batch *batch);
const char *netdev_dpdk_link_speed_to_str__(uint32_t link_speed);
void netdev_dpdk_mbuf_dump(const char *prefix, const char *message,
                           const struct rte_mbuf *mbuf);

/* Functions operating on struct netdev_dpdk_common. */
void netdev_dpdk_detect_hw_ol_features(struct netdev_dpdk_common *common,
                                       const struct rte_eth_dev_info *info);
void netdev_dpdk_build_port_conf(struct netdev_dpdk_common *common,
                                 const struct rte_eth_dev_info *info,
                                 struct rte_eth_conf *conf);
void netdev_dpdk_check_link_status(struct netdev_dpdk_common *common);

void *netdev_dpdk_watchdog(void *params);

void netdev_dpdk_update_netdev_flags(struct netdev_dpdk_common *common);
void netdev_dpdk_clear_xstats(struct netdev_dpdk_common *common);
void netdev_dpdk_configure_xstats(struct netdev_dpdk_common *common);
void netdev_dpdk_set_rxq_config(struct netdev_dpdk_common *common,
                                const struct smap *args);
int netdev_dpdk_prep_hwol_batch(struct netdev_dpdk_common *common,
                                struct rte_mbuf **pkts, int pkt_cnt);
int netdev_dpdk_filter_packet_len(struct netdev_dpdk_common *common,
                                  struct rte_mbuf **pkts, int pkt_cnt);
int netdev_dpdk_eth_tx_burst(struct netdev_dpdk_common *common,
                             dpdk_port_t port_id, int qid,
                             struct rte_mbuf **pkts, int cnt);
void netdev_dpdk_get_config_common(struct netdev_dpdk_common *common,
                                   struct smap *args);
struct netdev_dpdk_common *
netdev_dpdk_lookup_by_port_id__(dpdk_port_t port_id,
                                struct ovs_list *list);
dpdk_port_t netdev_dpdk_get_port_by_devargs(const char *devargs);

/* Rxq ops shared between dpdk and doca. */
struct netdev_rxq *netdev_dpdk_rxq_alloc(void);
int netdev_dpdk_rxq_construct(struct netdev_rxq *rxq);
void netdev_dpdk_rxq_destruct(struct netdev_rxq *rxq);
void netdev_dpdk_rxq_dealloc(struct netdev_rxq *rxq);

/* Netdev provider ops usable by both dpdk and doca. */

int netdev_dpdk_get_numa_id(const struct netdev *netdev);
int netdev_dpdk_set_tx_multiq(struct netdev *netdev, unsigned int n_txq);
int netdev_dpdk_set_etheraddr__(struct netdev_dpdk_common *common,
                                const struct eth_addr mac);
int netdev_dpdk_update_flags(struct netdev *netdev,
                             enum netdev_flags off, enum netdev_flags on,
                             enum netdev_flags *old_flagsp);
int netdev_dpdk_update_flags__(struct netdev_dpdk_common *common,
                               enum netdev_flags off, enum netdev_flags on,
                               enum netdev_flags *old_flagsp);
int netdev_dpdk_set_etheraddr(struct netdev *netdev,
                              const struct eth_addr mac);
int netdev_dpdk_get_etheraddr(const struct netdev *netdev,
                              struct eth_addr *mac);
int netdev_dpdk_get_mtu(const struct netdev *netdev, int *mtup);
int netdev_dpdk_get_ifindex(const struct netdev *netdev);
int netdev_dpdk_get_carrier(const struct netdev *netdev, bool *carrier);
long long int netdev_dpdk_get_carrier_resets(const struct netdev *netdev);
int netdev_dpdk_set_miimon(struct netdev *netdev, long long int interval);
int netdev_dpdk_get_speed(const struct netdev *netdev, uint32_t *current,
                          uint32_t *max);
int netdev_dpdk_get_features(const struct netdev *netdev,
                             enum netdev_features *current,
                             enum netdev_features *advertised,
                             enum netdev_features *supported,
                             enum netdev_features *peer);
void netdev_dpdk_convert_xstats(struct netdev_stats *stats,
                                const struct rte_eth_xstat *xstats,
                                const struct rte_eth_xstat_name *names,
                                const unsigned int size);
int netdev_dpdk_get_stats(const struct netdev *netdev,
                          struct netdev_stats *stats);
int netdev_dpdk_get_status__(const struct netdev *netdev,
                             struct ovs_mutex *dev_mutex,
                             struct smap *args);

#endif /* NETDEV_DPDK_PRIVATE_H */
