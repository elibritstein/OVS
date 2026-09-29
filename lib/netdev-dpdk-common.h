/*
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
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

#ifndef NETDEV_DPDK_COMMON_H
#define NETDEV_DPDK_COMMON_H

#include <config.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>

#include "netdev-provider.h"
#include "openvswitch/compiler.h"
#include "ovs-thread.h"
#include "packets.h"

struct dpdk_tx_queue;
struct ingress_policer;
struct qos_conf;
struct smap;

extern struct ovs_mutex dpdk_mutex;
extern struct ovs_mutex dpdk_mp_mutex OVS_ACQ_AFTER(dpdk_mutex);

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
#define NETDEV_DPDK_MAX_PKT_LEN     9728

/* Max and min number of packets in the mempool. OVS tries to allocate a
 * mempool with MAX_NB_MBUF: if this fails (because the system doesn't have
 * enough hugepages) we keep halving the number until the allocation succeeds
 * or we reach MIN_NB_MBUF */

#define MAX_NB_MBUF          (4096 * 64)
#define MIN_NB_MBUF          (4096 * 4)
#define MP_CACHE_SZ          RTE_MEMPOOL_CACHE_MAX_SIZE

struct dpdk_mp {
     struct rte_mempool *mp;
     int mtu;
     int socket_id;
     int refcount;
     struct ovs_list list_node OVS_GUARDED_BY(dpdk_mp_mutex);
};

/* Custom software stats for dpdk ports */
struct netdev_dpdk_sw_stats {
    /* No. of retries when unable to transmit. */
    uint64_t tx_retries;
    /* Packet drops when unable to transmit; Probably Tx queue is full. */
    uint64_t tx_failure_drops;
    /* Packet length greater than device MTU. */
    uint64_t tx_mtu_exceeded_drops;
    /* Packet drops in egress policer processing. */
    uint64_t tx_qos_drops;
    /* Packet drops in ingress policer processing. */
    uint64_t rx_qos_drops;
    /* Packet drops in HWOL processing. */
    uint64_t tx_invalid_hwol_drops;
};

struct netdev_dpdk_common {
    PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline0,
        uint16_t port_id;

        /* If true, device was attached by rte_eth_dev_attach(). */
        bool attached;
        /* If true, rte_eth_dev_start() was successfully called. */
        bool started;
        /* If true, this is a port representor. */
        bool is_representor;
        struct eth_addr hwaddr;
        /* 1 pad bytes here. */
        int mtu;
        int socket_id;
        int buf_size;
        int max_packet_len;
        enum netdev_flags flags;
        int link_reset_cnt;
        union {
            /* Device arguments for dpdk ports. */
            char *devargs;
            /* Identifier used to distinguish vhost devices from each other. */
            char *vhost_id;
        };
        struct dpdk_tx_queue *tx_q;
        struct rte_eth_link link;
    );

    PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline1,
        struct ovs_mutex mutex;
        struct dpdk_mp *dpdk_mp;

        /* virtio identifier for vhost devices */
        ovsrcu_index vid;

        /* True if vHost device is 'up' and has been reconfigured at least
         * once */
        bool vhost_reconfigured;

        atomic_uint8_t vhost_tx_retries_max;

        /* Flags for virtio features recovery mechanism. */
        uint8_t virtio_features_state;

        /* 1 pad byte here. */
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct netdev up;
        struct ovs_list list_node;

        /* QoS configuration and lock for the device */
        OVSRCU_TYPE(struct qos_conf *) qos_conf;

        /* Ingress Policer */
        OVSRCU_TYPE(struct ingress_policer *) ingress_policer;
        uint32_t policer_rate;
        uint32_t policer_burst;

        /* Array of vhost rxq states, see vring_state_changed. */
        bool *vhost_rxq_enabled;

        /* Ensures that Rx metadata delivery is configured only once. */
        bool rx_metadata_delivery_configured;
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct netdev_stats stats;
        struct netdev_dpdk_sw_stats *sw_stats;
        /* Protects stats */
        rte_spinlock_t stats_lock;
        /* 36 pad bytes here. */
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        /* The following properties cannot be changed when a device is running,
         * so we remember the request and update them next time
         * netdev_dpdk*_reconfigure() is called */
        int requested_mtu;
        int requested_n_txq;
        /* User input for n_rxq (see dpdk_set_rxq_config). */
        int user_n_rxq;
        /* user_n_rxq + an optional rx steering queue (see
         * netdev_dpdk_reconfigure). This field is different from the other
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

        /* Ignored by DPDK for vhost-user backends, only for VDUSE. */
        uint8_t vhost_max_queue_pairs;

        /* Denotes whether vHost port is client/server mode */
        uint64_t vhost_driver_flags;

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

        /* Requested rx queue steering flags,
         * from the enum set 'dpdk_rx_steer_flags'. */
        uint64_t requested_rx_steer_flags;
        uint64_t rx_steer_flags;
        size_t rx_steer_flows_num;
        struct rte_flow **rx_steer_flows;
    );

    PADDED_MEMBERS(CACHE_LINE_SIZE,
        /* Names of all XSTATS counters */
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

void netdev_dpdk_common_update_ol_flags(struct netdev_dpdk_common *common);

int netdev_dpdk_common_get_numa_id(const struct netdev *netdev);
void netdev_dpdk_common_get_etheraddr(const struct netdev_dpdk_common *common,
                                     struct eth_addr *mac);
void netdev_dpdk_common_get_mtu(const struct netdev_dpdk_common *common,
                               int *mtup);
int netdev_dpdk_common_get_ifindex(const struct netdev_dpdk_common *common);
int netdev_dpdk_common_set_mtu(struct netdev_dpdk_common *common, int mtu);
void
netdev_dpdk_common_get_sw_custom_stats(struct netdev_dpdk_common *common,
                                       struct netdev_custom_stats *stats);

/* Allocates an area of 'sz' bytes from DPDK.  The memory is zero'ed.
 *
 * Unlike xmalloc(), this function can return NULL on failure. */
static inline void *
dpdk_zmalloc(size_t sz)
{
    return rte_zmalloc("ovs_dpdk", sz, CACHE_LINE_SIZE);
}

struct dpdk_mp_config {
    char *name;
    int mtu;
    int socket_id;
    int n_rxq;
    int rxq_size;
    int n_txq;
    int txq_size;
};

void dpdk_mp_init(const struct smap *ovs_other_config);
bool dpdk_mp_per_port_memory(void);
struct dpdk_mp * dpdk_mp_get(struct dpdk_mp_config *cfg);
void dpdk_mp_put(struct dpdk_mp *dmp);
void dpdk_mp_dump(FILE *stream, struct dpdk_mp *dmp);

#endif /* NETDEV_DPDK_COMMON_H */
