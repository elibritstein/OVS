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

#include "dp-packet.h"
#include "netdev-provider.h"
#include "openvswitch/compiler.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"
#include "packets.h"

struct dpdk_tx_queue;
struct dpdk_qos_ingress_policer;
struct dpdk_qos_conf;
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
        OVSRCU_TYPE(struct dpdk_qos_conf *) qos_conf;

        /* Ingress Policer */
        OVSRCU_TYPE(struct dpdk_qos_ingress_policer *) ingress_policer;
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

/* Quality of Service */

int dpdk_qos_run(struct dpdk_qos_conf *qos_conf, struct rte_mbuf **pkts,
                 int pkt_cnt, bool should_steal);

/* Ingress policer */
struct dpdk_qos_ingress_policer *
    dpdk_qos_ingress_policer_construct(uint32_t rate, uint32_t burst);
void dpdk_qos_ingress_policer_destruct(struct dpdk_qos_ingress_policer *);
int dpdk_qos_ingress_policer_run(struct dpdk_qos_ingress_policer *policer,
                                 struct rte_mbuf **pkts, int pkt_cnt,
                                 bool should_steal);

int netdev_dpdk_common_set_policing(struct netdev_dpdk_common *common,
                                    uint32_t policer_rate,
                                    uint32_t policer_burst);

int netdev_dpdk_common_get_qos_types(const struct netdev *netdev,
                                     struct sset *types);
int netdev_dpdk_common_get_qos(const struct netdev_dpdk_common *common,
                               const char **typep, struct smap *details);
int netdev_dpdk_common_set_qos(struct netdev_dpdk_common *common,
                               const char *type, const struct smap *details);
int netdev_dpdk_common_get_queue(const struct netdev_dpdk_common *common,
                                 uint32_t queue_id, struct smap *details);
int netdev_dpdk_common_set_queue(struct netdev_dpdk_common *common,
                                 uint32_t queue_id,
                                 const struct smap *details);
int netdev_dpdk_common_delete_queue(struct netdev_dpdk_common *common,
                                    uint32_t queue_id);
int netdev_dpdk_common_get_queue_stats(const struct netdev_dpdk_common *common,
                                       uint32_t queue_id,
                                       struct netdev_queue_stats *stats);
int
netdev_dpdk_common_queue_dump_start(const struct netdev_dpdk_common *common,
                                    void **statep);
int netdev_dpdk_common_queue_dump_next(const struct netdev_dpdk_common *common,
                                       void *state_, uint32_t *queue_idp,
                                       struct smap *details);
int netdev_dpdk_common_queue_dump_done(const struct netdev *netdev,
                                       void *state_);

void netdev_dpdk_mbuf_dump(const char *prefix, const char *message,
                           const struct rte_mbuf *mbuf);

void netdev_dpdk_common_vlog_rl(enum vlog_level, const char *format, ...)
    OVS_PRINTF_FORMAT(2, 3);

uint32_t netdev_dpdk_extbuf_size(uint32_t data_len);
void *netdev_dpdk_extbuf_allocate(uint32_t buf_len);
void netdev_dpdk_extbuf_replace(struct dp_packet *b, void *buf,
                                uint32_t data_len);

struct rte_mbuf *dpdk_pktmbuf_alloc(struct rte_mempool *mp, uint32_t data_len);
struct dp_packet *dpdk_copy_dp_packet_to_mbuf(struct rte_mempool *mp,
                                              struct dp_packet *pkt_orig);
size_t dpdk_copy_batch_to_mbuf(struct netdev_dpdk_common *common,
                               struct dp_packet_batch *batch);

/* Prepare the packet for HWOL.
 * Return True if the packet is OK to continue. */
static inline bool
netdev_dpdk_prep_hwol_packet(struct netdev_dpdk_common *common,
                             struct rte_mbuf *mbuf)
{
    struct dp_packet *pkt = CONTAINER_OF(mbuf, struct dp_packet, mbuf);
    uint64_t unexpected = mbuf->ol_flags & RTE_MBUF_F_TX_OFFLOAD_MASK;
    struct netdev *netdev = &common->up;
    const struct ip_header *ip;
    bool is_sctp;
    bool l3_csum;
    bool l4_csum;
    bool is_tcp;
    bool is_udp;
    void *l2;
    void *l3;
    void *l4;

    if (OVS_UNLIKELY(unexpected)) {
        netdev_dpdk_common_vlog_rl(VLL_WARN,
                                   "%s: Unexpected Tx offload flags: %#"PRIx64,
                                   netdev_get_name(netdev), unexpected);
        netdev_dpdk_mbuf_dump(netdev_get_name(netdev),
                              "Packet with unexpected ol_flags", mbuf);
        return false;
    }

    if (!dp_packet_ip_checksum_partial(pkt)
        && !dp_packet_inner_ip_checksum_partial(pkt)
        && !dp_packet_l4_checksum_partial(pkt)
        && !dp_packet_inner_l4_checksum_partial(pkt)
        && !mbuf->tso_segsz) {

        return true;
    }

    if (dp_packet_tunnel(pkt)) {
        mbuf->outer_l2_len = (char *) dp_packet_l3(pkt) -
                             (char *) dp_packet_eth(pkt);
        mbuf->outer_l3_len = (char *) dp_packet_l4(pkt) -
                             (char *) dp_packet_l3(pkt);

        if (dp_packet_tunnel_geneve(pkt)) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_TUNNEL_GENEVE;
        } else if (dp_packet_tunnel_vxlan(pkt)) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_TUNNEL_VXLAN;
        } else {
            ovs_assert(dp_packet_tunnel_gre(pkt));
            mbuf->ol_flags |= RTE_MBUF_F_TX_TUNNEL_GRE;
        }

        if (dp_packet_ip_checksum_partial(pkt)) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_OUTER_IP_CKSUM;
        }

        if (dp_packet_l4_checksum_partial(pkt)) {
            ovs_assert(dp_packet_l4_proto_udp(pkt));
            mbuf->ol_flags |= RTE_MBUF_F_TX_OUTER_UDP_CKSUM;
        }

        ip = dp_packet_l3(pkt);
        mbuf->ol_flags |= IP_VER(ip->ip_ihl_ver) == 4
                          ? RTE_MBUF_F_TX_OUTER_IPV4
                          : RTE_MBUF_F_TX_OUTER_IPV6;

        /* Inner L2 length must account for the tunnel header length. */
        l2 = dp_packet_l4(pkt);
        l3 = dp_packet_inner_l3(pkt);
        l3_csum = dp_packet_inner_ip_checksum_partial(pkt);
        l4 = dp_packet_inner_l4(pkt);
        l4_csum = dp_packet_inner_l4_checksum_partial(pkt);
        is_tcp = dp_packet_inner_l4_proto_tcp(pkt);
        is_udp = dp_packet_inner_l4_proto_udp(pkt);
        is_sctp = dp_packet_inner_l4_proto_sctp(pkt);
    } else {
        mbuf->outer_l2_len = 0;
        mbuf->outer_l3_len = 0;

        l2 = dp_packet_eth(pkt);
        l3 = dp_packet_l3(pkt);
        l3_csum = dp_packet_ip_checksum_partial(pkt);
        l4 = dp_packet_l4(pkt);
        l4_csum = dp_packet_l4_checksum_partial(pkt);
        is_tcp = dp_packet_l4_proto_tcp(pkt);
        is_udp = dp_packet_l4_proto_udp(pkt);
        is_sctp = dp_packet_l4_proto_sctp(pkt);
    }

    ovs_assert(l4);

    ip = l3;
    mbuf->ol_flags |= IP_VER(ip->ip_ihl_ver) == 4
                      ? RTE_MBUF_F_TX_IPV4 : RTE_MBUF_F_TX_IPV6;

    if (l3_csum) {
        mbuf->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
    }

    if (l4_csum) {
        if (is_tcp) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
        } else if (is_udp) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
        } else {
            ovs_assert(is_sctp);
            mbuf->ol_flags |= RTE_MBUF_F_TX_SCTP_CKSUM;
        }
    }

    mbuf->l2_len = (char *) l3 - (char *) l2;
    mbuf->l3_len = (char *) l4 - (char *) l3;

    if (mbuf->tso_segsz) {
        struct tcp_header *th = l4;
        int hdr_len;

        mbuf->l4_len = TCP_OFFSET(th->tcp_ctl) * 4;

        hdr_len = mbuf->l2_len + mbuf->l3_len + mbuf->l4_len;
        if (dp_packet_tunnel(pkt)) {
            hdr_len += mbuf->outer_l2_len + mbuf->outer_l3_len;
        }

        if (OVS_UNLIKELY((hdr_len + mbuf->tso_segsz)
                         > common->max_packet_len)) {
            netdev_dpdk_common_vlog_rl(VLL_WARN,
                                       "%s: Oversized TSO packet. hdr: %"PRIu32
                                       ", gso: %"PRIu32", max len: %"PRIu32"",
                                       netdev->name, hdr_len, mbuf->tso_segsz,
                                       common->max_packet_len);
            return false;
        }
        mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;

        /* DPDK API mandates IPv4 checksum when requesting TSO. */
        if (IP_VER(ip->ip_ihl_ver) == 4) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
        }
    }

    return true;
}

/* Prepare a batch for HWOL.
 * Return the number of good packets in the batch. */
static inline int
netdev_dpdk_prep_hwol_batch(struct netdev_dpdk_common *common,
                            struct rte_mbuf **pkts, int pkt_cnt)
{
    int i = 0;
    int cnt = 0;
    struct rte_mbuf *pkt;

    /* Prepare and filter bad HWOL packets. */
    for (i = 0; i < pkt_cnt; i++) {
        pkt = pkts[i];
        if (!netdev_dpdk_prep_hwol_packet(common, pkt)) {
            rte_pktmbuf_free(pkt);
            continue;
        }

        if (OVS_UNLIKELY(i != cnt)) {
            pkts[cnt] = pkt;
        }
        cnt++;
    }

    return cnt;
}

static inline int
netdev_dpdk_filter_packet_len(struct netdev_dpdk_common *common,
                              struct rte_mbuf **pkts, int pkt_cnt)
{
    int i = 0;
    int cnt = 0;
    struct rte_mbuf *pkt;

    /* Filter oversized packets. The TSO packets are filtered out
     * during the offloading preparation for performance reasons. */
    for (i = 0; i < pkt_cnt; i++) {
        pkt = pkts[i];
        if (OVS_UNLIKELY((pkt->pkt_len > common->max_packet_len)
            && !pkt->tso_segsz)) {
            netdev_dpdk_common_vlog_rl(VLL_WARN,
                                       "%s: Too big size %" PRIu32
                                       " max_packet_len %d",
                                       common->up.name, pkt->pkt_len,
                                       common->max_packet_len);
            rte_pktmbuf_free(pkt);
            continue;
        }

        if (OVS_UNLIKELY(i != cnt)) {
            pkts[cnt] = pkt;
        }
        cnt++;
    }

    return cnt;
}

static inline size_t
netdev_dpdk_common_send(struct netdev_dpdk_common *common,
                        struct dp_packet_batch *batch,
                        struct netdev_dpdk_sw_stats *stats)
{
    struct rte_mbuf **pkts = (struct rte_mbuf **) batch->packets;
    size_t cnt, pkt_cnt = dp_packet_batch_size(batch);
    struct dpdk_qos_conf *qos_conf;
    struct dp_packet *packet;
    bool need_copy = false;

    memset(stats, 0, sizeof *stats);

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        if (packet->source != DPBUF_DPDK) {
            need_copy = true;
            break;
        }
    }

    /* Copy dp-packets to mbufs. */
    if (OVS_UNLIKELY(need_copy)) {
        cnt = dpdk_copy_batch_to_mbuf(common, batch);
        stats->tx_failure_drops += pkt_cnt - cnt;
        pkt_cnt = cnt;
    }

    /* Drop oversized packets. */
    cnt = netdev_dpdk_filter_packet_len(common, pkts, pkt_cnt);
    stats->tx_mtu_exceeded_drops += pkt_cnt - cnt;
    pkt_cnt = cnt;

    if (common->up.ol_flags) {
        /* Prepare each mbuf for hardware offloading. */
        cnt = netdev_dpdk_prep_hwol_batch(common, pkts, pkt_cnt);
        stats->tx_invalid_hwol_drops += pkt_cnt - cnt;
        pkt_cnt = cnt;
    }

    /* Apply Quality of Service policy. */
    qos_conf = ovsrcu_get(struct dpdk_qos_conf *, &common->qos_conf);
    if (qos_conf) {
        cnt = dpdk_qos_run(qos_conf, pkts, pkt_cnt, true);
        stats->tx_qos_drops += pkt_cnt - cnt;
    }

    return cnt;
}

#endif /* NETDEV_DPDK_COMMON_H */
