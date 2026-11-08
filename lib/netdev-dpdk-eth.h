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

#ifndef NETDEV_DPDK_ETH_H
#define NETDEV_DPDK_ETH_H

#include <inttypes.h>

#include <rte_ethdev.h>

#include "netdev-dpdk-common.h"
#include "ovs-thread.h"
#include "openvswitch/list.h"
#include "util.h"

#define DPDK_ETH_PORT_ID_INVALID    RTE_MAX_ETHPORTS

/* DPDK library uses uint16_t for port_id. */
typedef uint16_t dpdk_port_t;
#define DPDK_PORT_ID_FMT "%"PRIu16

struct netdev_dpdk_eth {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        dpdk_port_t port_id;

        /* No datapath fields below for this block. */

        int link_reset_cnt;
        /* User input for n_rxq (see dpdk_set_rxq_config). */
        int user_n_rxq;
        int requested_rxq_size;
        int requested_txq_size;
        /* Number of rx/tx descriptors for physical devices */
        int rxq_size;
        int txq_size;
        int rte_xstats_names_size;
        int rte_xstats_ids_size;
        /* If true, device was attached by rte_eth_dev_attach(). */
        bool attached;
        /* If true, rte_eth_dev_start() was successfully called. */
        bool started;
        /* If true, this is a port representor. */
        bool is_representor;
        /* If true, the port is configured with no Rx or Tx queues.  Set only
         * by netdev_dpdk_eth_set_no_queues(), for DOCA representor Ethernet
         * devices. */
        bool no_queues;
        /* Ensures that Rx metadata delivery is configured only once. */
        bool rx_metadata_delivery_configured;
        /* Properties for link state change detection mode.
         * If lsc_interrupt_mode is set to false, poll mode is used,
         * otherwise interrupt mode is used. */
        bool requested_lsc_interrupt_mode;
        bool lsc_interrupt_mode;
        /* VF configuration. */
        struct eth_addr requested_hwaddr;
    );

    struct netdev_dpdk_common common;

    /* No datapath fields below for the rest of the structure. */

    struct ovs_mutex mutex OVS_ACQ_AFTER(dpdk_eth_mutex);
    /* In dpdk_eth_list. */
    struct ovs_list list_node OVS_GUARDED_BY(dpdk_eth_mutex);

    /* Device arguments for dpdk ports. */
    char *devargs;

    struct rte_eth_link link;

    /* Requested rx queue steering flags,
     * from the enum set 'dpdk_rx_steer_flags'. */
    uint64_t requested_rx_steer_flags;
    uint64_t rx_steer_flags;
    size_t rx_steer_flows_num;
    struct rte_flow **rx_steer_flows;

    /* Names of all XSTATS counters */
    struct rte_eth_xstat_name *rte_xstats_names;
    uint64_t *rte_xstats_ids;

    /* DPDK-ETH Flow control */
    struct rte_eth_fc_conf fc_conf;
};

static inline struct netdev_dpdk_eth *
netdev_dpdk_eth_cast(const struct netdev *netdev)
{
    return CONTAINER_OF(netdev, struct netdev_dpdk_eth, common.up);
}

void netdev_dpdk_eth_set_no_queues(struct netdev *);

/* Receives a batch of packets from rxq 'queue_id' of device 'dev'.
 * Applies ingress QoS policing and initializes packet fields.
 *
 * Returns the number of received packets (after policing). */
static inline int
netdev_dpdk_eth_rx_burst(struct netdev_dpdk_eth *dev, int queue_id,
                         struct dp_packet_batch *batch)
{
    struct netdev_dpdk_common *common = &dev->common;
    struct dpdk_qos_ingress_policer *policer;
    int nb_rx;

    nb_rx = rte_eth_rx_burst(dev->port_id, queue_id,
                             (struct rte_mbuf **) batch->packets,
                             NETDEV_MAX_BURST);
    if (!nb_rx) {
        return 0;
    }

    policer = ovsrcu_get(struct dpdk_qos_ingress_policer *,
                         &common->ingress_policer);
    if (policer) {
        int dropped = nb_rx;

        nb_rx = dpdk_qos_ingress_policer_run(policer,
                                             (struct rte_mbuf **) batch->packets,
                                             nb_rx, true);
        dropped -= nb_rx;
        if (OVS_UNLIKELY(dropped)) {
            rte_spinlock_lock(&common->stats_lock);
            common->stats.rx_dropped += dropped;
            common->sw_stats->rx_qos_drops += dropped;
            rte_spinlock_unlock(&common->stats_lock);
        }
    }

    batch->count = nb_rx;
    netdev_dpdk_batch_init_packet_fields(batch);

    return nb_rx;
}

/* Tries to transmit 'pkts' to txq 'qid' of device 'dev'.  Takes ownership of
 * 'pkts', even in case of failure.
 *
 * Returns the number of packets that weren't transmitted. */
static inline int
netdev_dpdk_eth_tx_burst(struct netdev_dpdk_eth *dev, int qid,
                         struct rte_mbuf **pkts, int cnt)
{
    struct netdev *netdev = &dev->common.up;
    uint32_t nb_tx = 0;
    uint16_t nb_tx_prep = cnt;

    nb_tx_prep = rte_eth_tx_prepare(dev->port_id, qid, pkts, cnt);
    if (nb_tx_prep != cnt) {
        netdev_dpdk_common_vlog_rl(VLL_WARN,
                                   "%s: Output batch contains invalid packets. "
                                   "Only %u/%u are valid: %s",
                                   netdev_get_name(netdev),
                                   nb_tx_prep, cnt, rte_strerror(rte_errno));
        netdev_dpdk_mbuf_dump(netdev_get_name(netdev),
                              "First invalid packet", pkts[nb_tx_prep]);
    }

    while (nb_tx != nb_tx_prep) {
        uint32_t ret;

        ret = rte_eth_tx_burst(dev->port_id, qid, pkts + nb_tx,
                               nb_tx_prep - nb_tx);
        if (!ret) {
            break;
        }

        nb_tx += ret;
    }

    if (OVS_UNLIKELY(nb_tx != cnt)) {
        rte_pktmbuf_free_bulk(&pkts[nb_tx], cnt - nb_tx);
    }

    return cnt - nb_tx;
}

#endif /* NETDEV_DPDK_ETH_H */
