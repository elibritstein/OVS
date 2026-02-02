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

#include <config.h>

#include <dirent.h>
#include <infiniband/verbs.h>
#include <net/if.h>
#include <unistd.h>

#include <rte_bus.h>
#include <rte_config.h>
#include <rte_dev.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_pci.h>
#include <rte_pmd_mlx5.h>
#include <rte_ring.h>
#include <rte_version.h>

#include <doca_bitfield.h>
#include <doca_dpdk.h>
#include <doca_flow.h>
#include <doca_rdma_bridge.h>

#include "coverage.h"
#include "dp-packet.h"
#include "dpif-netdev.h"
#include "netdev-doca.h"
#include "netdev-provider.h"
#include "ovs-doca.h"
#include "ovs-thread.h"
#include "refmap.h"
#include "rtnetlink.h"
#include "unixctl.h"
#include "userspace-tso.h"
#include "util.h"

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_doca);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);

COVERAGE_DEFINE(netdev_doca_drop_oversized);
COVERAGE_DEFINE(netdev_doca_drop_ring_full);
COVERAGE_DEFINE(netdev_doca_invalid_classify_port);
COVERAGE_DEFINE(netdev_doca_no_mark);

#define DOCA_PORT_WATCHDOG_INTERVAL 5
#define SOCKET0              0
#define DPDK_ETH_PORT_ID_INVALID    RTE_MAX_ETHPORTS

#define ETHER_HDR_MAX_LEN           (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN \
                                     + (2 * VLAN_HEADER_LEN))
#define MTU_TO_FRAME_LEN(mtu)       ((mtu) + RTE_ETHER_HDR_LEN + \
                                     RTE_ETHER_CRC_LEN)
#define MTU_TO_MAX_FRAME_LEN(mtu)   ((mtu) + ETHER_HDR_MAX_LEN)
#define FRAME_LEN_TO_MTU(frame_len) ((frame_len)                    \
                                     - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN)
#define NETDEV_DOCA_MBUF_ALIGN      1024
#define MIN_NB_MBUF          (4096 * 4)
#define MP_CACHE_SZ          RTE_MEMPOOL_CACHE_MAX_SIZE

/* Default size of Physical NIC RXQ */
#define NIC_PORT_DEFAULT_RXQ_SIZE 2048
/* Default size of Physical NIC TXQ */
#define NIC_PORT_DEFAULT_TXQ_SIZE 2048

#define NETDEV_DOCA_MAX_MEGAFLOWS_COUNTERS (1 << 19)
#define NETDEV_DOCA_ACTIONS_MEM_SIZE \
    (64 * 2 * NETDEV_DOCA_MAX_MEGAFLOWS_COUNTERS)

#define MAX_PHYS_ITEM_ID_LEN 32

OVS_ASSERT_PACKED(struct netdev_doca_esw_key,
    struct rte_pci_addr rte_pci;
);

struct netdev_doca_esw_ctx_arg {
    struct netdev_doca_esw_key *esw_key;
    struct netdev_doca *dev;
};

struct netdev_rxq_doca {
    struct netdev_rxq up;
    uint16_t port_id;
};

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

struct dpdk_mp {
     struct rte_mempool *mp;
     int socket_id;
     uint16_t esw_mgr_port_id;
     int refcount;
     struct ovs_list list_node OVS_GUARDED_BY(dpdk_mp_mutex);
};

static struct ovs_mutex doca_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct doca_dev's. */
static struct ovs_list doca_list OVS_GUARDED_BY(doca_mutex)
    = OVS_LIST_INITIALIZER(&doca_list);

struct rss_match_type {
    enum doca_flow_l3_meta l3_type;
    enum doca_flow_l4_meta l4_type;
};

static uint16_t pre_miss_mapping[NUM_SEND_TO_KERNEL] = {
    [SEND_TO_KERNEL_LACP] = ETH_TYPE_LACP,
    [SEND_TO_KERNEL_LLDP] = ETH_TYPE_LLDP,
};

static struct refmap *netdev_doca_esw_rfm;
static struct atomic_count n_doca_ports = ATOMIC_COUNT_INIT(0);

static struct ovs_mutex dpdk_mp_mutex OVS_ACQ_AFTER(doca_mutex)
    = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dpdk_mp's. */
static struct ovs_list dpdk_mp_list OVS_GUARDED_BY(dpdk_mp_mutex)
    = OVS_LIST_INITIALIZER(&dpdk_mp_list);

static void
netdev_doca_destruct(struct netdev *netdev);
static int
netdev_doca_port_stop(struct netdev *netdev);

static bool
dev_is_representor(struct netdev_doca *dev)
{
    return dev->devargs && strstr(dev->devargs, "representor");
}

static uint16_t
netdev_doca_get_esw_mgr_port_id(const struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    int ret = DPDK_ETH_PORT_ID_INVALID;

    if (!rte_eth_dev_is_valid_port(dev->port_id) ||
        !rte_eth_dev_is_valid_port(dev->esw_mgr_port_id)) {
        goto out;
    }

    ret = dev->esw_mgr_port_id;
out:
    return ret;
}

static uint16_t
netdev_doca_get_port_id(const struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    int ret = DPDK_ETH_PORT_ID_INVALID;

    if (!rte_eth_dev_is_valid_port(dev->port_id)) {
        goto out;
    }

    ret = dev->port_id;
out:
    return ret;
}

static bool
netdev_doca_is_esw_mgr(const struct netdev *netdev)
{
    return netdev_doca_get_esw_mgr_port_id(netdev) ==
           netdev_doca_get_port_id(netdev) &&
           netdev_doca_get_esw_mgr_port_id(netdev) != DPDK_ETH_PORT_ID_INVALID;
}

static bool
dev_get_started(const struct netdev_doca *dev)
{
    bool started;

    atomic_read(&dev->started, &started);
    return started;
}

/* ======== slowpath ======== */
static int
netdev_doca_egress_pipe_init(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct ovs_doca_flow_match match;
    struct doca_flow_monitor monitor;
    struct doca_flow_fwd fwd;

    memset(&match, 0, sizeof match);
    memset(&fwd, 0, sizeof fwd);
    memset(&monitor, 0, sizeof monitor);

    /* Meta to match on is defined per entry */
    match.d.meta.pkt_meta = (OVS_FORCE doca_be32_t) UINT32_MAX;
    /* Port ID to forward to is defined per entry */
    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = UINT16_MAX;
    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    return ovs_doca_pipe_create(&dev->up, &match, NULL, &monitor, NULL, NULL,
                                NULL, &fwd, NULL, RTE_MAX_ETHPORTS, true,
                                true, UINT64_C(1) << AUX_QUEUE, "EGRESS",
                                &dev->esw_ctx->egress_pipe);
}

static void
netdev_doca_egress_pipe_uninit(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    ovs_doca_destroy_pipe(&esw->egress_pipe);
}

static int
netdev_doca_rss_pipe_init(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct ovs_doca_flow_actions actions_masks;
    struct ovs_doca_flow_actions actions;
    struct ovs_doca_flow_match match;
    struct doca_flow_monitor monitor;
    struct doca_flow_fwd fwd;
    int rv;

    memset(&match, 0, sizeof match);
    memset(&fwd, 0, sizeof fwd);
    memset(&actions, 0, sizeof actions);
    memset(&actions_masks, 0, sizeof actions_masks);
    memset(&monitor, 0, sizeof monitor);

    memset(&match.d.parser_meta.port_id, 0xFF,
           sizeof match.d.parser_meta.port_id);
    memset(&match.d.parser_meta.outer_l3_type, 0xFF,
           sizeof match.d.parser_meta.outer_l3_type);
    memset(&match.d.parser_meta.outer_l4_type, 0xFF,
           sizeof match.d.parser_meta.outer_l4_type);

    actions_masks.mark = (OVS_FORCE doca_be32_t) UINT32_MAX;
    actions.mark = (OVS_FORCE doca_be32_t) UINT32_MAX;

    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    fwd.type = DOCA_FLOW_FWD_RSS;
    fwd.rss_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
    memset(&fwd.rss.nr_queues, 0xFF, sizeof fwd.rss.nr_queues);

    rv = ovs_doca_pipe_create(&dev->up, &match, NULL, &monitor, &actions,
                              &actions_masks, NULL, &fwd, NULL,
                              NETDEV_DOCA_RSS_NUM_ENTRIES * RTE_MAX_ETHPORTS,
                              false, false, UINT64_C(1) << AUX_QUEUE, "RSS",
                              &dev->esw_ctx->rss_pipe);
    return rv;
}

static void
netdev_doca_rss_pipe_uninit(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    ovs_doca_destroy_pipe(&esw->rss_pipe);
}

static uint32_t
netdev_doca_rss_flags(enum netdev_doca_rss_type type)
{
    switch (type) {
    case NETDEV_DOCA_RSS_IPV4_TCP:
        return DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_TCP;
    case NETDEV_DOCA_RSS_IPV4_UDP:
        return DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_UDP;
    case NETDEV_DOCA_RSS_IPV4_ICMP:
        return DOCA_FLOW_RSS_IPV4;
    case NETDEV_DOCA_RSS_IPV4_ESP:
        return DOCA_FLOW_RSS_IPV4;
    case NETDEV_DOCA_RSS_IPV4_OTHER:
        return DOCA_FLOW_RSS_IPV4;
    case NETDEV_DOCA_RSS_IPV6_TCP:
        return DOCA_FLOW_RSS_IPV6 | DOCA_FLOW_RSS_TCP;
    case NETDEV_DOCA_RSS_IPV6_UDP:
        return DOCA_FLOW_RSS_IPV6 | DOCA_FLOW_RSS_UDP;
    case NETDEV_DOCA_RSS_IPV6_ICMP:
        return DOCA_FLOW_RSS_IPV6;
    case NETDEV_DOCA_RSS_IPV6_ESP:
        return DOCA_FLOW_RSS_IPV6;
    case NETDEV_DOCA_RSS_IPV6_OTHER:
        return DOCA_FLOW_RSS_IPV6;
    case NETDEV_DOCA_RSS_OTHER:
        return 0;
    }
    OVS_NOT_REACHED();
    return 0;
}

static struct rss_match_type
netdev_doca_rss_match_type(enum netdev_doca_rss_type type)
{
    switch (type) {
    case NETDEV_DOCA_RSS_IPV4_TCP:
        return (struct rss_match_type) {
            .l3_type = DOCA_FLOW_L3_META_IPV4,
            .l4_type = DOCA_FLOW_L4_META_TCP,
        };
    case NETDEV_DOCA_RSS_IPV4_UDP:
        return (struct rss_match_type) {
            .l3_type = DOCA_FLOW_L3_META_IPV4,
            .l4_type = DOCA_FLOW_L4_META_UDP,
        };
    case NETDEV_DOCA_RSS_IPV4_ICMP:
        return (struct rss_match_type) {
            .l3_type = DOCA_FLOW_L3_META_IPV4,
            .l4_type = DOCA_FLOW_L4_META_ICMP,
        };
    case NETDEV_DOCA_RSS_IPV4_ESP:
        return (struct rss_match_type) {
            .l3_type = DOCA_FLOW_L3_META_IPV4,
            .l4_type = DOCA_FLOW_L4_META_ESP,
        };
    case NETDEV_DOCA_RSS_IPV4_OTHER:
        return (struct rss_match_type) {
            .l3_type = DOCA_FLOW_L3_META_IPV4,
            .l4_type = DOCA_FLOW_L4_META_NONE,
        };
    case NETDEV_DOCA_RSS_IPV6_TCP:
        return (struct rss_match_type) {
            .l3_type = DOCA_FLOW_L3_META_IPV6,
            .l4_type = DOCA_FLOW_L4_META_TCP,
        };
    case NETDEV_DOCA_RSS_IPV6_UDP:
        return (struct rss_match_type) {
            .l3_type = DOCA_FLOW_L3_META_IPV6,
            .l4_type = DOCA_FLOW_L4_META_UDP,
        };
    case NETDEV_DOCA_RSS_IPV6_ICMP:
        return (struct rss_match_type) {
            .l3_type = DOCA_FLOW_L3_META_IPV6,
            .l4_type = DOCA_FLOW_L4_META_ICMP,
        };
    case NETDEV_DOCA_RSS_IPV6_ESP:
        return (struct rss_match_type) {
            .l3_type = DOCA_FLOW_L3_META_IPV6,
            .l4_type = DOCA_FLOW_L4_META_ESP,
        };
    case NETDEV_DOCA_RSS_IPV6_OTHER:
        return (struct rss_match_type) {
            .l3_type = DOCA_FLOW_L3_META_IPV6,
            .l4_type = DOCA_FLOW_L4_META_NONE,
        };
    case NETDEV_DOCA_RSS_OTHER:
        return (struct rss_match_type) {
            .l3_type = DOCA_FLOW_L3_META_NONE,
            .l4_type = DOCA_FLOW_L4_META_NONE,
        };
    }
    OVS_NOT_REACHED();
    return (struct rss_match_type) {};
}

static const char *
netdev_doca_stats_name(enum netdev_doca_rss_type type)
{
    switch (type) {
    case NETDEV_DOCA_RSS_IPV4_TCP:
        return "rx_ipv4_tcp";
    case NETDEV_DOCA_RSS_IPV4_UDP:
        return "rx_ipv4_udp";
    case NETDEV_DOCA_RSS_IPV4_ICMP:
        return "rx_ipv4_icmp";
    case NETDEV_DOCA_RSS_IPV4_ESP:
        return "rx_ipv4_esp";
    case NETDEV_DOCA_RSS_IPV4_OTHER:
        return "rx_ipv4_other";
    case NETDEV_DOCA_RSS_IPV6_TCP:
        return "rx_ipv6_tcp";
    case NETDEV_DOCA_RSS_IPV6_UDP:
        return "rx_ipv6_udp";
    case NETDEV_DOCA_RSS_IPV6_ICMP:
        return "rx_ipv6_icmp";
    case NETDEV_DOCA_RSS_IPV6_ESP:
        return "rx_ipv6_esp";
    case NETDEV_DOCA_RSS_IPV6_OTHER:
        return "rx_ipv6_other";
    case NETDEV_DOCA_RSS_OTHER:
        return "rx_other";
    }
    OVS_NOT_REACHED();
    return "ERR";
}

static int
netdev_doca_rss_entries_init(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;
    struct ovs_doca_flow_actions actions;
    struct doca_flow_pipe_entry *entry;
    struct ovs_doca_flow_match match;
    uint16_t port_id = dev->port_id;
    unsigned int num_of_queues;
    struct doca_flow_fwd fwd;
    uint16_t *rss_queues;
    int ret;
    int i;

    num_of_queues = esw->n_rxq;

    rss_queues = xcalloc(num_of_queues, sizeof *rss_queues);
    for (i = 0; i < num_of_queues; i++) {
        rss_queues[i] = i;
    }

    memset(&match, 0, sizeof match);
    memset(&actions, 0, sizeof actions);
    memset(&fwd, 0, sizeof fwd);

    fwd.type = DOCA_FLOW_FWD_RSS;
    fwd.rss.queues_array = rss_queues;
    fwd.rss.nr_queues = num_of_queues;
    fwd.rss_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    match.d.parser_meta.port_id = port_id;
    actions.mark = (OVS_FORCE doca_be32_t) DOCA_HTOBE32(port_id);

    for (i = 0; i < NETDEV_DOCA_RSS_NUM_ENTRIES; i++) {
        struct rss_match_type match_type = netdev_doca_rss_match_type(i);

        match.d.parser_meta.outer_l3_type = match_type.l3_type;
        match.d.parser_meta.outer_l4_type = match_type.l4_type;
        fwd.rss.outer_flags = netdev_doca_rss_flags(i);

        ret = ovs_doca_add_entry(&dev->up, AUX_QUEUE, esw->rss_pipe, &match,
                                 &actions, NULL, &fwd,
                                 DOCA_FLOW_ENTRY_FLAGS_NO_WAIT, &entry);
        if (ret) {
            VLOG_ERR("%s: Failed to create '%s' rss entry: Error %d (%s)",
                     netdev_get_name(&dev->up), netdev_doca_stats_name(i),
                     ret, doca_error_get_descr(ret));
            break;
        }
        dev->rss_entries[i] = entry;
    }

    free(rss_queues);

    return ret;
}

static void
netdev_doca_rss_entries_uninit(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    for (int i = 0; i < NETDEV_DOCA_RSS_NUM_ENTRIES; i++) {
        ovs_doca_remove_entry(esw, AUX_QUEUE, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT,
                              &dev->rss_entries[i]);
    }
}

static int
netdev_doca_meta_tag0_pipe_init(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct ovs_doca_flow_actions actions_masks;
    struct ovs_doca_flow_actions actions;
    struct ovs_doca_flow_match match;
    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = dev->esw_ctx->rss_pipe,
    };

    memset(&match, 0, sizeof match);
    memset(&actions, 0, sizeof actions);
    memset(&actions_masks, 0, sizeof actions_masks);

    memset(&actions_masks.d.meta.u32[0], 0xFF,
           sizeof actions_masks.d.meta.u32[0]);

    return ovs_doca_pipe_create(netdev, &match, NULL, NULL, &actions,
                                &actions_masks, NULL, &fwd, NULL, 1, false,
                                false, UINT64_C(1) << AUX_QUEUE, "META_TAG0",
                                &dev->esw_ctx->meta_tag0_pipe);
}

static void
netdev_doca_meta_tag0_pipe_uninit(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    ovs_doca_destroy_pipe(&esw->meta_tag0_pipe);
}

static int
netdev_doca_meta_tag0_rule_init(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct doca_flow_pipe_entry **pentry;
    struct doca_flow_pipe *pipe;
    int ret;

    pentry = &dev->esw_ctx->meta_tag0_entry;
    pipe = dev->esw_ctx->meta_tag0_pipe;

    ret = ovs_doca_add_entry(netdev, AUX_QUEUE, pipe, NULL, NULL, NULL, NULL,
                             DOCA_FLOW_ENTRY_FLAGS_NO_WAIT, pentry);
    if (ret) {
        VLOG_ERR("%s: Failed to create meta-tag0 rule",
                 netdev_get_name(netdev));
    }

    return ret;
}

static void
netdev_doca_meta_tag0_rule_uninit(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    ovs_doca_remove_entry(esw, AUX_QUEUE, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT,
                          &dev->esw_ctx->meta_tag0_entry);
}

static int
netdev_doca_pre_miss_pipe_init(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct ovs_doca_flow_match match = { .d = {
        .parser_meta.outer_l2_type = DOCA_FLOW_L2_META_NO_VLAN,
        .outer.eth.type = UINT16_MAX,
    }, };
    struct doca_flow_target *kernel_target;
    struct doca_flow_fwd fwd, miss;

    memset(&miss, 0, sizeof miss);
    memset(&fwd, 0, sizeof fwd);

    miss.type = DOCA_FLOW_FWD_PIPE;
    miss.next_pipe = dev->esw_ctx->meta_tag0_pipe;

    if (doca_flow_get_target(DOCA_FLOW_TARGET_KERNEL, &kernel_target)) {
        VLOG_ERR("%s: Could not get miss to kernel target",
                 netdev_get_name(netdev));
        return -1;
    }
    fwd.type = DOCA_FLOW_FWD_TARGET;
    fwd.target = kernel_target;

    return ovs_doca_pipe_create(netdev, &match, NULL, NULL, NULL, NULL, NULL,
                                &fwd, &miss, NUM_SEND_TO_KERNEL, false,
                                false, UINT64_C(1) << AUX_QUEUE, "PRE_MISS",
                                &dev->esw_ctx->pre_miss_pipe);
}

static void
netdev_doca_pre_miss_pipe_uninit(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    ovs_doca_destroy_pipe(&esw->pre_miss_pipe);
}

static int
netdev_doca_pre_miss_rules_init(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct doca_flow_pipe_entry **pentry;
    struct ovs_doca_flow_match match;
    int ret;

    memset(&match, 0, sizeof match);

    for (int i = 0 ; i < NUM_SEND_TO_KERNEL ; i++) {
        pentry = &dev->esw_ctx->pre_miss_entries[i];

        match.d.outer.eth.type = htons(pre_miss_mapping[i]);
        ret = ovs_doca_add_entry(netdev, AUX_QUEUE,
                                 dev->esw_ctx->pre_miss_pipe, &match, NULL,
                                 NULL, NULL, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT,
                                 pentry);
        if (ret) {
            VLOG_ERR("%s: Failed to create pre_miss %x rule",
                     netdev_get_name(netdev), pre_miss_mapping[i]);
            break;
        }
    }

    return ret;
}

static void
netdev_doca_pre_miss_rules_uninit(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    for (int i = 0 ; i < NUM_SEND_TO_KERNEL ; i++) {
        ovs_doca_remove_entry(esw, AUX_QUEUE, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT,
                              &esw->pre_miss_entries[i]);
    }
}

static int
netdev_doca_root_pipe_init(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct doca_flow_fwd miss;

    memset(&miss, 0, sizeof miss);
    miss.type = DOCA_FLOW_FWD_PIPE;
    miss.next_pipe = dev->esw_ctx->pre_miss_pipe;

    return ovs_doca_pipe_create(netdev, NULL, NULL, NULL, NULL, NULL, NULL,
                                NULL, &miss, 0, false, true, 0, "ROOT",
                                &dev->esw_ctx->root_pipe);
}

static void
netdev_doca_root_pipe_uninit(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    ovs_doca_destroy_pipe(&esw->root_pipe);
}

static int
netdev_doca_egress_entry_init(struct netdev_doca *dev)
{
    struct doca_flow_pipe *pipe = dev->esw_ctx->egress_pipe;
    struct ovs_doca_flow_match match;
    uint16_t port_id = dev->port_id;
    struct doca_flow_fwd fwd;
    int ret;

    memset(&match, 0, sizeof match);
    memset(&fwd, 0, sizeof fwd);

    match.d.meta.pkt_meta = (OVS_FORCE doca_be32_t) DOCA_HTOBE32(port_id);

    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = port_id;

    ret = ovs_doca_add_entry(&dev->up, AUX_QUEUE, pipe, &match, NULL, NULL,
                             &fwd, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT,
                             &dev->egress_entry);
    if (ret) {
        VLOG_ERR("Failed to create egress pipe entry. Error %d (%s)", ret,
                 doca_error_get_descr(ret));
    }

    return ret;
}

static void
netdev_doca_egress_entry_uninit(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    ovs_doca_remove_entry(esw, AUX_QUEUE, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT,
                          &dev->egress_entry);
}

static void
netdev_doca_slowpath_esw_uninit(struct netdev *netdev)
{
    netdev_doca_root_pipe_uninit(netdev);
    netdev_doca_pre_miss_rules_uninit(netdev);
    netdev_doca_pre_miss_pipe_uninit(netdev);
    netdev_doca_meta_tag0_rule_uninit(netdev);
    netdev_doca_meta_tag0_pipe_uninit(netdev);
    netdev_doca_rss_pipe_uninit(netdev);
    netdev_doca_egress_pipe_uninit(netdev);
}

static int
netdev_doca_slowpath_esw_init(struct netdev *netdev)
{
    int rv;

#define ESW_INIT_CMD(func)                                    \
    do {                                                      \
        rv = (func)(netdev);                                  \
        if (!rv) {                                            \
            break;                                            \
        }                                                     \
        VLOG_ERR("%s: Failed at %s", netdev_get_name(netdev), \
                 OVS_SOURCE_LOCATOR);                         \
        return rv;                                            \
    } while (0)

    ESW_INIT_CMD(netdev_doca_egress_pipe_init);
    ESW_INIT_CMD(netdev_doca_rss_pipe_init);
    ESW_INIT_CMD(netdev_doca_meta_tag0_pipe_init);
    ESW_INIT_CMD(netdev_doca_meta_tag0_rule_init);
    ESW_INIT_CMD(netdev_doca_pre_miss_pipe_init);
    ESW_INIT_CMD(netdev_doca_pre_miss_rules_init);
    ESW_INIT_CMD(netdev_doca_root_pipe_init);

    return 0;
}

static void
netdev_doca_esw_port_uninit(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;
    uint16_t pid;

    if (!esw) {
        return;
    }

    for (pid = 0; pid < RTE_MAX_ETHPORTS; pid++) {
        if (esw->port_queues[pid]) {
            for (uint16_t qid = 0; qid < esw->n_rxq; qid++) {
                struct rte_ring **pring = &esw->port_queues[pid][qid].ring;
                struct dp_packet *pkt;
                int deq;

                if (!*pring) {
                    continue;
                }

                while (1) {
                    deq = rte_ring_dequeue(*pring, (void **) &pkt);
                    if (deq) {
                        break;
                    }
                    dp_packet_delete(pkt);
                }
                rte_ring_free(*pring);
                *pring = NULL;
            }
            rte_free(esw->port_queues[pid]);
            esw->port_queues[pid] = NULL;
        }
    }

    netdev_doca_slowpath_esw_uninit(netdev);

    ovs_mutex_destroy(&esw->mgmt_queue_lock);
}

static int
netdev_doca_esw_init(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;
    uint16_t pid;
    int rv;

    ovs_mutex_init(&esw->mgmt_queue_lock);
    esw->esw_port = dev->port;
    esw->esw_netdev = netdev;
    esw->port_id = dev->port_id;
    esw->n_rxq = netdev->n_rxq;

    rv = netdev_doca_slowpath_esw_init(netdev);
    if (rv) {
        return rv;
    }

    for (pid = 0; pid < RTE_MAX_ETHPORTS; pid++) {
        uint16_t qid;

        esw->port_queues[pid] =
            rte_calloc_socket("port_queues", esw->n_rxq,
                              sizeof(struct netdev_doca_port_queue),
                              RTE_CACHE_LINE_SIZE,
                              dev->socket_id);
        if (!esw->port_queues[pid]) {
            goto err;
        }
        for (qid = 0; qid < esw->n_rxq; qid++) {
            char *ring_name;

            ring_name = xasprintf("%s-%d-%d", netdev_get_name(netdev), pid,
                                  qid);
            if (!ring_name) {
                goto err;
            }
            if (strlen(ring_name) >= RTE_RING_NAMESIZE) {
                free(ring_name);
                goto err;
            }
            esw->port_queues[pid][qid].ring =
                rte_ring_create(ring_name, NETDEV_MAX_BURST * 2,
                                dev->socket_id,
                                RING_F_SC_DEQ | RING_F_SP_ENQ);
            free(ring_name);
            if (!esw->port_queues[pid][qid].ring) {
                goto err;
            }
            atomic_init(&esw->port_queues[pid][qid].n_packets, 0);
            atomic_init(&esw->port_queues[pid][qid].n_bytes, 0);
        }
    }

    return 0;
err:
    netdev_doca_esw_port_uninit(netdev);
    return -1;
}

/* ======== sys-fs ======== */
static int
get_sys(const char *prefix, const char *devname, const char *suffix,
        char *outp, size_t maxlen)
{
    char str[PATH_MAX];
    size_t len;
    FILE *fp;
    char *p;
    int n;

    n = snprintf(str, sizeof str, "/sys/%s/%s/%s", prefix, devname, suffix);
    if (!(n >= 0 && n < sizeof str)) {
        return -1;
    }

    fp = fopen(str, "r");
    if (fp == NULL) {
        return -1;
    }

    p = fgets(str, sizeof str, fp);
    fclose(fp);

    if (p == NULL) {
        return -1;
    }

    /* The string is terminated by \n. Drop it. */
    if (outp) {
        len = strnlen(str, maxlen);
        if (maxlen <= len) {
            return -1;
        }
        ovs_strlcpy(outp, str, len);
    }

    return 0;
}

static int
get_phys_port_name(const char *devname, char *outp, size_t maxlen)
{
    return get_sys("class/net", devname, "phys_port_name", outp, maxlen);
}

static int
get_phys_switch_id(const char *devname, char *outp, size_t maxlen)
{
    return get_sys("class/net", devname, "phys_switch_id", outp, maxlen);
}

static int
get_bonding_slaves(const char *devname, char *outp, size_t maxlen)
{
    return get_sys("class/net", devname, "bonding/slaves", outp, maxlen);
}

static bool
is_mpesw(const char *pci)
{
    char tmp[PATH_MAX];
    DIR *dirp;

    /* Reading /sys/kernel/debug/mlx5/0000:08:00.0/lag/type requires
     * openvswitch to run as root. Instead check if we are in shared
     * fdb mode which means lag mode by checking the infiniband port
     * doesn't exists.
     */
    if (snprintf(tmp, sizeof tmp,
                 "/sys/bus/pci/devices/%s/infiniband", pci) < 0) {
        return false;
    }
    if ((dirp = opendir(tmp)) == NULL) {
        return true;
    }
    closedir(dirp);

    return false;
}

static int
get_pci(const char *name, char *pci, size_t maxlen)
{
    char device[PATH_MAX];
    char tmp[PATH_MAX];
    char *slash;
    int len;

    if (maxlen <= PCI_PRI_STR_SIZE) {
        return EINVAL;
    }

    if (snprintf(tmp, sizeof tmp, "/sys/class/net/%s/device", name) < 0) {
        return EINVAL;
    }
    memset(device, 0, sizeof device);
    len = readlink(tmp, device, sizeof device);
    if (len == 0) {
        return ENODEV;
    } else if (len < PCI_PRI_STR_SIZE || len >= sizeof device) {
        return E2BIG;
    }
    /* The result is like this: "../../../0000:08:00.0".
     * Take the last 12 chars as the PCI address.
     */
    slash = strrchr(device, '/');
    if (!slash) {
        return EINVAL;
    }

    ovs_strlcpy(pci, slash + 1, maxlen);
    return 0;
}

static int
get_primary_pci(const char *sw_id, char *pci, size_t maxlen)
{
    char *sys_class_net = "/sys/class/net";
    struct dirent *de;
    int err = EINVAL;
    DIR *dirp;

    dirp = opendir(sys_class_net);
    if (dirp == NULL) {
        goto out;
    }

    pci[0] = '\0';
    while ((de = readdir(dirp)) != NULL) {
        char p_switch_id[IFNAMSIZ];
        char p_port_name[IFNAMSIZ];

        if (get_phys_port_name(de->d_name, p_port_name, sizeof p_port_name)) {
            continue;
        }
        if (strcmp(p_port_name, "p0")) {
            continue;
        }

        if (get_phys_switch_id(de->d_name, p_switch_id, sizeof p_switch_id)) {
            continue;
        }
        if (strcmp(p_switch_id, sw_id)) {
            continue;
        }

        err = get_pci(de->d_name, pci, maxlen);
        break;
    }
    closedir(dirp);
out:
    return err;
}

static int
get_dpdk_iface_name(const char *name, char iface[IFNAMSIZ])
{
    char phys_port_name[IFNAMSIZ];
    char slaves[PATH_MAX];
    char *save_ptr;
    char *lower;

    /* In case the device is a bond, there is a lower_p0 symbolic link, with
     * the format of ../../.../<lower-dev>. Extract the lower device.
     */

    if (get_bonding_slaves(name, slaves, sizeof slaves)) {
        goto fallback;
    }

    lower = strtok_r(slaves, " ", &save_ptr);
    while (lower) {
        if (!get_phys_port_name(lower, phys_port_name,
                                sizeof phys_port_name) &&
            !strcmp(phys_port_name, "p0")) {
            break;
        }
        lower = strtok_r(NULL, " ", &save_ptr);
    }

    if (!lower) {
        goto fallback;
    }

    /* Reached here if found a lower device p0. */
    ovs_strlcpy(iface, lower, IFNAMSIZ);
    goto out;

fallback:
    ovs_strlcpy(iface, name, IFNAMSIZ);
out:
    return 0;
}

/* ======== netdev ======== */
struct netdev_doca *
netdev_doca_cast(const struct netdev *netdev)
{
    return CONTAINER_OF(netdev, struct netdev_doca, up);
}

/* Allocates an area of 'sz' bytes from DPDK.  The memory is zero'ed.
 *
 * Unlike xmalloc(), this function can return NULL on failure. */
static void *
doca_rte_mzalloc(const char *type, size_t sz)
{
    return rte_zmalloc(type, sz, CACHE_LINE_SIZE);
}

static struct netdev *
netdev_doca_alloc(void)
{
    struct netdev_doca *dev;

    dev = doca_rte_mzalloc("ovs_doca_netdev", sizeof *dev);
    if (!dev) {
        return NULL;
    }

    /* Upon the first port disable dpdk steering to allow doca to work. */
    if (!atomic_count_inc(&n_doca_ports)) {
        rte_pmd_mlx5_disable_steering();
    }

    return &dev->up;
}

static void
netdev_doca_dealloc(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    /* Upon the last doca port going down, enable back dpdk steering. */
    if (atomic_count_dec(&n_doca_ports) == 1) {
        rte_pmd_mlx5_enable_steering();
    }

    rte_free(dev);
}

static int
netdev_doca_get_numa_id(const struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    return dev->socket_id;
}

static int
netdev_doca_set_etheraddr__(struct netdev_doca *dev, const struct eth_addr mac)
    OVS_REQUIRES(dev->mutex)
{
    struct rte_ether_addr ea;
    int err;

    memcpy(ea.addr_bytes, mac.ea, ETH_ADDR_LEN);
    err = -rte_eth_dev_default_mac_addr_set(dev->port_id, &ea);
    if (!err) {
        dev->hwaddr = mac;
    } else {
        VLOG_WARN("%s: Failed to set requested mac("ETH_ADDR_FMT"): %s",
                  netdev_get_name(&dev->up), ETH_ADDR_ARGS(mac),
                  rte_strerror(err));
    }

    return err;
}

static int
netdev_doca_set_etheraddr(struct netdev *netdev, const struct eth_addr mac)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    int err = 0;

    ovs_mutex_lock(&dev->mutex);
    if (!eth_addr_equals(dev->hwaddr, mac)) {
        err = netdev_doca_set_etheraddr__(dev, mac);
        if (!err) {
            netdev_change_seq_changed(netdev);
        }
    }
    ovs_mutex_unlock(&dev->mutex);

    return err;
}

static int
netdev_doca_get_etheraddr(const struct netdev *netdev, struct eth_addr *mac)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    *mac = dev->hwaddr;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_doca_get_mtu(const struct netdev *netdev, int *mtup)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    *mtup = dev->mtu;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_doca_set_mtu(struct netdev *netdev, int mtu)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    if (dev->requested_mtu != mtu) {
        dev->requested_mtu = mtu;
        netdev_request_reconfigure(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_doca_get_ifindex(const struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    /* Calculate hash from the netdev name. Ensure that ifindex is a 24-bit
     * postive integer to meet RFC 2863 recommendations.
     */
    int ifindex = hash_string(netdev->name, 0) % 0xfffffe + 1;
    ovs_mutex_unlock(&dev->mutex);

    return ifindex;
}

static long long int
netdev_doca_get_carrier_resets(const struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    long long int carrier_resets;

    ovs_mutex_lock(&dev->mutex);
    carrier_resets = dev->link_reset_cnt;
    ovs_mutex_unlock(&dev->mutex);

    return carrier_resets;
}

static int
netdev_doca_set_miimon(struct netdev *netdev OVS_UNUSED,
                       long long int interval OVS_UNUSED)
{
    return EOPNOTSUPP;
}

static int
netdev_doca_update_flags__(struct netdev_doca *dev,
                           enum netdev_flags off, enum netdev_flags on,
                           enum netdev_flags *old_flagsp)
    OVS_REQUIRES(dev->mutex)
{
    if ((off | on) & ~(NETDEV_UP | NETDEV_PROMISC)) {
        return EINVAL;
    }

    *old_flagsp = dev->flags;
    dev->flags |= on;
    dev->flags &= ~off;

    if (dev->flags == *old_flagsp) {
        return 0;
    }

    if ((dev->flags ^ *old_flagsp) & NETDEV_UP) {
        int err;

        if (dev->flags & NETDEV_UP) {
            err = rte_eth_dev_set_link_up(dev->port_id);
        } else {
            err = rte_eth_dev_set_link_down(dev->port_id);
        }
        if (err == -ENOTSUP) {
            VLOG_INFO("Interface %s does not support link state "
                      "configuration", netdev_get_name(&dev->up));
        } else if (err < 0) {
            VLOG_ERR("Interface %s link change error: %s",
                     netdev_get_name(&dev->up), rte_strerror(-err));
            dev->flags = *old_flagsp;
            return -err;
        }
    }

    if (dev->flags & NETDEV_PROMISC) {
        rte_eth_promiscuous_enable(dev->port_id);
    }

    netdev_change_seq_changed(&dev->up);

    return 0;
}

static int
netdev_doca_update_flags(struct netdev *netdev,
                         enum netdev_flags off, enum netdev_flags on,
                         enum netdev_flags *old_flagsp)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    int error;

    ovs_mutex_lock(&dev->mutex);
    error = netdev_doca_update_flags__(dev, off, on, old_flagsp);
    ovs_mutex_unlock(&dev->mutex);

    return error;
}

static struct netdev_rxq *
netdev_doca_rxq_alloc(void)
{
    struct netdev_rxq_doca *rx = doca_rte_mzalloc("ovs_doca_rxq", sizeof *rx);

    if (rx) {
        return &rx->up;
    }

    return NULL;
}

static struct netdev_rxq_doca *
netdev_rxq_doca_cast(const struct netdev_rxq *rxq)
{
    return CONTAINER_OF(rxq, struct netdev_rxq_doca, up);
}

static int
netdev_doca_rxq_construct(struct netdev_rxq *rxq)
{
    struct netdev_rxq_doca *rx = netdev_rxq_doca_cast(rxq);
    struct netdev_doca *dev = netdev_doca_cast(rxq->netdev);

    ovs_mutex_lock(&dev->mutex);
    rx->port_id = dev->port_id;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static void
netdev_doca_rxq_destruct(struct netdev_rxq *rxq OVS_UNUSED)
{
}

static void
netdev_doca_rxq_dealloc(struct netdev_rxq *rxq)
{
    struct netdev_rxq_doca *rx = netdev_rxq_doca_cast(rxq);

    rte_free(rx);
}

static void
check_link_status(struct netdev_doca *dev)
{
    struct rte_eth_link link;

    if (!dev_get_started(dev)) {
        return;
    }

    if (rte_eth_link_get_nowait(dev->port_id, &link) < 0) {
        VLOG_DBG_RL(&rl,
                    "Failed to retrieve link status for port %d",
                    dev->port_id);
        return;
    }

    if (dev->link.link_status != link.link_status) {
        netdev_change_seq_changed(&dev->up);

        dev->link_reset_cnt++;
        dev->link = link;
        if (dev->link.link_status) {
            VLOG_DBG_RL(&rl,
                        "Port %d Link Up - speed %u Mbps - %s",
                        dev->port_id, (unsigned) dev->link.link_speed,
                        (dev->link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX)
                        ? "full-duplex" : "half-duplex");
        } else {
            VLOG_DBG_RL(&rl, "Port %d Link Down",
                        dev->port_id);
        }
    }
}

static void *
doca_watchdog(void *dummy OVS_UNUSED)
{
    struct netdev_doca *dev;

    pthread_detach(pthread_self());

    for (;;) {
        ovs_mutex_lock(&doca_mutex);
        LIST_FOR_EACH (dev, list_node, &doca_list) {
            ovs_mutex_lock(&dev->mutex);
            check_link_status(dev);
            ovs_mutex_unlock(&dev->mutex);
        }
        ovs_mutex_unlock(&doca_mutex);
        xsleep(DOCA_PORT_WATCHDOG_INTERVAL);
    }

    return NULL;
}

static int
netdev_doca_dev_open_pci(struct rte_pci_addr *rte_pci, struct doca_dev **pdev)
{
    struct doca_devinfo **dev_list;
    char pci[PCI_PRI_STR_SIZE];
    uint8_t is_esw_manager = 0;
    uint8_t is_addr_equal = 0;
    uint32_t nb_devs;
    size_t i;
    int res;

    /* Set default return value */
    *pdev = NULL;

    res = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (res != DOCA_SUCCESS) {
        VLOG_ERR("Failed to load doca devices list. Doca_error value: %d",
                 res);
        return res;
    }

    rte_pci_device_name(rte_pci, pci, sizeof pci);
    /* Search */
    for (i = 0; i < nb_devs; i++) {
        res = doca_devinfo_is_equal_pci_addr(dev_list[i], pci, &is_addr_equal);
        if (res != DOCA_SUCCESS || !is_addr_equal) {
            continue;
        }
        res = doca_dpdk_cap_is_rep_port_supported(dev_list[i],
                                                  &is_esw_manager);
        if (res != DOCA_SUCCESS || !is_esw_manager) {
            continue;
        }
        VLOG_INFO("Opening '%s'", pci);
        res = doca_dev_open(dev_list[i], pdev);
        if (res != DOCA_SUCCESS) {
            VLOG_ERR("Failed to open DOCA device: %s",
                     doca_error_get_descr(res));
        }
        goto out;
    }

    VLOG_WARN("No matching doca device found");
    res = DOCA_ERROR_NOT_FOUND;

out:
    doca_devinfo_destroy_list(dev_list);
    return res;
}

static int
netdev_doca_esw_ctx_init(void *ctx_, void *arg_)
{
    struct netdev_doca_esw_ctx_arg *arg = arg_;
    struct netdev_doca_esw_ctx *ctx = ctx_;

    if (netdev_doca_dev_open_pci(&arg->esw_key->rte_pci, &ctx->dev)) {
        return ENODEV;
    }
    rte_pci_device_name(&arg->esw_key->rte_pci, ctx->pci_addr,
                        sizeof ctx->pci_addr);
    ctx->cmd_fd = -1;
    memset(ctx->offload_queues, 0, sizeof ctx->offload_queues);

    return 0;
}

static void
netdev_doca_esw_ctx_uninit(void *ctx_)
{
    struct netdev_doca_esw_ctx *ctx = ctx_;

    memset(ctx->pci_addr, 0, sizeof ctx->pci_addr);
}

static struct ds *
dump_netdev_doca_esw(struct ds *s, void *key_,
                     void *ctx_ OVS_UNUSED, void *arg_ OVS_UNUSED)
{
    struct netdev_doca_esw_key *key = key_;
    char pci_addr[PCI_PRI_STR_SIZE];

    rte_pci_device_name(&key->rte_pci, pci_addr, sizeof pci_addr);
    ds_put_format(s, "pci=%s, ", pci_addr);

    return s;
}

static int
netdev_doca_class_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (!ovsthread_once_start(&once)) {
        return 0;
    }

    ovs_thread_create("doca_watchdog", doca_watchdog, NULL);
    netdev_doca_esw_rfm = refmap_create("netdev-doca-esw",
                                        sizeof(struct netdev_doca_esw_key),
                                        sizeof(struct netdev_doca_esw_ctx),
                                        netdev_doca_esw_ctx_init,
                                        netdev_doca_esw_ctx_uninit,
                                        dump_netdev_doca_esw);

    ovsthread_once_done(&once);
    return 0;
}

/* Extract the PCI part from 'devargs' to rte_pci.
 * Return -EINVAL for error or 0 for success.
 */
static int
netdev_doca_parse_dpdk_devargs_pci(const char *devargs,
                                   struct rte_pci_addr *rte_pci)
{
    struct rte_devargs da;
    int rv = 0;

    if (rte_devargs_parse(&da, devargs)) {
        return -1; /* Error has already been printed by the RTE function. */
    }

    if (rte_pci_addr_parse(da.name, rte_pci)) {
        rv = -1;
        goto out;
    }

out:
    rte_devargs_reset(&da);
    return rv;
}

static bool
netdev_doca_foreach_representor(struct netdev_doca *esw_dev,
                                bool (*cb)(struct netdev_doca *, uint16_t))
    OVS_REQUIRES(doca_mutex)
{
    bool need_reconfigure = false;
    struct rte_pci_addr esw_pci;
    struct rte_pci_addr rep_pci;
    struct netdev_doca *dev;

    if (netdev_doca_parse_dpdk_devargs_pci(esw_dev->devargs, &esw_pci)) {
        return false;
    }

    LIST_FOR_EACH (dev, list_node, &doca_list) {
        if (esw_dev == dev) {
            continue;
        }
        if (!dev->devargs ||
            netdev_doca_parse_dpdk_devargs_pci(dev->devargs, &rep_pci)) {
            continue;
        }
        if (rte_pci_addr_cmp(&rep_pci, &esw_pci)) {
            continue;
        }

        ovs_mutex_lock(&dev->mutex);
        need_reconfigure |= cb(dev, esw_dev->port_id);
        ovs_mutex_unlock(&dev->mutex);
        netdev_request_reconfigure(&dev->up);
    }

    return need_reconfigure;
}

static void
netdev_doca_dev_close(struct netdev_doca *dev)
{
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;
    struct rte_eth_dev_info dev_info;
    char *pci_addr;
    bool last;
    int err;

    memset(&dev_info, 0, sizeof dev_info);

    if (rte_eth_dev_is_valid_port(dev->port_id)) {
        err = rte_eth_dev_info_get(dev->port_id, &dev_info);
        if (err) {
            VLOG_ERR("Failed to get info of port %d: %s", dev->port_id,
                     rte_strerror(-err));
        }
        err = rte_eth_dev_close(dev->port_id);
        if (err) {
            VLOG_ERR("Failed to close port %d: %s", dev->port_id,
                     rte_strerror(-err));
        }
    }

    if (!esw) {
        return;
    }

    pci_addr = xstrdup(esw->pci_addr);
    if (dev->port_id != dev->esw_mgr_port_id && dev->dev_rep) {
        err = doca_dev_rep_close(dev->dev_rep);
        if (err) {
            VLOG_ERR("Failed to close doca dev_rep with port id %d. "
                     "Error: %d (%s)", dev->port_id, err,
                     doca_error_get_descr(err));
        }
        dev->dev_rep = NULL;
    }

    last = refmap_unref(netdev_doca_esw_rfm, esw);
    if (last && esw->dev) {
        if (rte_eth_dev_is_valid_port(dev->esw_mgr_port_id)) {
            err = rte_eth_dev_close(dev->esw_mgr_port_id);
            if (err) {
                VLOG_ERR("Failed to close esw_mgr port %d: %s",
                         dev->esw_mgr_port_id, rte_strerror(-err));
            }
        }
        /* esw->cmd_fd is closed inside. */
        if (dev_info.device) {
            err = rte_dev_remove(dev_info.device);
            if (err) {
                VLOG_ERR("Failed to remove device %s: %s", dev->devargs,
                         rte_strerror(-err));
            }
        }

        VLOG_INFO("Closing '%s'", pci_addr);
        err = doca_dev_close(esw->dev);
        if (err) {
            VLOG_ERR("Failed to close doca dev %s. Error: %d (%s)", pci_addr,
                     err, doca_error_get_descr(err));
        }
        esw->dev = NULL;
        esw->cmd_fd = -1;
    }

    dev->esw_ctx = NULL;
    free(pci_addr);
}

static bool
netdev_doca_rep_stop(struct netdev_doca *dev,
                     uint16_t esw_mgr_port_id OVS_UNUSED)
{
    if (!dev_get_started(dev)) {
        return false;
    }

    netdev_doca_port_stop(&dev->up);
    netdev_doca_dev_close(dev);
    dev->port_id = DPDK_ETH_PORT_ID_INVALID;
    dev->esw_mgr_port_id = DPDK_ETH_PORT_ID_INVALID;
    dev->attached = false;

    return true;
}

static int
netdev_doca_port_stop(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    int err = 0;

    if (!dev_get_started(dev)) {
        return 0;
    }

    if (netdev_doca_get_esw_mgr_port_id(netdev) == dev->port_id &&
        netdev_doca_foreach_representor(dev, netdev_doca_rep_stop)) {
        /* If a representor is reconfigured a result of its ESW manager
         * change, it might not be synced in the bridge's database. Signal it
         * to reconfigure, to make it right.
         */
        rtnetlink_report_link();
    }

    VLOG_INFO("%s: Stopping '%s', port_id=%d", netdev_get_name(netdev),
              dev->devargs, dev->port_id);

    atomic_store(&dev->started, false);

    netdev_doca_rss_entries_uninit(netdev);
    netdev_doca_egress_entry_uninit(netdev);

    if (dev->port_id == dev->esw_mgr_port_id) {
        netdev_doca_esw_port_uninit(netdev);
    }

    if (dev->port) {
        err = doca_flow_port_stop(dev->port);
        dev->port = NULL;
    }

    rte_eth_dev_stop(dev->port_id);

    return err;
}

static void
netdev_doca_clear_xstats(struct netdev_doca *dev)
    OVS_REQUIRES(dev->mutex)
{
    free(dev->rte_xstats_names);
    dev->rte_xstats_names = NULL;
    dev->rte_xstats_names_size = 0;
    free(dev->rte_xstats_ids);
    dev->rte_xstats_ids = NULL;
    dev->rte_xstats_ids_size = 0;
}

static void
dpdk_mp_put(struct dpdk_mp *dmp)
{
    if (!dmp) {
        return;
    }

    ovs_mutex_lock(&dpdk_mp_mutex);
    ovs_assert(dmp->refcount);
    dmp->refcount--;
    ovs_mutex_unlock(&dpdk_mp_mutex);
}

static void
common_destruct(struct netdev_doca *dev)
    OVS_REQUIRES(doca_mutex)
    OVS_EXCLUDED(dev->mutex)
{
    rte_free(dev->tx_q);
    dpdk_mp_put(dev->dpdk_mp);

    ovs_list_remove(&dev->list_node);
    free(dev->sw_tx_stats);
    free(dev->sw_stats);
    ovs_mutex_destroy(&dev->mutex);
}

static void
netdev_doca_destruct(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_lock(&doca_mutex);

    netdev_doca_port_stop(netdev);

    if (dev->attached) {
        netdev_doca_dev_close(dev);
        dev->port_id = DPDK_ETH_PORT_ID_INVALID;

        VLOG_INFO("Device '%s' has been removed", dev->devargs);
    }

    netdev_doca_clear_xstats(dev);
    free(dev->devargs);
    common_destruct(dev);

    ovs_mutex_unlock(&doca_mutex);
}

/* Sets the number of tx queues for the DOCA interface. */
static int
netdev_doca_set_tx_multiq(struct netdev *netdev, unsigned int n_txq)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_lock(&dev->mutex);

    if (dev->requested_n_txq == n_txq) {
        goto out;
    }

    dev->requested_n_txq = n_txq;
    netdev_request_reconfigure(netdev);

out:
    ovs_mutex_unlock(&dev->mutex);
    return 0;
}

static int
netdev_doca_get_carrier(const struct netdev *netdev, bool *carrier)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    check_link_status(dev);
    *carrier = dev->link.link_status;

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static void
netdev_doca_convert_xstats(struct netdev_stats *stats,
                           const struct rte_eth_xstat *xstats,
                           const struct rte_eth_xstat_name *names,
                           const unsigned int size)
{
/* DPDK XSTATS Counter names definition. */
#define DPDK_XSTATS \
    DPDK_XSTAT(multicast,               "rx_multicast_packets"            ) \
    DPDK_XSTAT(tx_multicast_packets,    "tx_multicast_packets"            ) \
    DPDK_XSTAT(rx_broadcast_packets,    "rx_broadcast_packets"            ) \
    DPDK_XSTAT(tx_broadcast_packets,    "tx_broadcast_packets"            ) \
    DPDK_XSTAT(rx_undersized_errors,    "rx_undersized_errors"            ) \
    DPDK_XSTAT(rx_oversize_errors,      "rx_oversize_errors"              ) \
    DPDK_XSTAT(rx_fragmented_errors,    "rx_fragmented_errors"            ) \
    DPDK_XSTAT(rx_jabber_errors,        "rx_jabber_errors"                ) \
    DPDK_XSTAT(rx_1_to_64_packets,      "rx_size_64_packets"              ) \
    DPDK_XSTAT(rx_65_to_127_packets,    "rx_size_65_to_127_packets"       ) \
    DPDK_XSTAT(rx_128_to_255_packets,   "rx_size_128_to_255_packets"      ) \
    DPDK_XSTAT(rx_256_to_511_packets,   "rx_size_256_to_511_packets"      ) \
    DPDK_XSTAT(rx_512_to_1023_packets,  "rx_size_512_to_1023_packets"     ) \
    DPDK_XSTAT(rx_1024_to_1522_packets, "rx_size_1024_to_1522_packets"    ) \
    DPDK_XSTAT(rx_1523_to_max_packets,  "rx_size_1523_to_max_packets"     ) \
    DPDK_XSTAT(tx_1_to_64_packets,      "tx_size_64_packets"              ) \
    DPDK_XSTAT(tx_65_to_127_packets,    "tx_size_65_to_127_packets"       ) \
    DPDK_XSTAT(tx_128_to_255_packets,   "tx_size_128_to_255_packets"      ) \
    DPDK_XSTAT(tx_256_to_511_packets,   "tx_size_256_to_511_packets"      ) \
    DPDK_XSTAT(tx_512_to_1023_packets,  "tx_size_512_to_1023_packets"     ) \
    DPDK_XSTAT(tx_1024_to_1522_packets, "tx_size_1024_to_1522_packets"    ) \
    DPDK_XSTAT(tx_1523_to_max_packets,  "tx_size_1523_to_max_packets"     )

    for (unsigned int i = 0; i < size; i++) {
#define DPDK_XSTAT(MEMBER, NAME) \
        if (strcmp(NAME, names[i].name) == 0) {   \
            stats->MEMBER = xstats[i].value;      \
            continue;                             \
        }
        DPDK_XSTATS;
#undef DPDK_XSTAT
    }
#undef DPDK_XSTATS
}

static int
netdev_doca_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    int rte_xstats_len, rte_xstats_new_len, rte_xstats_ret;
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct rte_eth_xstat_name *rte_xstats_names = NULL;
    struct rte_eth_xstat *rte_xstats = NULL;
    struct rte_eth_stats rte_stats;
    bool gg;

    netdev_doca_get_carrier(netdev, &gg);
    ovs_mutex_lock(&dev->mutex);

    if (!dev_get_started(dev)) {
        ovs_mutex_unlock(&dev->mutex);
        return ENODEV;
    }

    if (rte_eth_stats_get(dev->port_id, &rte_stats)) {
        VLOG_ERR("Can't get ETH statistics for port: %d",
                 dev->port_id);
        ovs_mutex_unlock(&dev->mutex);
        return EPROTO;
    }

    /* Get length of statistics */
    rte_xstats_len = rte_eth_xstats_get_names(dev->port_id, NULL, 0);
    if (rte_xstats_len < 0) {
        VLOG_WARN("Cannot get XSTATS values for port: %d",
                  dev->port_id);
        goto out;
    }
    /* Reserve memory for rte_xstats names and values */
    rte_xstats_names = xcalloc(rte_xstats_len, sizeof *rte_xstats_names);
    rte_xstats = xcalloc(rte_xstats_len, sizeof *rte_xstats);

    /* Retreive rte_xstats names */
    rte_xstats_new_len = rte_eth_xstats_get_names(dev->port_id,
                                                  rte_xstats_names,
                                                  rte_xstats_len);
    if (rte_xstats_new_len != rte_xstats_len) {
        VLOG_WARN("Cannot get XSTATS names for port: %d",
                  dev->port_id);
        goto out;
    }
    /* Retreive rte_xstats values */
    memset(rte_xstats, 0xff, sizeof *rte_xstats * rte_xstats_len);
    rte_xstats_ret = rte_eth_xstats_get(dev->port_id, rte_xstats,
                                        rte_xstats_len);
    if (rte_xstats_ret > 0 && rte_xstats_ret <= rte_xstats_len) {
        netdev_doca_convert_xstats(stats, rte_xstats, rte_xstats_names,
                                   rte_xstats_len);
    } else {
        VLOG_WARN("Cannot get XSTATS values for port: %d",
                  dev->port_id);
    }

out:
    free(rte_xstats);
    free(rte_xstats_names);

    stats->rx_packets = rte_stats.ipackets;
    stats->tx_packets = rte_stats.opackets;
    stats->rx_bytes = rte_stats.ibytes;
    stats->tx_bytes = rte_stats.obytes;
    stats->rx_errors = rte_stats.ierrors;
    stats->tx_errors = rte_stats.oerrors;

    rte_spinlock_lock(&dev->stats_lock);
    stats->tx_dropped = dev->stats.tx_dropped;
    stats->rx_dropped = dev->stats.rx_dropped;
    rte_spinlock_unlock(&dev->stats_lock);

    /* These are the available DPDK counters for packets not received due to
     * local resource constraints in DPDK and NIC respectively. */
    stats->rx_dropped += rte_stats.rx_nombuf + rte_stats.imissed;
    stats->rx_missed_errors = rte_stats.imissed;

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_doca_get_sw_custom_stats(const struct netdev *netdev,
                                struct netdev_custom_stats *custom_stats)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    int i, n;

#define SW_CSTATS                    \
    SW_CSTAT(tx_retries)             \
    SW_CSTAT(tx_failure_drops)       \
    SW_CSTAT(tx_mtu_exceeded_drops)  \
    SW_CSTAT(tx_invalid_hwol_drops)

#define SW_CSTAT(NAME) + 1
    custom_stats->size = SW_CSTATS;
#undef SW_CSTAT
    custom_stats->counters = xcalloc(custom_stats->size,
                                     sizeof *custom_stats->counters);

    ovs_mutex_lock(&dev->mutex);

    rte_spinlock_lock(&dev->stats_lock);
    i = 0;
#define SW_CSTAT(NAME) \
    custom_stats->counters[i++].value = dev->sw_stats->NAME;
    SW_CSTATS;
#undef SW_CSTAT
    rte_spinlock_unlock(&dev->stats_lock);

    ovs_mutex_unlock(&dev->mutex);

    i = 0;
    n = 0;
#define SW_CSTAT(NAME) \
    if (custom_stats->counters[i].value != UINT64_MAX) {                   \
        ovs_strlcpy(custom_stats->counters[n].name,                        \
                    "ovs_"#NAME, NETDEV_CUSTOM_STATS_NAME_SIZE);           \
        custom_stats->counters[n].value = custom_stats->counters[i].value; \
        n++;                                                               \
    }                                                                      \
    i++;
    SW_CSTATS;
#undef SW_CSTAT

    custom_stats->size = n;
    return 0;
}

static int
netdev_doca_get_custom_stats(const struct netdev *netdev,
                             struct netdev_custom_stats *custom_stats)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw_ctx = dev->esw_ctx;
    struct doca_flow_resource_query stats;
    struct netdev_custom_counter *counter;
    uint64_t n_sw_packets, n_sw_bytes;
    uint16_t port_id = dev->port_id;
    uint64_t n_packets, n_bytes;
    int n_txq = netdev->n_txq;
    unsigned int n_rxq;
    int sw_stats_size;
    enum {
        PACKETS,
        BYTES,
    };
    int err;
    int i;

    if (!dev_get_started(dev)) {
        return -1;
    }

    netdev_doca_get_sw_custom_stats(netdev, custom_stats);

    sw_stats_size = custom_stats->size;
    n_rxq = dev->esw_ctx->n_rxq;
    custom_stats->size += 2 * (NETDEV_DOCA_RSS_NUM_ENTRIES + n_rxq + n_txq +
                               1);

    custom_stats->counters = xrealloc(custom_stats->counters,
                                      custom_stats->size *
                                      sizeof *custom_stats->counters);
    counter = &custom_stats->counters[sw_stats_size];

    for (i = 0; i < NETDEV_DOCA_RSS_NUM_ENTRIES; i++, counter += 2) {
        const char *stats_name = netdev_doca_stats_name(i);

        err = doca_flow_resource_query_entry(dev->rss_entries[i], &stats);
        if (err) {
            VLOG_ERR("%s: Failed to query '%s' RSS entry. Error %d (%s)",
                     dev->devargs, stats_name, err,
                     doca_error_get_descr(err));
            return -1;
        }

        counter[PACKETS].value = stats.counter.total_pkts;
        snprintf(counter[PACKETS].name, NETDEV_CUSTOM_STATS_NAME_SIZE,
                 "%s_packets", stats_name);
        counter[BYTES].value = stats.counter.total_bytes;
        snprintf(counter[BYTES].name, NETDEV_CUSTOM_STATS_NAME_SIZE,
                 "%s_bytes", stats_name);
    }

    n_sw_packets = 0;
    n_sw_bytes = 0;

    for (i = 0; i < n_rxq; i++, counter += 2) {
        atomic_read_relaxed(&esw_ctx->port_queues[port_id][i].n_packets,
                            &n_packets);
        atomic_read_relaxed(&esw_ctx->port_queues[port_id][i].n_bytes,
                            &n_bytes);

        n_sw_packets += n_packets;
        n_sw_bytes += n_bytes;

        counter[PACKETS].value = n_packets;
        snprintf(counter[PACKETS].name, NETDEV_CUSTOM_STATS_NAME_SIZE,
                 "rx_q%d_packets", i);
        counter[BYTES].value = n_bytes;
        snprintf(counter[BYTES].name, NETDEV_CUSTOM_STATS_NAME_SIZE,
                 "rx_q%d_bytes", i);
    }

    counter[PACKETS].value = n_sw_packets;
    snprintf(counter[PACKETS].name, NETDEV_CUSTOM_STATS_NAME_SIZE,
             "sw_rx_packets");
    counter[BYTES].value = n_sw_bytes;
    snprintf(counter[BYTES].name, NETDEV_CUSTOM_STATS_NAME_SIZE,
             "sw_rx_bytes");
    counter += 2;

    for (i = 0; i < n_txq; i++, counter += 2) {
        atomic_read_relaxed(&dev->sw_tx_stats[i].n_packets, &n_packets);
        atomic_read_relaxed(&dev->sw_tx_stats[i].n_bytes, &n_bytes);

        counter[PACKETS].value = n_packets;
        snprintf(counter[PACKETS].name, NETDEV_CUSTOM_STATS_NAME_SIZE,
                 "tx_q%d_packets", i);
        counter[BYTES].value = n_bytes;
        snprintf(counter[BYTES].name, NETDEV_CUSTOM_STATS_NAME_SIZE,
                 "tx_q%d_bytes", i);
        counter->value = n_packets;
    }

    return 0;
}

static int
netdev_doca_get_features(const struct netdev *netdev,
                         enum netdev_features *current,
                         enum netdev_features *advertised,
                         enum netdev_features *supported,
                         enum netdev_features *peer)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct rte_eth_link link;
    uint32_t feature = 0;

    ovs_mutex_lock(&dev->mutex);
    link = dev->link;
    ovs_mutex_unlock(&dev->mutex);

    /* Match against OpenFlow defined link speed values. */
    if (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) {
        switch (link.link_speed) {
        case RTE_ETH_SPEED_NUM_10M:
            feature |= NETDEV_F_10MB_FD;
            break;
        case RTE_ETH_SPEED_NUM_100M:
            feature |= NETDEV_F_100MB_FD;
            break;
        case RTE_ETH_SPEED_NUM_1G:
            feature |= NETDEV_F_1GB_FD;
            break;
        case RTE_ETH_SPEED_NUM_10G:
            feature |= NETDEV_F_10GB_FD;
            break;
        case RTE_ETH_SPEED_NUM_40G:
            feature |= NETDEV_F_40GB_FD;
            break;
        case RTE_ETH_SPEED_NUM_100G:
            feature |= NETDEV_F_100GB_FD;
            break;
        default:
            feature |= NETDEV_F_OTHER;
        }
    } else if (link.link_duplex == RTE_ETH_LINK_HALF_DUPLEX) {
        switch (link.link_speed) {
        case RTE_ETH_SPEED_NUM_10M:
            feature |= NETDEV_F_10MB_HD;
            break;
        case RTE_ETH_SPEED_NUM_100M:
            feature |= NETDEV_F_100MB_HD;
            break;
        case RTE_ETH_SPEED_NUM_1G:
            feature |= NETDEV_F_1GB_HD;
            break;
        default:
            feature |= NETDEV_F_OTHER;
        }
    }

    if (link.link_autoneg) {
        feature |= NETDEV_F_AUTONEG;
    }

    *current = feature;
    *advertised = *supported = *peer = 0;

    return 0;
}

static int
netdev_doca_get_speed(const struct netdev *netdev, uint32_t *current,
                      uint32_t *max)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct rte_eth_dev_info dev_info;
    struct rte_eth_link link;
    int diag;

    ovs_mutex_lock(&dev->mutex);
    link = dev->link;
    if (dev_get_started(dev)) {
        diag = rte_eth_dev_info_get(dev->port_id, &dev_info);
    } else {
        memset(&dev_info, 0, sizeof dev_info);
        diag = -1;
    }
    ovs_mutex_unlock(&dev->mutex);

    *current = link.link_speed != RTE_ETH_SPEED_NUM_UNKNOWN
               ? link.link_speed : 0;

    if (diag < 0) {
        *max = 0;
        goto out;
    }

    if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_200G) {
        *max = RTE_ETH_SPEED_NUM_200G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_100G) {
        *max = RTE_ETH_SPEED_NUM_100G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_56G) {
        *max = RTE_ETH_SPEED_NUM_56G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_50G) {
        *max = RTE_ETH_SPEED_NUM_50G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_40G) {
        *max = RTE_ETH_SPEED_NUM_40G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_25G) {
        *max = RTE_ETH_SPEED_NUM_25G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_20G) {
        *max = RTE_ETH_SPEED_NUM_20G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_10G) {
        *max = RTE_ETH_SPEED_NUM_10G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_5G) {
        *max = RTE_ETH_SPEED_NUM_5G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_2_5G) {
        *max = RTE_ETH_SPEED_NUM_2_5G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_1G) {
        *max = RTE_ETH_SPEED_NUM_1G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_100M ||
        dev_info.speed_capa & RTE_ETH_LINK_SPEED_100M_HD) {
        *max = RTE_ETH_SPEED_NUM_100M;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_10M ||
        dev_info.speed_capa & RTE_ETH_LINK_SPEED_10M_HD) {
        *max = RTE_ETH_SPEED_NUM_10M;
    } else {
        *max = 0;
    }

out:
    return 0;
}

/*
 * Convert a given uint32_t link speed defined in DPDK to a string
 * equivalent.
 */
static const char *
netdev_doca_link_speed_to_str__(uint32_t link_speed)
{
    switch (link_speed) {
    case RTE_ETH_SPEED_NUM_10M:    return "10Mbps";
    case RTE_ETH_SPEED_NUM_100M:   return "100Mbps";
    case RTE_ETH_SPEED_NUM_1G:     return "1Gbps";
    case RTE_ETH_SPEED_NUM_2_5G:   return "2.5Gbps";
    case RTE_ETH_SPEED_NUM_5G:     return "5Gbps";
    case RTE_ETH_SPEED_NUM_10G:    return "10Gbps";
    case RTE_ETH_SPEED_NUM_20G:    return "20Gbps";
    case RTE_ETH_SPEED_NUM_25G:    return "25Gbps";
    case RTE_ETH_SPEED_NUM_40G:    return "40Gbps";
    case RTE_ETH_SPEED_NUM_50G:    return "50Gbps";
    case RTE_ETH_SPEED_NUM_56G:    return "56Gbps";
    case RTE_ETH_SPEED_NUM_100G:   return "100Gbps";
    default:                       return "Not Defined";
    }
}

static int
netdev_doca_get_status(const struct netdev *netdev, struct smap *args)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct rte_eth_dev_info dev_info;
    uint32_t link_speed;
    int diag;

    if (!rte_eth_dev_is_valid_port(dev->port_id)) {
        return ENODEV;
    }

    ovs_mutex_lock(&doca_mutex);
    ovs_mutex_lock(&dev->mutex);
    diag = rte_eth_dev_info_get(dev->port_id, &dev_info);
    link_speed = dev->link.link_speed;
    ovs_mutex_unlock(&dev->mutex);
    ovs_mutex_unlock(&doca_mutex);

    smap_add_format(args, "port_no", "%d", dev->port_id);
    smap_add_format(args, "numa_id", "%d",
                           rte_eth_dev_socket_id(dev->port_id));
    if (!diag) {
        smap_add_format(args, "driver_name", "%s", dev_info.driver_name);
        smap_add_format(args, "driver_version", "%s", rte_version());
        smap_add_format(args, "min_rx_bufsize", "%u", dev_info.min_rx_bufsize);
    }
    smap_add_format(args, "max_rx_pktlen", "%u", dev->max_packet_len);
    if (!diag) {
        smap_add_format(args, "max_rx_queues", "%u", dev_info.max_rx_queues);
        smap_add_format(args, "max_tx_queues", "%u", dev_info.max_tx_queues);
        smap_add_format(args, "max_mac_addrs", "%u", dev_info.max_mac_addrs);
        smap_add_format(args, "max_hash_mac_addrs", "%u",
                        dev_info.max_hash_mac_addrs);
        smap_add_format(args, "max_vfs", "%u", dev_info.max_vfs);
        smap_add_format(args, "max_vmdq_pools", "%u", dev_info.max_vmdq_pools);
    }

    smap_add_format(args, "n_rxq", "%d", netdev->n_rxq);
    smap_add_format(args, "n_txq", "%d", netdev->n_txq);

    smap_add(args, "rx_csum_offload",
             dev->hw_ol_features & NETDEV_RX_CHECKSUM_OFFLOAD
             ? "true" : "false");

    /* Querying the DPDK library for if-type may be done in future, pending
     * support; cf. RFC 3635 Section 3.2.4. */
    enum { IF_TYPE_ETHERNETCSMACD = 6 };

    smap_add_format(args, "if_type", "%"PRIu32, IF_TYPE_ETHERNETCSMACD);
    smap_add_format(args, "if_descr", "%s %s", rte_version(),
                    diag < 0 ? "<unknown>" : dev_info.driver_name);
    if (!diag) {
        const char *bus_info = rte_dev_bus_info(dev_info.device);
        smap_add_format(args, "bus_info", "bus_name=%s%s%s",
                        rte_bus_name(rte_dev_bus(dev_info.device)),
                        bus_info != NULL ? ", " : "",
                        bus_info != NULL ? bus_info : "");
    }

    /* Not all link speeds are defined in the OpenFlow specs e.g. 25 Gbps.
     * In that case the speed will not be reported as part of the usual
     * call to get_features(). Get the link speed of the device and add it
     * to the device status in an easy to read string format.
     */
    smap_add(args, "link_speed",
             netdev_doca_link_speed_to_str__(link_speed));

    if (dev_is_representor(dev)) {
        smap_add_format(args, "dpdk-vf-mac", ETH_ADDR_FMT,
                        ETH_ADDR_ARGS(dev->hwaddr));
    }

    return 0;
}

static uint32_t
dpdk_buf_size(int mtu)
{
    return ROUND_UP(MTU_TO_MAX_FRAME_LEN(mtu), NETDEV_DOCA_MBUF_ALIGN)
            + RTE_PKTMBUF_HEADROOM;
}

static int
dpdk_mp_full(const struct rte_mempool *mp)
    OVS_REQUIRES(dpdk_mp_mutex)
{
    /* At this point we want to know if all the mbufs are back
     * in the mempool. rte_mempool_full() is not atomic but it's
     * the best available and as we are no longer requesting mbufs
     * from the mempool, it means mbufs will not move from
     * 'mempool ring' --> 'mempool cache'. In rte_mempool_full()
     * the ring is counted before caches, so we won't get false
     * positives in this use case and we handle false negatives.
     *
     * If future implementations of rte_mempool_full() were to change
     * it could be possible for a false positive. Even that would
     * likely be ok, as there are additional checks during mempool
     * freeing but it would make things racey.
     */
    return rte_mempool_full(mp);
}

/* Free unused mempools. */
static void
dpdk_mp_sweep(void)
    OVS_REQUIRES(dpdk_mp_mutex)
{
    struct dpdk_mp *dmp;

    LIST_FOR_EACH_SAFE (dmp, list_node, &dpdk_mp_list) {
        if (!dmp->refcount && dpdk_mp_full(dmp->mp)) {
            VLOG_DBG("Freeing mempool \"%s\"", dmp->mp->name);
            ovs_list_remove(&dmp->list_node);
            rte_mempool_free(dmp->mp);
            rte_free(dmp);
        }
    }
}

static uint32_t
doca_calculate_mbufs(struct netdev_doca *dev)
{
     /* In DOCA mode, Shared RQ is used which mean RX queue is
     * only allocated on the eswitch manager. This mean we can determine
     * the max number of RX queue is the system.
     * Rough estimation of number of mbufs required for the ESW manager
     * and all its ports:
     * (<packets required to fill the device rxqs>
     * + <packets that could be stuck on other ports txqs>
     * + <packets in the pmd threads>
     * + <additional memory for corner cases>)
     */
    uint32_t n_mbufs;

    n_mbufs = dev->requested_n_rxq * dev->requested_rxq_size
              + dev->requested_n_txq * dev->requested_txq_size
              + MIN(RTE_MAX_LCORE, dev->requested_n_rxq) * NETDEV_MAX_BURST
              + MIN_NB_MBUF;
    return n_mbufs;
}

/* This should match the implementation in netdev-dpdk.c
 * as dp-packet.c calls free_dpdk_buf(). */
static void
ovs_rte_pktmbuf_init(struct rte_mempool *mp OVS_UNUSED,
                     void *opaque_arg OVS_UNUSED,
                     void *_p,
                     unsigned i OVS_UNUSED)
{
    struct rte_mbuf *pkt = _p;

    dp_packet_init_dpdk((struct dp_packet *) pkt);
}

static struct dpdk_mp *
dpdk_mp_create(struct netdev_doca *dev, int mtu)
{
    const char *netdev_name = netdev_get_name(&dev->up);
    uint32_t hash = hash_string(netdev_name, 0);
    int socket_id = dev->requested_socket_id;
    char mp_name[RTE_MEMPOOL_NAMESIZE];
    uint32_t mbuf_priv_data_len = 0;
    uint32_t aligned_mbuf_size = 0;
    struct dpdk_mp *dmp = NULL;
    uint32_t mbuf_size = 0;
    uint32_t pkt_size = 0;
    uint32_t n_mbufs = 0;
    int ret;

    dmp = doca_rte_mzalloc("ovs_doca_mp", sizeof *dmp);
    if (!dmp) {
        return NULL;
    }
    dmp->socket_id = socket_id;
    dmp->esw_mgr_port_id = dev->esw_mgr_port_id;
    dmp->refcount = 1;

    /* Get the size of each mbuf, based on the MTU */
    mbuf_size = MTU_TO_FRAME_LEN(mtu);

    n_mbufs = doca_calculate_mbufs(dev);

    do {
        /* Full DPDK memory pool name must be unique and cannot be
         * longer than RTE_MEMPOOL_NAMESIZE. Note that for the shared
         * mempool case this can result in one device using a mempool
         * which references a different device in it's name. However as
         * mempool names are hashed, the device name will not be readable
         * so this is not an issue for tasks such as debugging.
         */
        ret = snprintf(mp_name, RTE_MEMPOOL_NAMESIZE,
                       "ovs%08x%02d%05d%07u",
                        hash, socket_id, mtu, n_mbufs);
        if (ret < 0 || ret >= RTE_MEMPOOL_NAMESIZE) {
            VLOG_DBG("snprintf returned %d. "
                     "Failed to generate a mempool name for \"%s\". "
                     "Hash:0x%x, socket_id: %d, mtu:%d, mbufs:%u.",
                     ret, netdev_name, hash, socket_id, mtu, n_mbufs);
            break;
        }

        VLOG_DBG("Port %s: Requesting a mempool of %u mbufs of size %u "
                  "on socket %d for ESW %u with %d Rx and %d Tx queues, "
                  "cache line size of %u",
                  netdev_name, n_mbufs, mbuf_size, socket_id,
                  dev->esw_mgr_port_id,
                  dev->requested_n_rxq, dev->requested_n_txq,
                  RTE_CACHE_LINE_SIZE);

        /* The size of the mbuf's private area (i.e. area that holds OvS'
         * dp_packet data)*/
        mbuf_priv_data_len = sizeof(struct dp_packet) -
                                 sizeof(struct rte_mbuf);
        /* The size of the entire dp_packet. */
        pkt_size = sizeof(struct dp_packet) + mbuf_size;
        /* mbuf size, rounded up to cacheline size. */
        aligned_mbuf_size = ROUND_UP(pkt_size, RTE_CACHE_LINE_SIZE);
        /* If there is a size discrepancy, add padding to mbuf_priv_data_len.
         * This maintains mbuf size cache alignment, while also honoring RX
         * buffer alignment in the data portion of the mbuf. If this adjustment
         * is not made, there is a possiblity later on that for an element of
         * the mempool, buf, buf->data_len < (buf->buf_len - buf->data_off).
         * This is problematic in the case of multi-segment mbufs, particularly
         * when an mbuf segment needs to be resized (when [push|popp]ing a VLAN
         * header, for example.
         */
        mbuf_priv_data_len += (aligned_mbuf_size - pkt_size);

        dmp->mp = rte_pktmbuf_pool_create(mp_name, n_mbufs, MP_CACHE_SZ,
                                          mbuf_priv_data_len,
                                          mbuf_size,
                                          socket_id);

        if (dmp->mp) {
            VLOG_DBG("Allocated \"%s\" mempool with %u mbufs",
                     mp_name, n_mbufs);
            /* rte_pktmbuf_pool_create has done some initialization of the
             * rte_mbuf part of each dp_packet, while ovs_rte_pktmbuf_init
             * initializes some OVS specific fields of dp_packet.
             */
            rte_mempool_obj_iter(dmp->mp, ovs_rte_pktmbuf_init, NULL);
            return dmp;
        } else if (rte_errno == EEXIST) {
            /* A mempool with the same name already exists.  We just
             * retrieve its pointer to be returned to the caller. */
            dmp->mp = rte_mempool_lookup(mp_name);
            /* As the mempool create returned EEXIST we can expect the
             * lookup has returned a valid pointer.  If for some reason
             * that's not the case we keep track of it. */
            VLOG_DBG("A mempool with name \"%s\" already exists at %p.",
                     mp_name, dmp->mp);
            return dmp;
        } else {
            VLOG_DBG("Failed to create mempool \"%s\" with a request of "
                     "%u mbufs, retrying with %u mbufs",
                     mp_name, n_mbufs, n_mbufs / 2);
        }
    } while (!dmp->mp && rte_errno == ENOMEM && (n_mbufs /= 2) >= MIN_NB_MBUF);

    VLOG_ERR("Failed to create mempool \"%s\" with a request of %u mbufs",
             mp_name, n_mbufs);

    rte_free(dmp);
    return NULL;
}

static struct dpdk_mp *
dpdk_mp_get(struct netdev_doca *dev, int mtu)
{
    struct dpdk_mp *dmp = NULL;
    bool reuse = false;

    ovs_mutex_lock(&dpdk_mp_mutex);
    /* Check if shared memory is being used, if so check existing mempools
     * to see if reuse is possible. */
    LIST_FOR_EACH (dmp, list_node, &dpdk_mp_list) {
        if (dmp->socket_id == dev->requested_socket_id
            && dmp->esw_mgr_port_id == dev->esw_mgr_port_id) {
            VLOG_DBG("Reusing mempool \"%s\"", dmp->mp->name);
            dmp->refcount++;
            reuse = true;
            break;
        }
    }
    /* Sweep mempools after reuse or before create. */
    dpdk_mp_sweep();

    if (!reuse) {
        dmp = dpdk_mp_create(dev, mtu);
        if (dmp) {
            /* Shared memory will hit the reuse case above so will not
             * request a mempool that already exists but we need to check
             * for the EEXIST case for per port memory case. Compare the
             * mempool returned by dmp to each entry in dpdk_mp_list. If a
             * match is found, free dmp as a new entry is not required, set
             * dmp to point to the existing entry and increment the refcount
             * to avoid being freed at a later stage.
             */
            ovs_list_push_back(&dpdk_mp_list, &dmp->list_node);
        }
    }

    ovs_mutex_unlock(&dpdk_mp_mutex);

    return dmp;
}

/* Decrement reference to a mempool. */
static int
netdev_doca_mempool_configure(struct netdev_doca *dev)
    OVS_REQUIRES(dev->mutex)
{
    uint32_t buf_size = dpdk_buf_size(dev->requested_mtu);
    struct dpdk_mp *dmp;
    int ret = 0;

    dmp = dpdk_mp_get(dev, FRAME_LEN_TO_MTU(buf_size));
    if (!dmp) {
        VLOG_ERR("Failed to create memory pool for netdev "
                 "%s, with MTU %d on socket %d: %s\n",
                 dev->up.name, dev->requested_mtu, dev->requested_socket_id,
                 rte_strerror(rte_errno));
        ret = rte_errno;
    } else {
        /* Check for any pre-existing dpdk_mp for the device before accessing
         * the associated mempool.
         */
        if (dev->dpdk_mp != NULL) {
            /* A new MTU was requested, decrement the reference count for the
             * devices current dpdk_mp. This is required even if a pointer to
             * same dpdk_mp is returned by dpdk_mp_get. The refcount for dmp
             * has already been incremented by dpdk_mp_get at this stage so it
             * must be decremented to keep an accurate refcount for the
             * dpdk_mp.
             */
            dpdk_mp_put(dev->dpdk_mp);
        }
        dev->dpdk_mp = dmp;
        dev->mtu = dev->requested_mtu;
        dev->socket_id = dev->requested_socket_id;
        dev->max_packet_len = MTU_TO_FRAME_LEN(dev->mtu);
    }

    return ret;
}

static int
dpdk_eth_dev_port_config_complete(struct netdev_doca *dev,
                                  int n_rxq, int n_txq)
{
    uint16_t conf_mtu;
    int diag;

    free(dev->sw_tx_stats);
    dev->sw_tx_stats = xcalloc(n_txq, sizeof *dev->sw_tx_stats);
    for (int i = 0; i < n_txq; i++) {
        atomic_init(&dev->sw_tx_stats[i].n_packets, 0);
        atomic_init(&dev->sw_tx_stats[i].n_bytes, 0);
    }

    dev->up.n_rxq = n_rxq;
    dev->up.n_txq = n_txq;

    diag = rte_eth_dev_set_mtu(dev->port_id, dev->mtu);

    if (diag) {
        /* A device may not support rte_eth_dev_set_mtu, in this case
         * flag a warning to the user and include the devices configured
         * MTU value that will be used instead. */
        if (-ENOTSUP == diag) {
            rte_eth_dev_get_mtu(dev->port_id, &conf_mtu);
            VLOG_WARN("Interface %s does not support MTU configuration, "
                      "max packet size supported is %"PRIu16".",
                      dev->up.name, conf_mtu);
        } else {
            VLOG_ERR("Interface %s MTU (%d) setup error: %s",
                     dev->up.name, dev->mtu, rte_strerror(-diag));
        }
    }

    return diag;
}

static int
dpdk_eth_dev_port_config(struct netdev_doca *dev,
                         const struct rte_eth_dev_info *info,
                         int n_rxq, int n_txq)
{
    struct rte_eth_conf conf = {
        .rxmode = {
            .offloads = 0,
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = NULL,
                .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP,
            },
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
    };
    int diag = 0;
    int i;

    /* As of DPDK 17.11.1 a few PMDs require to explicitly enable
     * scatter to support jumbo RX.
     * Setting scatter for the device is done after checking for
     * scatter support in the device capabilites. */
    if (dev->mtu > RTE_ETHER_MTU) {
        if (dev->hw_ol_features & NETDEV_RX_HW_SCATTER) {
            conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_SCATTER;
        }
    }

    conf.intr_conf.lsc = dev->lsc_interrupt_mode;

    if (dev->hw_ol_features & NETDEV_RX_CHECKSUM_OFFLOAD) {
        conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_CHECKSUM;
    }

    if (!(dev->hw_ol_features & NETDEV_RX_HW_CRC_STRIP)
        && info->rx_offload_capa & RTE_ETH_RX_OFFLOAD_KEEP_CRC) {
        conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_KEEP_CRC;
    }

    if (dev->hw_ol_features & NETDEV_TX_IPV4_CKSUM_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    }

    if (dev->hw_ol_features & NETDEV_TX_TCP_CKSUM_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
    }

    if (dev->hw_ol_features & NETDEV_TX_UDP_CKSUM_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
    }

    if (dev->hw_ol_features & NETDEV_TX_SCTP_CKSUM_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_SCTP_CKSUM;
    }

    if (dev->hw_ol_features & NETDEV_TX_TSO_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_TSO;
    }

    if (dev->hw_ol_features & NETDEV_TX_VXLAN_TNL_TSO_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO;
    }

    if (dev->hw_ol_features & NETDEV_TX_GENEVE_TNL_TSO_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO;
    }

    if (dev->hw_ol_features & NETDEV_TX_GRE_TNL_TSO_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO;
    }

    if (dev->hw_ol_features & NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM;
    }

    if (dev->hw_ol_features & NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD) {
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM;
    }

    /* Limit configured rss hash functions to only those supported
     * by the eth device. */
    conf.rx_adv_conf.rss_conf.rss_hf &= info->flow_type_rss_offloads;
    if (conf.rx_adv_conf.rss_conf.rss_hf == 0) {
        conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    } else {
        conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    }

    if (!netdev_doca_is_esw_mgr(&dev->up)) {
        rte_eth_dev_configure(dev->port_id, 0, 0, &conf);
        return dpdk_eth_dev_port_config_complete(dev, n_rxq, n_txq);
    }

    /* A device may report more queues than it makes available (this has
     * been observed for Intel xl710, which reserves some of them for
     * SRIOV):  rte_eth_*_queue_setup will fail if a queue is not
     * available.  When this happens we can retry the configuration
     * and request less queues */
    while (n_rxq && n_txq) {
        if (diag) {
            VLOG_INFO("Retrying setup with (rxq:%d txq:%d)", n_rxq, n_txq);
        }

        diag = rte_eth_dev_configure(dev->port_id, n_rxq,
                                     n_txq, &conf);
        if (diag) {
            VLOG_WARN("Interface %s eth_dev setup error %s\n",
                      dev->up.name, rte_strerror(-diag));
            break;
        }

        for (i = 0; i < n_txq; i++) {
            diag = rte_eth_tx_queue_setup(dev->port_id, i, dev->txq_size,
                                          dev->socket_id, NULL);
            if (diag) {
                VLOG_INFO("Interface %s unable to setup txq(%d): %s",
                          dev->up.name, i, rte_strerror(-diag));
                break;
            }
        }

        if (i != n_txq) {
            /* Retry with less tx queues */
            n_txq = i;
            continue;
        }

        for (i = 0; i < n_rxq; i++) {
            diag = rte_eth_rx_queue_setup(dev->port_id, i, dev->rxq_size,
                                          dev->socket_id, NULL,
                                          dev->dpdk_mp->mp);
            if (diag) {
                VLOG_INFO("Interface %s unable to setup rxq(%d): %s",
                          dev->up.name, i, rte_strerror(-diag));
                break;
            }
        }

        if (i != n_rxq) {
            /* Retry with less rx queues */
            n_rxq = i;
            continue;
        }

        return dpdk_eth_dev_port_config_complete(dev, n_rxq, n_txq);
    }

    return diag;
}

static int
netdev_doca_esw_key_parse(const char *devargs,
                          struct netdev_doca_esw_key *esw_key)
{
    struct rte_pci_addr *rte_pci = &esw_key->rte_pci;

    memset(esw_key, 0, sizeof *esw_key);
    return netdev_doca_parse_dpdk_devargs_pci(devargs, rte_pci);
}

static int
netdev_doca_dev_probe(struct netdev_doca *dev, const char *devargs)
{
    struct ds rte_devargs = DS_EMPTY_INITIALIZER;
    struct netdev_doca_esw_ctx_arg ctx_arg;
    struct netdev_doca_esw_key esw_key;
    struct ibv_pd *pd;
    int rv = 0;

    if (dev->esw_ctx) {
        /* Already probed. do nothing. */
        return 0;
    }

    if (netdev_doca_esw_key_parse(devargs, &esw_key)) {
        return EINVAL;
    }

    ctx_arg = (struct netdev_doca_esw_ctx_arg) {
        .esw_key = &esw_key,
        .dev = dev,
    };

    dev->esw_ctx = refmap_ref(netdev_doca_esw_rfm, &esw_key, &ctx_arg);
    if (!dev->esw_ctx) {
        VLOG_ERR("Could not get esw context for %s", devargs);
        return EINVAL;
    } else if (dev->attached) {
        /* When a representor is probed before its ESW, dpdk implicitly
         * probes the latter, thus probe is not called from
         * netdev_dpdk_process_devargs(). In this case we call probe at
         * netdev_doca_port_start(), to take the reference and initialize
         * esw_ctx handle in dev.
         */
        goto out;
    }

    if (doca_rdma_bridge_get_dev_pd(dev->esw_ctx->dev, &pd)) {
        VLOG_ERR("Could not get pd for %s", devargs);
        rv = EINVAL;
        goto out;
    }
    if (dev->esw_ctx->cmd_fd == -1) {
        dev->esw_ctx->cmd_fd = dup(pd->context->cmd_fd);
        if (dev->esw_ctx->cmd_fd == -1) {
            VLOG_ERR("Could not dup fd for %s. Error %s", devargs,
                     ovs_strerror(errno));
            rv = EBADF;
            goto out;
        }
    }

    ds_put_format(&rte_devargs, "%s,cmd_fd=%d,pd_handle=%u", devargs,
                  dev->esw_ctx->cmd_fd, pd->handle);

    VLOG_INFO("Probing '%s'", ds_cstr(&rte_devargs));
    if (rte_dev_probe(ds_cstr(&rte_devargs))) {
        rv = ENODEV;
        goto out;
    }

out:
    ds_destroy(&rte_devargs);
    if (rv) {
        netdev_doca_dev_close(dev);
    }
    return rv;
}

static int
netdev_doca_port_start(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct doca_flow_port_cfg *port_cfg;
    const char *devargs = dev->devargs;
    uint16_t port_id = dev->port_id;
    struct netdev_doca_esw_ctx *esw;
    int err;

    if (!rte_eth_dev_is_valid_port(dev->esw_mgr_port_id)) {
        VLOG_ERR("Cannot start port %d '%s', invalid proxy port", port_id,
                 devargs);
        return -1;
    }

    err = doca_flow_port_cfg_create(&port_cfg);
    if (err) {
        VLOG_ERR("Failed to create doca flow port_cfg. Error: %d (%s)",
                 err, doca_error_get_descr(err));
        return -1;
    }

    if (netdev_doca_dev_probe(dev, devargs)) {
        err = -1;
        goto out;
    }
    esw = dev->esw_ctx;
    if (!esw) {
        err = -1;
        goto out;
    }

    err = doca_flow_port_cfg_set_port_id(port_cfg, port_id);
    if (err) {
        VLOG_ERR("%s: Failed to set doca flow port_cfg port_id %d. "
                 "Error: %d (%s)", netdev_get_name(netdev), port_id, err,
                 doca_error_get_descr(err));
        goto out;
    }

    if (!netdev_doca_is_esw_mgr(netdev)) {
        VLOG_INFO("%s: Opening doca dev_rep for port_id %d",
                  netdev_get_name(netdev), port_id);
        err = doca_dpdk_open_dev_rep_by_port_id(port_id, esw->dev,
                                                &dev->dev_rep);
        if (err) {
            VLOG_ERR("%s: Failed to open doca dev_rep for port_id %d. "
                     "Error: %d (%s)", netdev_get_name(netdev), port_id, err,
                     doca_error_get_descr(err));
            goto out;
        }

        err = doca_flow_port_cfg_set_dev_rep(port_cfg, dev->dev_rep);
        if (err) {
            VLOG_ERR("%s: Failed to set doca flow port_cfg dev_rep. "
                     "Error: %d (%s)", netdev_get_name(netdev), err,
                     doca_error_get_descr(err));
            goto out;
        }
    }

    err = doca_flow_port_cfg_set_dev(port_cfg, esw->dev);
    if (err) {
        VLOG_ERR("%s: Failed to set doca flow port_cfg dev. Error: %d (%s)",
                 netdev_get_name(netdev), err, doca_error_get_descr(err));
        goto out;
    }

    VLOG_INFO("%s: Starting '%s', port_id=%d", netdev_get_name(netdev),
              devargs, port_id);
    if (dev->port_id == dev->esw_mgr_port_id) {
        err = doca_flow_port_cfg_set_actions_mem_size(
                port_cfg, NETDEV_DOCA_ACTIONS_MEM_SIZE);
        if (err) {
            VLOG_ERR("Failed set_actions_mem_size for port_id %"PRIu16
                     ". Error: %d (%s)", dev->port_id, err,
                     doca_error_get_descr(err));
            goto out;
        }
        err = rte_eth_dev_start(dev->port_id);
        if (err) {
            VLOG_ERR("Failed to start dpdk port_id %"PRIu16". Error: %d (%s)",
                     dev->port_id, err, rte_strerror(-err));
            goto out;
        }

        err = doca_flow_port_cfg_set_nr_resources(port_cfg,
                                                  DOCA_FLOW_RESOURCE_COUNTER,
                                                  ovs_doca_max_counters());
        if (err) {
            VLOG_ERR("Failed set_nr_resources counters for port_id %"PRIu16
                     ". Error: %d (%s)", dev->port_id, err,
                     doca_error_get_descr(err));
            goto out;
        }
    }
    err = doca_flow_port_start(port_cfg, &dev->port);
    if (err) {
        VLOG_ERR("Failed to start doca flow port_id %"PRIu16". Error: %d (%s)",
                 port_id, err, doca_error_get_descr(err));
        goto out;
    }

    if (dev->port_id == dev->esw_mgr_port_id &&
        netdev_doca_esw_init(netdev)) {
        err = -1;
        goto out;
    }
    err = netdev_doca_egress_entry_init(dev);
    if (err) {
        goto out;
    }
    err = netdev_doca_rss_entries_init(netdev);
    if (err) {
        goto out;
    }

out:
    doca_flow_port_cfg_destroy(port_cfg);
    if (err) {
        netdev_doca_port_stop(netdev);
    }
    return err;
}

static const char *
netdev_doca_get_xstat_name(struct netdev_doca *dev, uint64_t id)
    OVS_REQUIRES(dev->mutex)
{
    if (id >= dev->rte_xstats_names_size) {
        return "UNKNOWN";
    }
    return dev->rte_xstats_names[id].name;
}

static bool
is_queue_stat(const char *s)
{
    uint16_t tmp;

    return (s[0] == 'r' || s[0] == 't') &&
            (ovs_scan(s + 1, "x_q%"SCNu16"_packets", &tmp) ||
             ovs_scan(s + 1, "x_q%"SCNu16"_bytes", &tmp));
}

static void
netdev_doca_configure_xstats(struct netdev_doca *dev)
    OVS_REQUIRES(dev->mutex)
{
    struct rte_eth_xstat_name *rte_xstats_names = NULL;
    struct rte_eth_xstat *rte_xstats = NULL;
    int rte_xstats_names_size;
    int rte_xstats_len;
    const char *name;
    uint64_t id;

    netdev_doca_clear_xstats(dev);

    rte_xstats_names_size = rte_eth_xstats_get_names(dev->port_id, NULL, 0);
    if (rte_xstats_names_size < 0) {
        VLOG_WARN("Cannot get XSTATS names for port: %d",
                  dev->port_id);
        goto out;
    }

    rte_xstats_names = xcalloc(rte_xstats_names_size,
                               sizeof *rte_xstats_names);
    rte_xstats_len = rte_eth_xstats_get_names(dev->port_id,
                                              rte_xstats_names,
                                              rte_xstats_names_size);
    if (rte_xstats_len < 0 || rte_xstats_len != rte_xstats_names_size) {
        VLOG_WARN("Cannot get XSTATS names for port: %d",
                  dev->port_id);
        goto out;
    }

    rte_xstats = xcalloc(rte_xstats_names_size, sizeof *rte_xstats);
    rte_xstats_len = rte_eth_xstats_get(dev->port_id, rte_xstats,
                                        rte_xstats_names_size);
    if (rte_xstats_len < 0 || rte_xstats_len != rte_xstats_names_size) {
        VLOG_WARN("Cannot get XSTATS for port: %d",
                  dev->port_id);
        goto out;
    }

    dev->rte_xstats_names = rte_xstats_names;
    rte_xstats_names = NULL;
    dev->rte_xstats_names_size = rte_xstats_names_size;

    dev->rte_xstats_ids = xcalloc(rte_xstats_names_size,
                                  sizeof *dev->rte_xstats_ids);
    for (unsigned int i = 0; i < rte_xstats_names_size; i++) {
        id = rte_xstats[i].id;
        name = netdev_doca_get_xstat_name(dev, id);

        /* For custom stats, we filter out everything except per rxq/txq basic
         * stats, and dropped, error and management counters. */
        if (is_queue_stat(name) ||
            string_ends_with(name, "_errors") ||
            strstr(name, "_management_") ||
            string_ends_with(name, "_dropped")) {

            dev->rte_xstats_ids[dev->rte_xstats_ids_size] = id;
            dev->rte_xstats_ids_size++;
        }
    }

out:
    free(rte_xstats);
    free(rte_xstats_names);
}

static bool
netdev_doca_rep_set_esw_mgr_port_id(struct netdev_doca *dev,
                                    uint16_t esw_mgr_port_id)
{
    dev->esw_mgr_port_id = esw_mgr_port_id;

    return true;
}

static int
dpdk_eth_dev_init(struct netdev_doca *dev)
    OVS_REQUIRES(doca_mutex)
    OVS_REQUIRES(dev->mutex)
{
    uint32_t rx_chksm_offload_capa = RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
                                     RTE_ETH_RX_OFFLOAD_TCP_CKSUM |
                                     RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
    struct netdev *netdev = &dev->up;
    struct rte_ether_addr eth_addr;
    struct rte_eth_dev_info info;
    int n_rxq, n_txq;
    int diag;

    diag = rte_eth_dev_info_get(dev->port_id, &info);
    if (diag < 0) {
        VLOG_ERR("Interface %s rte_eth_dev_info_get error: %s",
                 dev->up.name, rte_strerror(-diag));
        return -diag;
    }

    if (strstr(info.driver_name, "vf") != NULL) {
        VLOG_INFO("Virtual function detected, HW_CRC_STRIP will be enabled");
        dev->hw_ol_features |= NETDEV_RX_HW_CRC_STRIP;
    } else {
        dev->hw_ol_features &= ~NETDEV_RX_HW_CRC_STRIP;
    }

    if ((info.rx_offload_capa & rx_chksm_offload_capa) !=
            rx_chksm_offload_capa) {
        VLOG_WARN("Rx checksum offload is not supported on port %d",
                  dev->port_id);
        dev->hw_ol_features &= ~NETDEV_RX_CHECKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features |= NETDEV_RX_CHECKSUM_OFFLOAD;
    }

    if (info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER) {
        dev->hw_ol_features |= NETDEV_RX_HW_SCATTER;
    } else {
        /* Do not warn on lack of scatter support */
        dev->hw_ol_features &= ~NETDEV_RX_HW_SCATTER;
    }

    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
        dev->hw_ol_features |= NETDEV_TX_IPV4_CKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features &= ~NETDEV_TX_IPV4_CKSUM_OFFLOAD;
    }

    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) {
        dev->hw_ol_features |= NETDEV_TX_TCP_CKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features &= ~NETDEV_TX_TCP_CKSUM_OFFLOAD;
    }

    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
        dev->hw_ol_features |= NETDEV_TX_UDP_CKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features &= ~NETDEV_TX_UDP_CKSUM_OFFLOAD;
    }

    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_SCTP_CKSUM) {
        dev->hw_ol_features |= NETDEV_TX_SCTP_CKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features &= ~NETDEV_TX_SCTP_CKSUM_OFFLOAD;
    }

    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM) {
        dev->hw_ol_features |= NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features &= ~NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD;
    }

    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM) {
        dev->hw_ol_features |= NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD;
    } else {
        dev->hw_ol_features &= ~NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD;
    }

    dev->hw_ol_features &= ~NETDEV_TX_TSO_OFFLOAD;
    if (userspace_tso_enabled()) {
        if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO) {
            dev->hw_ol_features |= NETDEV_TX_TSO_OFFLOAD;
        } else {
            VLOG_WARN("%s: Tx TSO offload is not supported.",
                      netdev_get_name(&dev->up));
        }

        if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO) {
            dev->hw_ol_features |= NETDEV_TX_VXLAN_TNL_TSO_OFFLOAD;
        } else {
            VLOG_WARN("%s: Tx Vxlan tunnel TSO offload is not supported.",
                      netdev_get_name(&dev->up));
        }

        if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO) {
            dev->hw_ol_features |= NETDEV_TX_GENEVE_TNL_TSO_OFFLOAD;
        } else {
            VLOG_WARN("%s: Tx Geneve tunnel TSO offload is not supported.",
                      netdev_get_name(&dev->up));
        }

        if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO) {
            dev->hw_ol_features |= NETDEV_TX_GRE_TNL_TSO_OFFLOAD;
        } else {
            VLOG_WARN("%s: Tx GRE tunnel TSO offload is not supported.",
                      netdev_get_name(&dev->up));
        }
    }

    n_rxq = MIN(info.max_rx_queues, dev->up.n_rxq);
    n_txq = MIN(info.max_tx_queues, dev->up.n_txq);

    diag = dpdk_eth_dev_port_config(dev, &info, n_rxq, n_txq);
    if (diag) {
        VLOG_ERR("Interface %s(rxq:%d txq:%d lsc interrupt mode:%s) "
                 "configure error: %s",
                 dev->up.name, n_rxq, n_txq,
                 dev->lsc_interrupt_mode ? "true" : "false",
                 rte_strerror(-diag));
        return -diag;
    }

    /* When a representor is probed before its ESW, dpdk implicitly
     * probes the latter, thus probe is not called from
     * netdev_doca_process_devargs(). In this case we call probe at
     * netdev_doca_port_start(), and make sure the device is marked as
     * "attached".
     */
    dev->attached = true;
    if (netdev_doca_port_start(netdev)) {
        VLOG_ERR("Failed to init DOCA port %s port_id %"PRIu16,
                 netdev_get_name(netdev), dev->port_id);
        return -1;
    }

    atomic_store(&dev->started, true);
    ovs_mutex_unlock(&dev->mutex);

    ovs_mutex_lock(&dev->mutex);

    netdev_doca_configure_xstats(dev);

    memset(&eth_addr, 0x0, sizeof(eth_addr));
    rte_eth_macaddr_get(dev->port_id, &eth_addr);
    VLOG_INFO_RL(&rl, "Port %d: "ETH_ADDR_FMT,
                 dev->port_id, ETH_ADDR_BYTES_ARGS(eth_addr.addr_bytes));

    memcpy(dev->hwaddr.ea, eth_addr.addr_bytes, ETH_ADDR_LEN);
    if (rte_eth_link_get_nowait(dev->port_id, &dev->link) < 0) {
        memset(&dev->link, 0, sizeof dev->link);
    }

    /* Upon success of esw_mgr port, update the representor's field of it. */
    if (netdev_doca_get_esw_mgr_port_id(netdev) == dev->port_id &&
        netdev_doca_foreach_representor(dev,
                                        netdev_doca_rep_set_esw_mgr_port_id)) {
        /* If a representor is reconfigured a result of its ESW manager
         * change, it might not be synced in the bridge's database. Signal it
         * to reconfigure, to make it right.
         */
        rtnetlink_report_link();
    }
    return 0;
}

static void
netdev_doca_update_netdev_flag(struct netdev_doca *dev,
                               enum dpdk_hw_ol_features hw_ol_features,
                               enum netdev_ol_flags flag)
    OVS_REQUIRES(dev->mutex)
{
    struct netdev *netdev = &dev->up;

    if (dev->hw_ol_features & hw_ol_features) {
        netdev->ol_flags |= flag;
    } else {
        netdev->ol_flags &= ~flag;
    }
}

static void
netdev_doca_update_netdev_flags(struct netdev_doca *dev)
    OVS_REQUIRES(dev->mutex)
{
    netdev_doca_update_netdev_flag(dev, NETDEV_TX_IPV4_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_IPV4_CKSUM);
    netdev_doca_update_netdev_flag(dev, NETDEV_TX_TCP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_TCP_CKSUM);
    netdev_doca_update_netdev_flag(dev, NETDEV_TX_UDP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_UDP_CKSUM);
    netdev_doca_update_netdev_flag(dev, NETDEV_TX_SCTP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_SCTP_CKSUM);
    netdev_doca_update_netdev_flag(dev, NETDEV_TX_TSO_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_TCP_TSO);
    netdev_doca_update_netdev_flag(dev, NETDEV_TX_VXLAN_TNL_TSO_OFFLOAD,
                                   NETDEV_TX_VXLAN_TNL_TSO);
    netdev_doca_update_netdev_flag(dev, NETDEV_TX_GRE_TNL_TSO_OFFLOAD,
                                   NETDEV_TX_GRE_TNL_TSO);
    netdev_doca_update_netdev_flag(dev, NETDEV_TX_GENEVE_TNL_TSO_OFFLOAD,
                                   NETDEV_TX_GENEVE_TNL_TSO);
    netdev_doca_update_netdev_flag(dev, NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_OUTER_IP_CKSUM);
    netdev_doca_update_netdev_flag(dev, NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_OUTER_UDP_CKSUM);
}

static struct doca_tx_queue *
netdev_doca_alloc_txq(unsigned int n_txqs)
{
    struct doca_tx_queue *txqs;
    unsigned i;

    txqs = doca_rte_mzalloc("ovs_doca_txq", n_txqs * sizeof *txqs);
    if (txqs) {
        for (i = 0; i < n_txqs; i++) {
            rte_spinlock_init(&txqs[i].tx_lock);
        }
    }

    return txqs;
}

static int
netdev_doca_reconfigure(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    int err = 0;

    /* If an ESW manager is not attached to OVS, a representor cannot be
     * configured.
     */
    if (!netdev_doca_is_esw_mgr(netdev) &&
        netdev_doca_get_esw_mgr_port_id(netdev) == DPDK_ETH_PORT_ID_INVALID) {
        return EOPNOTSUPP;
    }

    ovs_mutex_lock(&doca_mutex);
    ovs_mutex_lock(&dev->mutex);

    dev->requested_n_rxq = dev->user_n_rxq;

    if (netdev->n_txq == dev->requested_n_txq
        && netdev->n_rxq == dev->requested_n_rxq
        && dev->mtu == dev->requested_mtu
        && dev->lsc_interrupt_mode == dev->requested_lsc_interrupt_mode
        && dev->rxq_size == dev->requested_rxq_size
        && dev->txq_size == dev->requested_txq_size
        && eth_addr_equals(dev->hwaddr, dev->requested_hwaddr)
        && dev->socket_id == dev->requested_socket_id
        && dev_get_started(dev)) {
        /* Reconfiguration is unnecessary */
        goto out;
    }

    netdev_doca_port_stop(netdev);

    err = netdev_doca_mempool_configure(dev);
    if (err && err != EEXIST) {
        goto out;
    }

    dev->lsc_interrupt_mode = dev->requested_lsc_interrupt_mode;

    netdev->n_txq = dev->requested_n_txq;
    netdev->n_rxq = dev->requested_n_rxq;
    if (!netdev_doca_is_esw_mgr(netdev)) {
        int esw_n_rxq;

        esw_n_rxq = dev->esw_ctx->n_rxq;
        if (esw_n_rxq < 0) {
            err = -1;
            goto out;
        }
        if (dev->requested_n_rxq != esw_n_rxq) {
            VLOG_WARN("%s: requested_n_rxq=%d is ignored. DOCA binds the "
                      "number of rx queues to the esw's n_rxq=%d",
                      netdev_get_name(netdev), dev->requested_n_rxq,
                      esw_n_rxq);
        }
        netdev->n_rxq = esw_n_rxq;
    }

    dev->rxq_size = dev->requested_rxq_size;
    dev->txq_size = dev->requested_txq_size;

    rte_free(dev->tx_q);
    dev->tx_q = NULL;

    if (!eth_addr_equals(dev->hwaddr, dev->requested_hwaddr)) {
        err = netdev_doca_set_etheraddr__(dev, dev->requested_hwaddr);
        if (err) {
            goto out;
        }
    }

    err = dpdk_eth_dev_init(dev);
    if (err) {
        goto out;
    }
    netdev_doca_update_netdev_flags(dev);

    /* If both requested and actual hw-addr were previously
     * unset (initialized to 0), then first device init above
     * will have set actual hw-addr to something new.
     * This would trigger spurious MAC reconfiguration unless
     * the requested MAC is kept in sync.
     *
     * This is harmless in case requested_hwaddr was
     * configured by the user, as netdev_doca_set_etheraddr__()
     * will have succeeded to get to this point.
     */
    dev->requested_hwaddr = dev->hwaddr;

    dev->tx_q = netdev_doca_alloc_txq(netdev->n_txq);
    if (!dev->tx_q) {
        err = ENOMEM;
    }

    netdev_change_seq_changed(netdev);

out:
    ovs_mutex_unlock(&dev->mutex);
    ovs_mutex_unlock(&doca_mutex);
    return err;
}

static int
common_construct(struct netdev *netdev, uint16_t port_no, int socket_id)
    OVS_REQUIRES(doca_mutex)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_init(&dev->mutex);

    rte_spinlock_init(&dev->stats_lock);

    /* If the 'sid' is negative, it means that the kernel fails
     * to obtain the pci numa info.  In that situation, always
     * use 'SOCKET0'. */
    dev->socket_id = socket_id < 0 ? SOCKET0 : socket_id;
    dev->requested_socket_id = dev->socket_id;
    dev->port_id = port_no;
    dev->esw_mgr_port_id = port_no;
    dev->flags = 0;
    dev->requested_mtu = RTE_ETHER_MTU;
    dev->max_packet_len = MTU_TO_FRAME_LEN(dev->mtu);
    dev->requested_lsc_interrupt_mode = 0;
    dev->attached = false;
    atomic_store(&dev->started, false);

    netdev->n_rxq = 0;
    netdev->n_txq = 0;
    dev->user_n_rxq = NR_QUEUE;
    dev->requested_n_rxq = NR_QUEUE;
    dev->requested_n_txq = NR_QUEUE;
    dev->requested_rxq_size = NIC_PORT_DEFAULT_RXQ_SIZE;
    dev->requested_txq_size = NIC_PORT_DEFAULT_TXQ_SIZE;

    /* Initialize the flow control to NULL */
    memset(&dev->fc_conf, 0, sizeof dev->fc_conf);

    /* Initilize the hardware offload flags to 0 */
    dev->hw_ol_features = 0;

    dev->rx_metadata_delivery_configured = false;

    dev->flags = NETDEV_UP | NETDEV_PROMISC;

    ovs_list_push_back(&doca_list, &dev->list_node);

    netdev_request_reconfigure(netdev);

    dev->rte_xstats_names = NULL;
    dev->rte_xstats_names_size = 0;

    dev->rte_xstats_ids = NULL;
    dev->rte_xstats_ids_size = 0;

    dev->sw_stats = xzalloc(sizeof *dev->sw_stats);
    dev->sw_stats->tx_retries = UINT64_MAX;

    return 0;
}

static int
netdev_doca_construct(struct netdev *netdev)
{
    int err;

    ovs_mutex_lock(&doca_mutex);
    err = common_construct(netdev, DPDK_ETH_PORT_ID_INVALID, SOCKET0);
    ovs_mutex_unlock(&doca_mutex);

    return err;
}

static int
netdev_doca_get_config(const struct netdev *netdev, struct smap *args)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_lock(&dev->mutex);

    if (dev->devargs && dev->devargs[0]) {
        smap_add_format(args, "dpdk-devargs", "%s", dev->devargs);
    }

    smap_add_format(args, "n_rxq", "%d", dev->user_n_rxq);

    if (dev->fc_conf.mode == RTE_ETH_FC_TX_PAUSE ||
        dev->fc_conf.mode == RTE_ETH_FC_FULL) {
        smap_add(args, "rx-flow-ctrl", "true");
    }

    if (dev->fc_conf.mode == RTE_ETH_FC_RX_PAUSE ||
        dev->fc_conf.mode == RTE_ETH_FC_FULL) {
        smap_add(args, "tx-flow-ctrl", "true");
    }

    if (dev->fc_conf.autoneg) {
        smap_add(args, "flow-ctrl-autoneg", "true");
    }

    smap_add_format(args, "n_rxq_desc", "%d", dev->rxq_size);
    smap_add_format(args, "n_txq_desc", "%d", dev->txq_size);

    smap_add(args, "dpdk-lsc-interrupt",
             dev->lsc_interrupt_mode ? "true" : "false");

    if (dev_is_representor(dev)) {
        smap_add_format(args, "dpdk-vf-mac", ETH_ADDR_FMT,
                        ETH_ADDR_ARGS(dev->requested_hwaddr));
    }

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static char *
netdev_doca_generate_devargs(const char *name, char *devargs, size_t maxlen,
                             char iface[IFNAMSIZ])
{
    char phys_port_name_[IFNAMSIZ], *phys_port_name = phys_port_name_;
    char phys_sw_id[MAX_PHYS_ITEM_ID_LEN];
    char iface_tmp[IFNAMSIZ];
    char device[PATH_MAX];
    char *mlx5_devargs;
    char *rep_part;
    bool mpesw;
    bool is_pf;
    char *pci;
    int port;
    int len;

    if (get_dpdk_iface_name(name, iface_tmp)) {
        return NULL;
    }
    name = iface_tmp;
    ovs_strlcpy(iface, name, IFNAMSIZ);

    if (get_pci(name, device, sizeof device)) {
        return NULL;
    }
    pci = device;

    if (get_phys_port_name(name, phys_port_name_, sizeof phys_port_name_)) {
        return NULL;
    }
    /* In some kernels, there is a controller prefix, like "c1". Ignore it. */
    if (sscanf(phys_port_name, "c%d", &port) == 1) {
        phys_port_name += 2;
    }

    if (get_phys_switch_id(name, phys_sw_id, sizeof phys_sw_id)) {
        return NULL;
    }

    is_pf = false;

    if (sscanf(phys_port_name, "p%d", &port) == 1) {
        is_pf =  true;
    } else if (sscanf(phys_port_name, "pf%d", &port) != 1) {
        return NULL;
    }

    mpesw = is_mpesw(pci);
    if (port > 0 && mpesw) {
        if (get_primary_pci(phys_sw_id, device, sizeof device)) {
            return NULL;
        }
    }

    mlx5_devargs =
        "dv_xmeta_en=4,"
        "dv_flow_en=2";

    len = strlen(phys_port_name);
    /* hpf's phys_port_name is pf0/pf1. */
    if (len == 3 && !strncmp(phys_port_name, "pf", 2)) {
        /* "" to workaround a false positive checkpatch issue. */
        if (snprintf(devargs, maxlen, "%s,%s,representor=(pf%d)""vf65535", pci,
                     mlx5_devargs, port) < 0) {
            return NULL;
        }
        return devargs;
    }

    /* pf ports */
    if (is_pf) {
        if (!mpesw || port == 0) {
            len = snprintf(devargs, maxlen, "%s,%s", pci, mlx5_devargs);
        } else {
            len = snprintf(devargs, maxlen, "%s,%s,representor=pf%d", pci,
                           mlx5_devargs, port);
        }
        if (len < 0) {
            return NULL;
        }
        return devargs;
    }

    /* Representors. */
    rep_part = strstr(phys_port_name, "vf");
    if (!rep_part) {
        rep_part = strstr(phys_port_name, "sf");
    }
    if (!rep_part) {
        return NULL;
    }
    /* Format as (pfX)vfY or (pfX)sfY */
    if (snprintf(devargs, maxlen, "%s,%s,representor=(%.*s)%s", pci,
                 mlx5_devargs, (int) (rep_part - phys_port_name),
                 phys_port_name, rep_part) < 0) {
        return NULL;
    }
    return devargs;
}

/* Return the first DPDK port id matching the 'devargs' pattern. */
static uint16_t netdev_doca_get_port_by_devargs(const char *devargs)
    OVS_REQUIRES(doca_mutex)
{
    struct rte_dev_iterator iterator;
    uint16_t port_id;

    RTE_ETH_FOREACH_MATCHING_DEV (port_id, devargs, &iterator) {
        /* If a break is done - must call rte_eth_iterator_cleanup. */
        rte_eth_iterator_cleanup(&iterator);
        break;
    }

    return port_id;
}

static uint16_t
netdev_doca_process_devargs(struct netdev_doca *dev,
                            const char *devargs, char **errp)
    OVS_REQUIRES(doca_mutex)
{
    uint16_t new_port_id;

    new_port_id = netdev_doca_get_port_by_devargs(devargs);
    if (!rte_eth_dev_is_valid_port(new_port_id)) {
        int err;

        /* Device not found in DPDK, attempt to attach it */
        err = netdev_doca_dev_probe(dev, devargs);
        if (err) {
            new_port_id = DPDK_ETH_PORT_ID_INVALID;
        } else {
            new_port_id = netdev_doca_get_port_by_devargs(devargs);
            if (rte_eth_dev_is_valid_port(new_port_id)) {
                /* Attach successful */
                dev->attached = true;
                VLOG_INFO("Device '%s' attached to DPDK", devargs);
            } else {
                /* Attach unsuccessful */
                new_port_id = DPDK_ETH_PORT_ID_INVALID;
            }
        }
    }

    if (new_port_id == DPDK_ETH_PORT_ID_INVALID) {
        VLOG_WARN_BUF(errp, "Error attaching device '%s' to DPDK", devargs);
    }
    return new_port_id;
}

static struct netdev_doca *
netdev_doca_lookup_by_port_id(uint16_t port_id)
    OVS_REQUIRES(doca_mutex)
{
    struct netdev_doca *dev;

    LIST_FOR_EACH (dev, list_node, &doca_list) {
        if (dev->port_id == port_id) {
            return dev;
        }
    }

    return NULL;
}

static uint16_t
netdev_doca_find_esw_mgr_port_id(uint16_t dev_port_id)
    OVS_REQUIRES(doca_mutex)
{
    struct rte_eth_dev_info info;
    struct netdev_doca *dev;
    uint16_t domain_id;

    if (!rte_eth_dev_is_valid_port(dev_port_id)) {
        return -1;
    }
    if (rte_eth_dev_info_get(dev_port_id, &info) < 0) {
        VLOG_DBG_RL(&rl, "Failed to retrieve device info for port %d",
                    dev_port_id);
        return -1;
    }
    domain_id = info.switch_info.domain_id;
    LIST_FOR_EACH (dev, list_node, &doca_list) {
        if (!rte_eth_dev_is_valid_port(dev->port_id)) {
            continue;
        }
        if (rte_eth_dev_info_get(dev->port_id, &info) < 0) {
            VLOG_DBG_RL(&rl, "Failed to retrieve device info for port %d",
                        dev->port_id);
            continue;
        }
        if (info.switch_info.domain_id == domain_id &&
            !(*info.dev_flags & RTE_ETH_DEV_REPRESENTOR)) {
            VLOG_INFO("Found ESW manager port %d for device %d",
                      dev->port_id, dev_port_id);
            return dev->port_id;
        }
    }

    return -1;
}

static void
doca_set_rxq_config(struct netdev_doca *dev, const struct smap *args)
    OVS_REQUIRES(dev->mutex)
{
    int new_n_rxq;

    new_n_rxq = MAX(smap_get_int(args, "n_rxq", NR_QUEUE), 1);
    if (new_n_rxq != dev->user_n_rxq) {
        dev->user_n_rxq = new_n_rxq;
        netdev_request_reconfigure(&dev->up);
    }
}

static int
netdev_doca_set_config(struct netdev *netdev, const struct smap *args,
                       char **errp)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    char generated[PATH_MAX];
    bool lsc_interrupt_mode;
    const char *new_devargs;
    char iface[IFNAMSIZ];
    const char *dev_name;
    const char *vf_mac;
    int err = 0;
    bool is_rep;

    ovs_mutex_lock(&doca_mutex);
    ovs_mutex_lock(&dev->mutex);

    memset(iface, 0, sizeof iface);
    if (!dev->devargs) {
        dev_name = netdev_get_name(netdev);
        new_devargs = netdev_doca_generate_devargs(dev_name, generated,
                                                   sizeof generated, iface);
        if (!new_devargs) {
            VLOG_DBG("%s: Configured port name was not found in sysfs, "
                     "skipping DPDK probe", netdev_get_name(netdev));
            err = ENODEV;
            goto out;
        }
        dev->devargs = xstrdup(new_devargs);
    }

    is_rep = strstr(dev->devargs, "representor=");
    if (is_rep) {
        struct netdev_doca_esw_key esw_key;
        struct netdev_doca_esw_ctx *esw;

        if (netdev_doca_esw_key_parse(dev->devargs, &esw_key)) {
            return EINVAL;
        }
        esw = refmap_try_ref(netdev_doca_esw_rfm, &esw_key);
        if (!esw) {
            goto out;
        }
        refmap_unref(netdev_doca_esw_rfm, esw);
    }

    doca_set_rxq_config(dev, args);

    /* Don't process dpdk-devargs if value is unchanged and port id
     * is valid */
    if (!(rte_eth_dev_is_valid_port(dev->port_id) && dev->attached)) {
        uint16_t new_port_id = netdev_doca_process_devargs(dev,
                                                           dev->devargs,
                                                           errp);
        if (!rte_eth_dev_is_valid_port(new_port_id)) {
            err = EINVAL;
        } else if (new_port_id == dev->port_id) {
            /* Already configured, do not reconfigure again */
            err = 0;
        } else {
            struct netdev_doca *dup_dev;

            dup_dev = netdev_doca_lookup_by_port_id(new_port_id);
            if (dup_dev) {
                VLOG_WARN_BUF(errp, "'%s' is trying to use device '%s' "
                              "which is already in use by '%s'",
                              netdev_get_name(netdev), dev->devargs,
                              netdev_get_name(&dup_dev->up));
                err = EADDRINUSE;
            } else {
                int sid = rte_eth_dev_socket_id(new_port_id);

                dev->requested_socket_id = sid < 0 ? SOCKET0 : sid;
                dev->port_id = new_port_id;
                dev->esw_mgr_port_id =
                    netdev_doca_find_esw_mgr_port_id(new_port_id);
                netdev_request_reconfigure(&dev->up);
                err = 0;
            }
        }
    }

    if (err) {
        goto out;
    }

    vf_mac = smap_get(args, "dpdk-vf-mac");
    if (vf_mac) {
        struct eth_addr mac;

        if (!dev_is_representor(dev)) {
            VLOG_WARN("'%s' is trying to set the VF MAC '%s' "
                      "but 'options:dpdk-vf-mac' is only supported for "
                      "VF representors.",
                      netdev_get_name(netdev), vf_mac);
        } else if (!eth_addr_from_string(vf_mac, &mac)) {
            VLOG_WARN("interface '%s': cannot parse VF MAC '%s'.",
                      netdev_get_name(netdev), vf_mac);
        } else if (eth_addr_is_multicast(mac)) {
            VLOG_WARN("interface '%s': cannot set VF MAC to multicast "
                      "address '%s'.", netdev_get_name(netdev), vf_mac);
        } else if (!eth_addr_equals(dev->requested_hwaddr, mac)) {
            dev->requested_hwaddr = mac;
            netdev_request_reconfigure(netdev);
        }
    }

    lsc_interrupt_mode = smap_get_bool(args, "dpdk-lsc-interrupt", false);
    if (dev->requested_lsc_interrupt_mode != lsc_interrupt_mode) {
        dev->requested_lsc_interrupt_mode = lsc_interrupt_mode;
        netdev_request_reconfigure(netdev);
    }

out:
    ovs_mutex_unlock(&dev->mutex);
    ovs_mutex_unlock(&doca_mutex);

    return err;
}

static void
classify_in_port(struct dp_packet_batch *rx_batch,
                 struct netdev_doca_port_queue *pq[RTE_MAX_ETHPORTS],
                 uint16_t queue_id)
{
    struct dp_packet *pkt;
    uint64_t old_count;
    uint32_t pkt_size;
    uint32_t port_id;
    int rv;

    DP_PACKET_BATCH_FOR_EACH (i, pkt, rx_batch) {
        dp_packet_reset_cutlen(pkt);
        pkt->packet_type = htonl(PT_ETH);
        pkt->has_hash = !!(pkt->mbuf.ol_flags & RTE_MBUF_F_RX_RSS_HASH);
        pkt->has_mark = !!(pkt->mbuf.ol_flags & RTE_MBUF_F_RX_FDIR_ID);
        pkt->offloads =
            pkt->mbuf.ol_flags & (RTE_MBUF_F_RX_IP_CKSUM_BAD
                                  | RTE_MBUF_F_RX_IP_CKSUM_GOOD
                                  | RTE_MBUF_F_RX_L4_CKSUM_BAD
                                  | RTE_MBUF_F_RX_L4_CKSUM_GOOD);

        if (!dp_packet_has_flow_mark(pkt, &port_id)) {
            COVERAGE_INC(netdev_doca_no_mark);
            dp_packet_delete(pkt);
            continue;
        }
        pkt->has_mark = false;
        if (!rte_eth_dev_is_valid_port(port_id)) {
            COVERAGE_INC(netdev_doca_invalid_classify_port);
            dp_packet_delete(pkt);
            continue;
        }
        pkt_size = dp_packet_size(pkt);
        rv = rte_ring_sp_enqueue(pq[port_id][queue_id].ring, pkt);
        if (rv) {
            COVERAGE_INC(netdev_doca_drop_ring_full);
            dp_packet_delete(pkt);
            continue;
        }
        atomic_add_relaxed(&pq[port_id][queue_id].n_bytes, pkt_size,
                           &old_count);
    }
}

static int
netdev_doca_rxq_recv(struct netdev_rxq *rxq, struct dp_packet_batch *batch,
                     int *qfill)
{
    struct netdev_doca *dev = netdev_doca_cast(rxq->netdev);
    struct netdev_rxq_doca *rx = netdev_rxq_doca_cast(rxq);
    struct netdev_doca_port_queue *pq;
    struct dp_packet_batch rx_batch;
    uint16_t esw_mgr_port_id;
    uint64_t old_count;
    uint16_t port_id;
    int nb_rx;

    if (OVS_UNLIKELY(!(dev->flags & NETDEV_UP) || !dev_get_started(dev))) {
        return EAGAIN;
    }

    esw_mgr_port_id = dev->esw_ctx->port_id;
    port_id = dev->port_id;

    if (port_id == esw_mgr_port_id) {
        rx_batch.count =
            rte_eth_rx_burst(esw_mgr_port_id, rxq->queue_id,
                             (struct rte_mbuf **) rx_batch.packets,
                             NETDEV_MAX_BURST);
        if (rx_batch.count == 0) {
            return 0;
        }
        classify_in_port(&rx_batch, dev->esw_ctx->port_queues, rxq->queue_id);
    }

    pq = &dev->esw_ctx->port_queues[port_id][rxq->queue_id];
    batch->count =
        rte_ring_sc_dequeue_burst(pq->ring, (void **) batch->packets,
                                  NETDEV_MAX_BURST, NULL);
    atomic_add_relaxed(&pq->n_packets, batch->count, &old_count);

    nb_rx = batch->count;

    if (!nb_rx) {
        return EAGAIN;
    }

    if (qfill) {
        if (nb_rx == NETDEV_MAX_BURST) {
            *qfill = rte_eth_rx_queue_count(rx->port_id, rxq->queue_id);
        } else {
            *qfill = 0;
        }
    }

    return 0;
}

static struct rte_mbuf *
dpdk_pktmbuf_alloc(struct rte_mempool *mp, uint32_t data_len)
{
    struct rte_mbuf *pkt = rte_pktmbuf_alloc(mp);

    if (OVS_UNLIKELY(!pkt)) {
        return NULL;
    }

    if (rte_pktmbuf_tailroom(pkt) >= data_len) {
        return pkt;
    }

    rte_pktmbuf_free(pkt);

    return NULL;
}

static struct dp_packet *
dpdk_copy_dp_packet_to_mbuf(struct rte_mempool *mp, struct dp_packet *pkt_orig)
{
    struct rte_mbuf *mbuf_dest;
    struct dp_packet *pkt_dest;
    uint32_t pkt_len;

    pkt_len = dp_packet_size(pkt_orig);
    mbuf_dest = dpdk_pktmbuf_alloc(mp, pkt_len);
    if (OVS_UNLIKELY(mbuf_dest == NULL)) {
            return NULL;
    }

    pkt_dest = CONTAINER_OF(mbuf_dest, struct dp_packet, mbuf);
    memcpy(dp_packet_data(pkt_dest), dp_packet_data(pkt_orig), pkt_len);
    dp_packet_set_size(pkt_dest, pkt_len);

    mbuf_dest->tx_offload = pkt_orig->mbuf.tx_offload;
    mbuf_dest->packet_type = pkt_orig->mbuf.packet_type;
    mbuf_dest->ol_flags |= (pkt_orig->mbuf.ol_flags &
                            ~(RTE_MBUF_F_EXTERNAL | RTE_MBUF_F_INDIRECT));
    mbuf_dest->tso_segsz = pkt_orig->mbuf.tso_segsz;

    memcpy(&pkt_dest->l2_pad_size, &pkt_orig->l2_pad_size,
           sizeof(struct dp_packet) - offsetof(struct dp_packet, l2_pad_size));

    if (dp_packet_l3(pkt_dest)) {
        if (dp_packet_eth(pkt_dest)) {
            mbuf_dest->l2_len = (char *) dp_packet_l3(pkt_dest)
                                - (char *) dp_packet_eth(pkt_dest);
        } else {
            mbuf_dest->l2_len = 0;
        }
        if (dp_packet_l4(pkt_dest)) {
            mbuf_dest->l3_len = (char *) dp_packet_l4(pkt_dest)
                                - (char *) dp_packet_l3(pkt_dest);
        } else {
            mbuf_dest->l3_len = 0;
        }
    }

    return pkt_dest;
}

/* Replace packets in a 'batch' with their corresponding copies using
 * DPDK memory.
 *
 * Returns the number of good packets in the batch. */
static size_t
dpdk_copy_batch_to_mbuf(struct netdev *netdev, struct dp_packet_batch *batch)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    size_t i, size = dp_packet_batch_size(batch);
    struct dp_packet *packet;

    DP_PACKET_BATCH_REFILL_FOR_EACH (i, size, packet, batch) {
        if (OVS_UNLIKELY(packet->source == DPBUF_DPDK)) {
            dp_packet_batch_refill(batch, packet, i);
        } else {
            struct dp_packet *pktcopy;

            pktcopy = dpdk_copy_dp_packet_to_mbuf(dev->dpdk_mp->mp, packet);
            if (pktcopy) {
                dp_packet_batch_refill(batch, pktcopy, i);
            }

            dp_packet_delete(packet);
        }
    }

    return dp_packet_batch_size(batch);
}

static int
netdev_doca_filter_packet_len(struct netdev_doca *dev, struct rte_mbuf **pkts,
                              int pkt_cnt)
{
    int i = 0;
    int cnt = 0;
    struct rte_mbuf *pkt;

    /* Filter over-sized packets. The TSO packets are filtered out
     * during the offloading preparation for performance reasons. */
    for (i = 0; i < pkt_cnt; i++) {
        pkt = pkts[i];
        if (OVS_UNLIKELY((pkt->pkt_len > dev->max_packet_len)
            && !(pkt->ol_flags & RTE_MBUF_F_TX_TCP_SEG))) {
            VLOG_WARN_RL(&rl, "%s: Too big size %" PRIu32 " "
                         "max_packet_len %d", dev->up.name, pkt->pkt_len,
                         dev->max_packet_len);
            COVERAGE_INC(netdev_doca_drop_oversized);
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

static void
netdev_doca_mbuf_dump(const char *prefix, const char *message,
                      const struct rte_mbuf *mbuf)
{
    static struct vlog_rate_limit dump_rl = VLOG_RATE_LIMIT_INIT(5, 5);
    char *response = NULL;
    FILE *stream;
    size_t size;

    if (VLOG_DROP_DBG(&dump_rl)) {
        return;
    }

    stream = open_memstream(&response, &size);
    if (!stream) {
        VLOG_ERR("Unable to open memstream for mbuf dump: %s.",
                 ovs_strerror(errno));
        return;
    }

    rte_pktmbuf_dump(stream, mbuf, rte_pktmbuf_pkt_len(mbuf));

    fclose(stream);

    VLOG_DBG(prefix ? "%s: %s:\n%s" : "%s%s:\n%s",
             prefix ? prefix : "", message, response);
    free(response);
}

/* Prepare the packet for HWOL.
 * Return True if the packet is OK to continue. */
static bool
netdev_doca_prep_hwol_packet(struct netdev_doca *dev, struct rte_mbuf *mbuf)
{
    struct dp_packet *pkt = CONTAINER_OF(mbuf, struct dp_packet, mbuf);
    uint64_t unexpected = mbuf->ol_flags & RTE_MBUF_F_TX_OFFLOAD_MASK;
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
        VLOG_WARN_RL(&rl, "%s: Unexpected Tx offload flags: %#"PRIx64,
                     netdev_get_name(&dev->up), unexpected);
        netdev_doca_mbuf_dump(netdev_get_name(&dev->up),
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

    if (dp_packet_tunnel(pkt)
        && (dp_packet_inner_ip_checksum_partial(pkt)
            || dp_packet_inner_l4_checksum_partial(pkt)
            || mbuf->tso_segsz)) {
        if (dp_packet_ip_checksum_partial(pkt)
            || dp_packet_l4_checksum_partial(pkt)) {
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

            /* Skip outer headers. */
            l2 = dp_packet_eth(pkt);
            l3 = dp_packet_inner_l3(pkt);
            l3_csum = dp_packet_inner_ip_checksum_partial(pkt);
            l4 = dp_packet_inner_l4(pkt);
            l4_csum = dp_packet_inner_l4_checksum_partial(pkt);
            is_tcp = dp_packet_inner_l4_proto_tcp(pkt);
            is_udp = dp_packet_inner_l4_proto_udp(pkt);
            is_sctp = dp_packet_inner_l4_proto_sctp(pkt);
        }
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
        uint16_t link_tso_segsz;
        int hdr_len;

        mbuf->l4_len = TCP_OFFSET(th->tcp_ctl) * 4;
        if (dp_packet_tunnel(pkt)) {
            link_tso_segsz = dev->mtu - mbuf->l2_len - mbuf->l3_len -
                             mbuf->l4_len - mbuf->outer_l3_len;
        } else {
            link_tso_segsz = dev->mtu - mbuf->l3_len - mbuf->l4_len;
        }

        if (mbuf->tso_segsz > link_tso_segsz) {
            mbuf->tso_segsz = link_tso_segsz;
        }

        hdr_len = mbuf->l2_len + mbuf->l3_len + mbuf->l4_len;
        if (OVS_UNLIKELY((hdr_len + mbuf->tso_segsz) > dev->max_packet_len)) {
            VLOG_WARN_RL(&rl, "%s: Oversized TSO packet. hdr: %"PRIu32", "
                         "gso: %"PRIu32", max len: %"PRIu32"",
                         dev->up.name, hdr_len, mbuf->tso_segsz,
                         dev->max_packet_len);
            return false;
        }
        mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
    }

    /* If L4 checksum is requested, IPv4 should be requested as well. */
    if (mbuf->ol_flags & RTE_MBUF_F_TX_L4_MASK
        && mbuf->ol_flags & RTE_MBUF_F_TX_IPV4) {
        mbuf->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
    }

    return true;
}

/* Prepare a batch for HWOL.
 * Return the number of good packets in the batch. */
static int
netdev_doca_prep_hwol_batch(struct netdev_doca *dev, struct rte_mbuf **pkts,
                            int pkt_cnt)
{
    int i = 0;
    int cnt = 0;
    struct rte_mbuf *pkt;

    /* Prepare and filter bad HWOL packets. */
    for (i = 0; i < pkt_cnt; i++) {
        pkt = pkts[i];
        if (!netdev_doca_prep_hwol_packet(dev, pkt)) {
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

static size_t
netdev_doca_common_send(struct netdev *netdev, struct dp_packet_batch *batch,
                        struct netdev_doca_sw_stats *stats)
{
    struct rte_mbuf **pkts = (struct rte_mbuf **) batch->packets;
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    size_t cnt, pkt_cnt = dp_packet_batch_size(batch);
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
        cnt = dpdk_copy_batch_to_mbuf(netdev, batch);
        stats->tx_failure_drops += pkt_cnt - cnt;
        pkt_cnt = cnt;
    }

    /* Drop over-sized packets. */
    cnt = netdev_doca_filter_packet_len(dev, pkts, pkt_cnt);
    stats->tx_mtu_exceeded_drops += pkt_cnt - cnt;
    pkt_cnt = cnt;

    /* Prepare each mbuf for hardware offloading. */
    cnt = netdev_doca_prep_hwol_batch(dev, pkts, pkt_cnt);
    stats->tx_invalid_hwol_drops += pkt_cnt - cnt;
    pkt_cnt = cnt;

    return cnt;
}

static inline void
packet_set_meta(struct dp_packet *p, uint32_t meta)
{
    *RTE_MBUF_DYNFIELD(&p->mbuf, rte_flow_dynf_metadata_offs,
                       uint32_t *) = meta;
    p->mbuf.ol_flags |= RTE_MBUF_DYNFLAG_TX_METADATA;
}

/* Tries to transmit 'pkts' to txq 'qid' of device 'dev'.  Takes ownership of
 * 'pkts', even in case of failure.
 *
 * Returns the number of packets that weren't transmitted. */
static inline int
netdev_doca_eth_tx_burst(struct netdev_doca *dev, int qid,
                         struct rte_mbuf **pkts, int cnt)
{
    uint16_t nb_tx_prep = cnt;
    uint32_t nb_tx = 0;

    if (OVS_UNLIKELY(!dev_get_started(dev))) {
        goto out;
    }

    nb_tx_prep = rte_eth_tx_prepare(dev->esw_mgr_port_id, qid, pkts, cnt);
    if (nb_tx_prep != cnt) {
        VLOG_WARN_RL(&rl, "%s: Output batch contains invalid packets. "
                     "Only %u/%u are valid: %s", netdev_get_name(&dev->up),
                     nb_tx_prep, cnt, rte_strerror(rte_errno));
        netdev_doca_mbuf_dump(netdev_get_name(&dev->up),
                              "First invalid packet", pkts[nb_tx_prep]);
    }

    while (nb_tx != nb_tx_prep) {
        uint32_t ret;

        ret = rte_eth_tx_burst(dev->esw_mgr_port_id, qid, pkts + nb_tx,
                               nb_tx_prep - nb_tx);
        if (!ret) {
            break;
        }

        nb_tx += ret;
    }

out:
    if (OVS_UNLIKELY(nb_tx != cnt)) {
        /* Free buffers, which we couldn't transmit. */
        rte_pktmbuf_free_bulk(&pkts[nb_tx], cnt - nb_tx);
    }

    return cnt - nb_tx;
}

static int
netdev_doca_eth_send(struct netdev *netdev, int qid,
                     struct dp_packet_batch *batch, bool concurrent_txq)
{
    struct rte_mbuf **pkts = (struct rte_mbuf **) batch->packets;
    uint32_t port_id_meta = netdev_doca_get_port_id(netdev);
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    int batch_cnt = dp_packet_batch_size(batch);
    struct netdev_doca_sw_stats stats;
    int cnt, dropped;
    struct dp_packet *packet;
    uint64_t n_bytes = 0;
    uint64_t old_count;

    if (OVS_UNLIKELY(!(dev->flags & NETDEV_UP))) {
        rte_spinlock_lock(&dev->stats_lock);
        dev->stats.tx_dropped += dp_packet_batch_size(batch);
        rte_spinlock_unlock(&dev->stats_lock);
        dp_packet_delete_batch(batch, true);
        return 0;
    }

    if (OVS_UNLIKELY(concurrent_txq)) {
        qid = qid % dev->up.n_txq;
        rte_spinlock_lock(&dev->tx_q[qid].tx_lock);
    }

    cnt = netdev_doca_common_send(netdev, batch, &stats);

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        /* Set metadata for egress pipe rules to match on. */
        packet_set_meta(packet, port_id_meta);
        n_bytes += dp_packet_size(packet);
    }
    atomic_add_relaxed(&dev->sw_tx_stats[qid].n_packets, batch->count,
                       &old_count);
    atomic_add_relaxed(&dev->sw_tx_stats[qid].n_bytes, n_bytes, &old_count);

    dropped = netdev_doca_eth_tx_burst(dev, qid, pkts, cnt);
    stats.tx_failure_drops += dropped;
    dropped += batch_cnt - cnt;
    if (OVS_UNLIKELY(dropped)) {
        struct netdev_doca_sw_stats *sw_stats = dev->sw_stats;

        rte_spinlock_lock(&dev->stats_lock);
        dev->stats.tx_dropped += dropped;
        sw_stats->tx_failure_drops += stats.tx_failure_drops;
        sw_stats->tx_mtu_exceeded_drops += stats.tx_mtu_exceeded_drops;
        sw_stats->tx_invalid_hwol_drops += stats.tx_invalid_hwol_drops;
        rte_spinlock_unlock(&dev->stats_lock);
    }
    if (OVS_UNLIKELY(concurrent_txq)) {
        rte_spinlock_unlock(&dev->tx_q[qid].tx_lock);
    }

    return 0;
}

#define NETDEV_DOCA_CLASS_COMMON                            \
    .is_pmd = true,                                         \
    .alloc = netdev_doca_alloc,                             \
    .dealloc = netdev_doca_dealloc,                         \
    .get_numa_id = netdev_doca_get_numa_id,                 \
    .set_etheraddr = netdev_doca_set_etheraddr,             \
    .get_etheraddr = netdev_doca_get_etheraddr,             \
    .get_mtu = netdev_doca_get_mtu,                         \
    .set_mtu = netdev_doca_set_mtu,                         \
    .get_ifindex = netdev_doca_get_ifindex,                 \
    .get_carrier_resets = netdev_doca_get_carrier_resets,   \
    .set_miimon_interval = netdev_doca_set_miimon,          \
    .update_flags = netdev_doca_update_flags,               \
    .rxq_alloc = netdev_doca_rxq_alloc,                     \
    .rxq_construct = netdev_doca_rxq_construct,             \
    .rxq_destruct = netdev_doca_rxq_destruct,               \
    .rxq_dealloc = netdev_doca_rxq_dealloc

#define NETDEV_DOCA_CLASS_BASE                          \
    NETDEV_DOCA_CLASS_COMMON,                           \
    .init = netdev_doca_class_init,                     \
    .destruct = netdev_doca_destruct,                   \
    .set_tx_multiq = netdev_doca_set_tx_multiq,         \
    .get_carrier = netdev_doca_get_carrier,             \
    .get_stats = netdev_doca_get_stats,                 \
    .get_custom_stats = netdev_doca_get_custom_stats,   \
    .get_features = netdev_doca_get_features,           \
    .get_speed = netdev_doca_get_speed,                 \
    .get_status = netdev_doca_get_status,               \
    .reconfigure = netdev_doca_reconfigure,             \
    .rxq_recv = netdev_doca_rxq_recv

const struct netdev_class netdev_doca_class = {
    .type = "doca",
    NETDEV_DOCA_CLASS_BASE,
    .construct = netdev_doca_construct,
    .get_config = netdev_doca_get_config,
    .set_config = netdev_doca_set_config,
    .send = netdev_doca_eth_send,
};

void
netdev_doca_register(void)
{
    netdev_register_provider(&netdev_doca_class);
}
