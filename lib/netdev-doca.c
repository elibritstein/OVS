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

#include <config.h>

#include "netdev-doca.h"

#include <errno.h>
#include <infiniband/verbs.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/stat.h>

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
#include <doca_dev.h>
#include <doca_dpdk.h>
#include <doca_flow.h>
#include <doca_rdma_bridge.h>

#include "coverage.h"
#include "dp-packet.h"
#include "dpif-netdev.h"
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
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

COVERAGE_DEFINE(netdev_doca_rx_drop_invalid_port);
COVERAGE_DEFINE(netdev_doca_rx_drop_no_mark);
COVERAGE_DEFINE(netdev_doca_rx_drop_ring_full);

#define NETDEV_DOCA_MAX_MEGAFLOWS_COUNTERS (1 << 19)
#define NETDEV_DOCA_ACTIONS_MEM_SIZE \
    (64 * 2 * NETDEV_DOCA_MAX_MEGAFLOWS_COUNTERS)

struct netdev_doca_esw_key {
    struct rte_pci_addr rte_pci;
};

struct netdev_doca_esw_ctx_arg {
    struct netdev_doca_esw_key *esw_key;
    struct netdev_doca *dev;
};

struct rss_match_type {
    enum doca_flow_l3_meta l3_type;
    enum doca_flow_l4_meta l4_type;
};

static uint16_t pre_miss_mapping[PRE_MISS_N_TYPES] = {
    [PRE_MISS_TYPE_LACP] = ETH_TYPE_LACP,
    [PRE_MISS_TYPE_LLDP] = ETH_TYPE_LLDP,
};

static struct refmap *netdev_doca_esw_rfm;
static struct atomic_count n_doca_ports = ATOMIC_COUNT_INIT(0);
/* Global mutex for all DOCA activities.  This must be acquired before
 * any per-device mutex ('netdev_dpdk_common.mutex'). */
struct ovs_mutex doca_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct doca_dev's. */
static struct ovs_list doca_list OVS_GUARDED_BY(doca_mutex)
    = OVS_LIST_INITIALIZER(&doca_list);

static struct ovs_mutex doca_mp_mutex OVS_ACQ_AFTER(doca_mutex)
    = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct doca_mp's. */
static struct ovs_list doca_mp_list OVS_GUARDED_BY(doca_mp_mutex)
    = OVS_LIST_INITIALIZER(&doca_mp_list);

struct doca_mp {
     struct rte_mempool *mp;
     bool dead;
     struct ovs_list list_node OVS_GUARDED_BY(doca_mp_mutex);
};

static void
netdev_doca_destruct(struct netdev *netdev);

static int
netdev_doca_port_stop(struct netdev *netdev)
    OVS_REQUIRES(doca_mutex);

static void
netdev_doca_mempool_unconfigure(struct netdev_doca *dev);

static dpdk_port_t
netdev_doca_get_esw_mgr_port_id(const struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    if (!rte_eth_dev_is_valid_port(dev->common.port_id) ||
        !rte_eth_dev_is_valid_port(dev->esw_mgr_port_id)) {
        return DPDK_ETH_PORT_ID_INVALID;
    }

    return dev->esw_mgr_port_id;
}

static dpdk_port_t
netdev_doca_get_port_id(const struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    if (!rte_eth_dev_is_valid_port(dev->common.port_id)) {
        return DPDK_ETH_PORT_ID_INVALID;
    }

    return dev->common.port_id;
}

static bool
netdev_doca_is_esw_mgr(const struct netdev *netdev)
{
    dpdk_port_t esw_mgr_id = netdev_doca_get_esw_mgr_port_id(netdev);

    return esw_mgr_id == netdev_doca_get_port_id(netdev) &&
           esw_mgr_id != DPDK_ETH_PORT_ID_INVALID;
}

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

    /* Meta to match on is defined per entry. */
    memset(&match.d.meta.pkt_meta, 0xFF, sizeof match.d.meta.pkt_meta);

    /* Port ID to forward to is defined per entry. */
    fwd.type = DOCA_FLOW_FWD_PORT;
    memset(&fwd.port_id, 0xFF, sizeof fwd.port_id);
    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    return ovs_doca_pipe_create(&dev->common.up, &match, NULL, &monitor, NULL,
                                NULL, NULL, &fwd, NULL, RTE_MAX_ETHPORTS, true,
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
    struct ovs_doca_flow_actions actions;
    struct ovs_doca_flow_match match;
    struct doca_flow_monitor monitor;
    struct doca_flow_fwd fwd;
    int rv;

    memset(&match, 0, sizeof match);
    memset(&fwd, 0, sizeof fwd);
    memset(&actions, 0, sizeof actions);
    memset(&monitor, 0, sizeof monitor);

    memset(&match.d.parser_meta.port_id, 0xFF,
           sizeof match.d.parser_meta.port_id);
    memset(&match.d.parser_meta.outer_l3_type, 0xFF,
           sizeof match.d.parser_meta.outer_l3_type);
    memset(&match.d.parser_meta.outer_l4_type, 0xFF,
           sizeof match.d.parser_meta.outer_l4_type);

    memset(&actions.mark, 0xFF, sizeof actions.mark);

    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    fwd.type = DOCA_FLOW_FWD_RSS;
    fwd.rss_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
    memset(&fwd.rss.nr_queues, 0xFF, sizeof fwd.rss.nr_queues);

    rv = ovs_doca_pipe_create(&dev->common.up, &match, NULL, &monitor,
                              &actions, &actions, NULL, &fwd, NULL,
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
    struct netdev_dpdk_common *common = &dev->common;
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;
    dpdk_port_t port_id = common->port_id;
    struct ovs_doca_flow_actions actions;
    struct doca_flow_pipe_entry *entry;
    struct ovs_doca_flow_match match;
    unsigned int num_of_queues;
    struct doca_flow_fwd fwd;
    uint16_t *rss_queues;
    int ret;

    num_of_queues = esw->n_rxq;
    ovs_assert(num_of_queues > 0);

    rss_queues = xcalloc(num_of_queues, sizeof *rss_queues);
    for (int i = 0; i < num_of_queues; i++) {
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
    actions.mark = htonl(port_id);

    for (int i = 0; i < NETDEV_DOCA_RSS_NUM_ENTRIES; i++) {
        struct rss_match_type match_type = netdev_doca_rss_match_type(i);

        match.d.parser_meta.outer_l3_type = match_type.l3_type;
        match.d.parser_meta.outer_l4_type = match_type.l4_type;
        fwd.rss.outer_flags = netdev_doca_rss_flags(i);

        ret = ovs_doca_add_entry(&common->up, AUX_QUEUE, esw->rss_pipe, &match,
                                 &actions, NULL, &fwd,
                                 DOCA_FLOW_ENTRY_FLAGS_NO_WAIT, &entry);
        if (ret != DOCA_SUCCESS) {
            VLOG_ERR("%s: Failed to create '%s' rss entry. Error: %d (%s)",
                     netdev_get_name(&common->up), netdev_doca_stats_name(i),
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
    if (ret != DOCA_SUCCESS) {
        VLOG_ERR("%s: Failed to create meta-tag0 rule. Error: %d (%s)",
                 netdev_get_name(netdev), ret, doca_error_get_descr(ret));
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
    int err;

    memset(&miss, 0, sizeof miss);
    memset(&fwd, 0, sizeof fwd);

    miss.type = DOCA_FLOW_FWD_PIPE;
    miss.next_pipe = dev->esw_ctx->meta_tag0_pipe;

    err = doca_flow_get_target(DOCA_FLOW_TARGET_KERNEL, &kernel_target);
    if (err != DOCA_SUCCESS) {
        VLOG_ERR("%s: Could not get miss to kernel target. Error: %d (%s)",
                 netdev_get_name(netdev), err, doca_error_get_descr(err));
        return err;
    }

    fwd.type = DOCA_FLOW_FWD_TARGET;
    fwd.target = kernel_target;

    return ovs_doca_pipe_create(netdev, &match, NULL, NULL, NULL, NULL, NULL,
                                &fwd, &miss, PRE_MISS_N_TYPES, false,
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

    for (int i = 0; i < PRE_MISS_N_TYPES; i++) {
        pentry = &dev->esw_ctx->pre_miss_entries[i];

        match.d.outer.eth.type = htons(pre_miss_mapping[i]);
        ret = ovs_doca_add_entry(netdev, AUX_QUEUE,
                                 dev->esw_ctx->pre_miss_pipe, &match, NULL,
                                 NULL, NULL, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT,
                                 pentry);
        if (ret != DOCA_SUCCESS) {
            VLOG_ERR("%s: Failed to create pre_miss %x rule. Error: %d (%s)",
                     netdev_get_name(netdev), pre_miss_mapping[i],
                     ret, doca_error_get_descr(ret));
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

    for (int i = 0; i < PRE_MISS_N_TYPES; i++) {
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
    struct netdev_dpdk_common *common = &dev->common;
    dpdk_port_t port_id = common->port_id;
    struct ovs_doca_flow_match match;
    struct doca_flow_fwd fwd;
    int ret;

    memset(&match, 0, sizeof match);
    memset(&fwd, 0, sizeof fwd);

    match.d.meta.pkt_meta = (OVS_FORCE doca_be32_t) DOCA_HTOBE32(port_id);

    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = port_id;

    ret = ovs_doca_add_entry(&common->up, AUX_QUEUE, pipe, &match, NULL, NULL,
                             &fwd, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT,
                             &dev->egress_entry);
    if (ret != DOCA_SUCCESS) {
        VLOG_ERR("Failed to create egress pipe entry. Error: %d (%s)", ret,
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

#define ESW_INIT_CMD(func)                                                \
    do {                                                                  \
        rv = (func)(netdev);                                              \
        if (!rv) {                                                        \
            break;                                                        \
        }                                                                 \
        VLOG_ERR("%s: eSwitch initialization failed, %s() with error: "   \
                 "%d (%s)", netdev_get_name(netdev), #func, rv,           \
                  doca_error_get_descr(rv));                              \
        return rv;                                             \
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

                while (true) {
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
}

static int
netdev_doca_esw_init(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_dpdk_common *common = &dev->common;
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;
    uint16_t pid;
    int rv;

    esw->esw_port = dev->port;
    esw->esw_netdev = netdev;
    esw->port_id = common->port_id;
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
                              common->socket_id);
        if (!esw->port_queues[pid]) {
            VLOG_ERR("%s: port_queues alloc failed for pid=%d",
                     netdev_get_name(netdev), pid);
            rv = ENOMEM;
            goto err;
        }

        for (qid = 0; qid < esw->n_rxq; qid++) {
            char *ring_name;

            ring_name = xasprintf("%s-%d-%d", netdev_get_name(netdev), pid,
                                  qid);
            if (strlen(ring_name) >= RTE_RING_NAMESIZE) {
                VLOG_ERR("%s: ring_name too long for pid=%d qid=%d",
                         netdev_get_name(netdev), pid, qid);
                free(ring_name);
                rv = ENAMETOOLONG;
                goto err;
            }

            esw->port_queues[pid][qid].ring =
                rte_ring_create(ring_name, NETDEV_MAX_BURST * 2,
                                common->socket_id,
                                RING_F_SC_DEQ | RING_F_SP_ENQ);
            free(ring_name);
            if (!esw->port_queues[pid][qid].ring) {
                VLOG_ERR("%s: ring creation failed for pid=%d qid=%d",
                         netdev_get_name(netdev), pid, qid);
                rv = ENOMEM;
                goto err;
            }

            atomic_init(&esw->port_queues[pid][qid].n_packets, 0);
            atomic_init(&esw->port_queues[pid][qid].n_bytes, 0);
        }
    }

    return 0;

err:
    netdev_doca_esw_port_uninit(netdev);
    return rv;
}

static int
get_sysfs_attr(const char *prefix, const char *devname, const char *suffix,
               char *outp, size_t maxlen)
{
    char str[PATH_MAX];
    size_t len;
    FILE *fp;
    char *p;
    int n;

    ovs_assert(prefix && devname && suffix);

    n = snprintf(str, sizeof str, "/sys/%s/%s/%s", prefix, devname, suffix);
    if (!(n >= 0 && n < sizeof str)) {
        VLOG_DBG("snprintf overflow for %s/%s/%s", prefix, devname,
                 suffix);
        return ENOSPC;
    }

    fp = fopen(str, "r");
    if (!fp) {
        VLOG_DBG("fopen failed for %s", str);
        return errno;
    }

    p = fgets(str, sizeof str, fp);
    fclose(fp);

    if (!p) {
        VLOG_DBG("fgets failed for %s", str);
        return EIO;
    }

    /* 'fgets' terminates the string with \n.  Passing 'len', which
     * includes the \n, as the size to ovs_strlcpy() causes it to copy
     * len-1 characters, dropping the newline. */
    if (outp) {
        len = strnlen(str, maxlen);
        if (maxlen <= len) {
            VLOG_DBG("maxlen exceeded for /%s/%s/%s", prefix, devname, suffix);
            return ERANGE;
        }
        ovs_strlcpy(outp, str, len);
    }

    return 0;
}

static int
get_phys_port_name(const char *devname, char *outp, size_t maxlen)
{
    return get_sysfs_attr("class/net", devname, "phys_port_name", outp,
                          maxlen);
}

static int
get_bonding_slaves(const char *devname, char *outp, size_t maxlen)
{
    return get_sysfs_attr("class/net", devname, "bonding/slaves", outp,
                          maxlen);
}

static doca_error_t
dev_get_rep(const char *name, struct doca_devinfo *devinfo, bool *found)
{
    char dev_name[DOCA_DEVINFO_IFACE_NAME_SIZE];
    struct doca_devinfo_rep **dev_list_rep;
    doca_error_t err = DOCA_SUCCESS;
    struct doca_dev *ddev;
    uint32_t nb_devs_rep;
    doca_error_t ret;

    ret = doca_dev_open(devinfo, &ddev);
    if (ret != DOCA_SUCCESS) {
        VLOG_ERR("%s: Failed to open device. Error: %d (%s)", name, ret,
                 doca_error_get_descr(ret));
        return ret;
    }

    ret = doca_devinfo_rep_create_list(ddev, DOCA_DEVINFO_REP_FILTER_NET,
                                       &dev_list_rep, &nb_devs_rep);
    if (ret != DOCA_SUCCESS) {
        VLOG_ERR("%s: Failed to create a rep list. Error: %d (%s)", name, ret,
                 doca_error_get_descr(ret));
        err = ret;
        goto out;
    }

    for (int i = 0; i < nb_devs_rep; i++) {
        ret = doca_devinfo_rep_get_iface_name(dev_list_rep[i], dev_name,
                                              sizeof dev_name);
        if (ret != DOCA_SUCCESS) {
            VLOG_ERR("%s: Failed to get rep iface name. Error: %d (%s)", name,
                     ret, doca_error_get_descr(ret));
            err = ret;
            break;
        }

        if (!strcmp(name, dev_name)) {
            *found = true;
            break;
        }
    }

    ret = doca_devinfo_rep_destroy_list(dev_list_rep);
    if (ret != DOCA_SUCCESS) {
        VLOG_ERR("%s: Failed to destroy rep list. Error: %d (%s)", name, ret,
                 doca_error_get_descr(ret));
        if (err == DOCA_SUCCESS) {
            err = ret;
        }
    }

out:
    ret = doca_dev_close(ddev);
    if (ret != DOCA_SUCCESS) {
        VLOG_ERR("%s: Failed to close dev. Error: %d (%s)", name, ret,
                 doca_error_get_descr(ret));
        if (err == DOCA_SUCCESS) {
            err = ret;
        }
    }

    return err;
}

static int
get_doca_dev_pci(const char *name, char *pci, size_t maxlen, bool *is_rep)
{
    struct doca_devinfo **dev_list;
    bool found = false;
    uint32_t nb_devs;
    doca_error_t ret;

    ovs_assert(maxlen > PCI_PRI_STR_SIZE);

    ret = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (ret != DOCA_SUCCESS) {
        VLOG_ERR("%s: Failed to create a dev list. Error: %d (%s)", name, ret,
                 doca_error_get_descr(ret));
        return ret;
    }

    /* Traverse the list of devices.
     * 1. If the device is not an ESW, continue.
     * 2. If the device name is what we look for, done.
     * 3. If not, try to find in the representors of this ESW.
     */
    for (int i = 0; i < nb_devs; i++) {
        char dev_name[DOCA_DEVINFO_IFACE_NAME_SIZE];
        uint8_t net_supported;

        /* If not an ESW, continue. */
        ret = doca_devinfo_rep_cap_is_filter_net_supported(dev_list[i],
                                                           &net_supported);
        if (ret != DOCA_SUCCESS) {
            VLOG_ERR("%s: Failed to check rep_cap. Error: %d (%s)", name, ret,
                     doca_error_get_descr(ret));
            goto out;
        }

        if (!net_supported) {
            continue;
        }

        ret = doca_devinfo_get_pci_addr_str(dev_list[i], pci);
        if (ret != DOCA_SUCCESS) {
            VLOG_ERR("%s: Failed to get pci. Error: %d (%s)", name, ret,
                     doca_error_get_descr(ret));
            goto out;
        }

        ret = doca_devinfo_get_iface_name(dev_list[i], dev_name,
                                          sizeof dev_name);
        if (ret != DOCA_SUCCESS) {
            VLOG_ERR("%s: Failed to get iface name. Error: %d (%s)", name, ret,
                     doca_error_get_descr(ret));
            goto out;
        }

        if (!strcmp(name, dev_name)) {
            found = true;
            *is_rep = false;
            break;
        }

        /* Search in its representor devices. */
        ret = dev_get_rep(name, dev_list[i], &found);
        if (ret != DOCA_SUCCESS) {
            goto out;
        }

        if (found) {
            *is_rep = true;
            break;
        }
    }

    if (!found) {
        ret = DOCA_ERROR_NOT_FOUND;
        VLOG_WARN("%s: Not found. Error: %d (%s)", name, ret,
                  doca_error_get_descr(ret));
    }

out:
    doca_devinfo_destroy_list(dev_list);
    return ret;
}

static int
get_phys_iface_name(const char *name, char iface[IFNAMSIZ])
{
    char phys_port_name[IFNAMSIZ];
    char slaves[PATH_MAX];
    char *save_ptr;
    char *lower;

    /* In case the device is a bond, there is a lower_p0 symbolic link, with
     * the format of ../../.../<lower-dev>.  Extract the lower device.  */
    if (get_bonding_slaves(name, slaves, sizeof slaves)) {
        goto fallback;
    }

    lower = strtok_r(slaves, " ", &save_ptr);
    while (lower) {
        if (!get_phys_port_name(lower, phys_port_name,
                                sizeof phys_port_name)
            && !strcmp(phys_port_name, "p0")) {
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

struct netdev_doca *
netdev_doca_cast(const struct netdev *netdev)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);

    return CONTAINER_OF(common, struct netdev_doca, common);
}

/* Allocates an area of 'sz' bytes from DPDK.  The memory is zero'ed.
 *
 * Unlike xmalloc(), this function can return NULL on failure. */
static void *
doca_rte_zmalloc(const char *type, size_t sz)
{
    return rte_zmalloc(type, sz, CACHE_LINE_SIZE);
}

static struct netdev *
netdev_doca_alloc(void)
{
    struct netdev_doca *dev;

    dev = doca_rte_zmalloc("ovs_doca_netdev", sizeof *dev);
    if (!dev) {
        return NULL;
    }

    /* Upon the first port disable dpdk steering to allow doca to work. */
    if (!atomic_count_inc(&n_doca_ports)) {
        rte_pmd_mlx5_disable_steering();
    }

    return &dev->common.up;
}

static void
netdev_doca_dealloc(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    unsigned int old_count;

    /* Upon the last doca port going down, enable back dpdk steering. */
    old_count = atomic_count_dec(&n_doca_ports);
    ovs_assert(old_count > 0);

    if (old_count == 1) {
        rte_pmd_mlx5_enable_steering();
    }

    rte_free(dev);
}

static int
netdev_doca_set_mtu(struct netdev *netdev, int mtu)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);

    ovs_mutex_lock(&common->mutex);
    if (common->requested_mtu != mtu) {
        if (!netdev_doca_is_esw_mgr(netdev)) {
            VLOG_WARN("%s: setting requested MTU %d is ignored for "
                      "representor", netdev_get_name(netdev), mtu);
            goto out;
        }

        common->requested_mtu = mtu;
        netdev_request_reconfigure(netdev);
    }

out:
    ovs_mutex_unlock(&common->mutex);

    return 0;
}


static int
netdev_doca_dev_open_pci(struct rte_pci_addr *rte_pci, struct doca_dev **pdev)
{
    struct doca_devinfo **dev_list;
    char pci[PCI_PRI_STR_SIZE];
    uint8_t is_esw_manager = 0;
    uint8_t is_addr_equal = 0;
    uint32_t nb_devs;
    int res;

    /* Set default return value. */
    *pdev = NULL;

    res = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (res != DOCA_SUCCESS) {
        VLOG_ERR("Failed to load doca devices list. Error: %d (%s)",
                 res, doca_error_get_descr(res));
        return res;
    }

    rte_pci_device_name(rte_pci, pci, sizeof pci);
    for (int i = 0; i < nb_devs; i++) {
        res = doca_devinfo_is_equal_pci_addr(dev_list[i], pci, &is_addr_equal);
        if (res != DOCA_SUCCESS || !is_addr_equal) {
            continue;
        }

        res = doca_dpdk_cap_is_rep_port_supported(dev_list[i],
                                                  &is_esw_manager);
        if (res != DOCA_SUCCESS || !is_esw_manager) {
            continue;
        }

        VLOG_DBG("Opening '%s'", pci);
        res = doca_dev_open(dev_list[i], pdev);
        if (res != DOCA_SUCCESS) {
            VLOG_ERR("Failed to open DOCA device. Error: %d (%s)",
                     res, doca_error_get_descr(res));
        }

        goto out;
    }

    VLOG_WARN("No DOCA device found for PCI address %s", pci);
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
netdev_doca_esw_ctx_dump(struct ds *s, void *key_, void *ctx OVS_UNUSED)
{
    struct netdev_doca_esw_key *key = key_;
    char pci_addr[PCI_PRI_STR_SIZE];

    rte_pci_device_name(&key->rte_pci, pci_addr, sizeof pci_addr);
    ds_put_format(s, "pci=%s", pci_addr);

    return s;
}

static int
netdev_doca_class_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static struct netdev_dpdk_watchdog_params watchdog_params = {
        .mutex = &doca_mutex,
        .list = &doca_list,
    };

    if (!ovsthread_once_start(&once)) {
        return 0;
    }

    ovs_thread_create("doca_watchdog", netdev_dpdk_watchdog, &watchdog_params);
    netdev_doca_esw_rfm = refmap_create("netdev-doca-esw",
                                        sizeof(struct netdev_doca_esw_key),
                                        sizeof(struct netdev_doca_esw_ctx),
                                        netdev_doca_esw_ctx_init,
                                        netdev_doca_esw_ctx_uninit,
                                        netdev_doca_esw_ctx_dump);

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
        VLOG_ERR("Device argument parsing failed for %s", devargs);
        return EINVAL;
    }

    if (rte_pci_addr_parse(da.name, rte_pci)) {
        VLOG_ERR("PCI address parsing failed for %s, devargs %s", da.name,
                 devargs);
        rv = EINVAL;
    }

    rte_devargs_reset(&da);
    return rv;
}

/* Changing the netdev of the ESW require changes of its representor ports.
 * This helper traverses them with a callback to run on each representor.
 * For each representor, request a reconfigure of it. */
static void
netdev_doca_do_foreach_representor(struct netdev_doca *esw_dev,
                                   bool (*cb)(struct netdev_doca *))
    OVS_REQUIRES(doca_mutex)
{
    bool need_reconfigure = false;
    struct rte_pci_addr esw_pci;
    struct rte_pci_addr rep_pci;
    struct netdev_doca *dev;

    if (netdev_doca_parse_dpdk_devargs_pci(esw_dev->common.devargs,
                                           &esw_pci)) {
        return;
    }

    LIST_FOR_EACH (dev, common.list_node, &doca_list) {
        if (esw_dev == dev) {
            continue;
        }

        if (!dev->common.devargs ||
            netdev_doca_parse_dpdk_devargs_pci(dev->common.devargs,
                                               &rep_pci)) {
            continue;
        }

        if (rte_pci_addr_cmp(&rep_pci, &esw_pci)) {
            continue;
        }

        ovs_mutex_lock(&dev->common.mutex);
        need_reconfigure |= cb(dev);
        ovs_mutex_unlock(&dev->common.mutex);
        netdev_request_reconfigure(&dev->common.up);
    }

    if (need_reconfigure) {
        /* If a representor is reconfigured a result of its ESW manager
         * change, it might not be synced in the bridge's database.  Signal it
         * to reconfigure, to make it right.
         */
        rtnetlink_report_link();
    }
}

static void
netdev_doca_dev_close(struct netdev_doca *dev)
{
    struct netdev_dpdk_common *common = &dev->common;
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;
    struct rte_eth_dev_info dev_info;
    char *pci_addr;
    bool last;
    int err;

    memset(&dev_info, 0, sizeof dev_info);

    if (rte_eth_dev_is_valid_port(common->port_id)) {
        err = rte_eth_dev_info_get(common->port_id, &dev_info);
        if (err) {
            VLOG_ERR("Failed to get info of port "DPDK_PORT_ID_FMT": %s",
                     common->port_id, rte_strerror(-err));
        }

        err = rte_eth_dev_close(common->port_id);
        if (err) {
            VLOG_ERR("Failed to close port "DPDK_PORT_ID_FMT": %s",
                     common->port_id, rte_strerror(-err));
        }
    }

    if (!esw) {
        return;
    }

    pci_addr = xstrdup(esw->pci_addr);
    if (common->port_id != dev->esw_mgr_port_id && dev->dev_rep) {
        VLOG_DBG("%s: Closing doca dev_rep for port_id "DPDK_PORT_ID_FMT
                 ". %p", netdev_get_name(&common->up),
                 common->port_id, dev->dev_rep);
        err = doca_dev_rep_close(dev->dev_rep);
        if (err != DOCA_SUCCESS) {
            VLOG_ERR("Failed to close doca dev_rep with port id "
                     DPDK_PORT_ID_FMT". Error: %d (%s)",
                     common->port_id, err, doca_error_get_descr(err));
        }

        dev->dev_rep = NULL;
    }

    last = refmap_unref(netdev_doca_esw_rfm, esw);
    /* The last is the ESW. */
    if (last && esw->dev) {
        if (dev_info.device) {
            /* The esw->cmd_fd is closed inside. */
            err = rte_dev_remove(dev_info.device);
            if (err) {
                VLOG_ERR("Failed to remove device %s: %s", common->devargs,
                         rte_strerror(-err));
            }
            esw->cmd_fd = -1;
        }

        VLOG_DBG("Closing '%s'", pci_addr);
        err = doca_dev_close(esw->dev);
        if (err != DOCA_SUCCESS) {
            VLOG_ERR("Failed to close doca dev %s. Error: %d (%s)", pci_addr,
                     err, doca_error_get_descr(err));
        }

        esw->dev = NULL;
        if (esw->cmd_fd != -1) {
            close(esw->cmd_fd);
        } else {
            esw->cmd_fd = -1;
        }
    }

    dev->esw_ctx = NULL;
    free(pci_addr);
}

static bool
netdev_doca_rep_stop(struct netdev_doca *dev)
    OVS_REQUIRES(doca_mutex)
{
    struct netdev_dpdk_common *common = &dev->common;

    if (!dpdk_dev_is_started(common)) {
        return false;
    }

    netdev_doca_port_stop(&common->up);
    netdev_doca_dev_close(dev);
    common->port_id = DPDK_ETH_PORT_ID_INVALID;
    dev->esw_mgr_port_id = DPDK_ETH_PORT_ID_INVALID;
    common->attached = false;

    return true;
}

static int
netdev_doca_port_stop(struct netdev *netdev)
    OVS_REQUIRES(doca_mutex)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_dpdk_common *common = &dev->common;
    bool started = dpdk_dev_is_started(common);
    int err = 0;

    if (started) {
        if (netdev_doca_get_esw_mgr_port_id(netdev) == common->port_id) {
            netdev_doca_do_foreach_representor(dev, netdev_doca_rep_stop);
        }

        VLOG_INFO("%s: Stopping '%s', port_id="DPDK_PORT_ID_FMT,
                  netdev_get_name(netdev), common->devargs,
                  common->port_id);
        atomic_store(&common->started, false);
    }

    netdev_doca_rss_entries_uninit(netdev);
    netdev_doca_egress_entry_uninit(netdev);

    if (common->port_id == dev->esw_mgr_port_id) {
        netdev_doca_esw_port_uninit(netdev);
    }

    if (dev->port) {
        err = doca_flow_port_stop(dev->port);
        dev->port = NULL;
    }

    if (common->port_id != DPDK_ETH_PORT_ID_INVALID) {
        rte_eth_dev_stop(common->port_id);
    }

    netdev_doca_mempool_unconfigure(dev);

    return err;
}

static void
common_destruct(struct netdev_doca *dev)
    OVS_REQUIRES(doca_mutex)
    OVS_EXCLUDED(dev->common.mutex)
{
    struct netdev_dpdk_common *common = &dev->common;

    rte_free(common->tx_q);
    ovs_list_remove(&common->list_node);
    free(dev->sw_tx_stats);
    free(common->sw_stats);
    ovs_mutex_destroy(&common->mutex);
}

static void
netdev_doca_destruct(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_dpdk_common *common = &dev->common;

    ovs_mutex_lock(&doca_mutex);

    netdev_doca_port_stop(netdev);

    if (common->attached) {
        netdev_doca_dev_close(dev);
        common->port_id = DPDK_ETH_PORT_ID_INVALID;

        VLOG_INFO("%s: Device '%s' has been removed", netdev_get_name(netdev),
                  common->devargs);
    }

    ovs_mutex_lock(&common->mutex);
    netdev_dpdk_clear_xstats(common);
    ovs_mutex_unlock(&common->mutex);
    free(common->devargs);
    common_destruct(dev);

    ovs_mutex_unlock(&doca_mutex);
}

static int
netdev_doca_get_sw_custom_stats(const struct netdev *netdev,
                                struct netdev_custom_stats *custom_stats)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_dpdk_common *common = &dev->common;
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

    ovs_mutex_lock(&common->mutex);

    rte_spinlock_lock(&common->stats_lock);
    i = 0;
#define SW_CSTAT(NAME) \
    custom_stats->counters[i++].value = common->sw_stats->NAME;
    SW_CSTATS;
#undef SW_CSTAT
    rte_spinlock_unlock(&common->stats_lock);

    ovs_mutex_unlock(&common->mutex);

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
    struct netdev_dpdk_common *common = &dev->common;
    dpdk_port_t port_id = common->port_id;
    struct doca_flow_resource_query stats;
    struct netdev_custom_counter *counter;
    uint64_t n_sw_packets, n_sw_bytes;
    uint64_t n_packets, n_bytes;
    int n_txq = netdev->n_txq;
    unsigned int n_rxq;
    int sw_stats_size;
    enum {
        PACKETS,
        BYTES,
    };
    int err;

    if (!dpdk_dev_is_started(common)) {
        return EAGAIN;
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

    for (int i = 0; i < NETDEV_DOCA_RSS_NUM_ENTRIES; i++, counter += 2) {
        const char *stats_name = netdev_doca_stats_name(i);

        err = doca_flow_resource_query_entry(dev->rss_entries[i], &stats);
        if (err != DOCA_SUCCESS) {
            VLOG_ERR("%s: Failed to query '%s' RSS entry %d. Error: %d (%s)",
                     common->devargs, stats_name, i, err,
                     doca_error_get_descr(err));
            return err;
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

    for (int i = 0; i < n_rxq; i++, counter += 2) {
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

    for (int i = 0; i < n_txq; i++, counter += 2) {
        atomic_read_relaxed(&dev->sw_tx_stats[i].n_packets, &n_packets);
        atomic_read_relaxed(&dev->sw_tx_stats[i].n_bytes, &n_bytes);

        counter[PACKETS].value = n_packets;
        snprintf(counter[PACKETS].name, NETDEV_CUSTOM_STATS_NAME_SIZE,
                 "tx_q%d_packets", i);
        counter[BYTES].value = n_bytes;
        snprintf(counter[BYTES].name, NETDEV_CUSTOM_STATS_NAME_SIZE,
                 "tx_q%d_bytes", i);
    }

    return 0;
}

static int
netdev_doca_get_status(const struct netdev *netdev, struct smap *args)
{
    return netdev_dpdk_get_eth_dev_status(netdev, &doca_mutex, args);
}

/* Mempools are allocated for ESW managers only.
 * Estimation of number of mbufs required for this port:
 * (<packets required to fill the device rxqs>
 *  + <packets that could be stuck on other ports txqs>
 *  + <packets in the pmd threads>
 *  + <headroom for per-lcore mempool caches>). */
static uint32_t
doca_calculate_mbufs(struct netdev_doca *dev)
{
    struct netdev_dpdk_common *common = &dev->common;

    /* The main thread may allocate packets from the mempool, filling its
     * per-lcore mempool cache, thus +1. */
    return common->requested_n_rxq * common->requested_rxq_size
           + common->requested_n_txq * common->requested_txq_size
           + MIN(RTE_MAX_LCORE, common->requested_n_rxq) * NETDEV_MAX_BURST
           + MIN(RTE_MAX_LCORE, 1 + common->requested_n_rxq) * MP_CACHE_SZ;
}

static int
doca_mp_full(const struct rte_mempool *mp)
    OVS_REQUIRES(doca_mp_mutex)
{
    /* At this point we want to know if all the mbufs are back
     * in the mempool. rte_mempool_full() is not atomic but it's
     * the best available and as we are no longer requesting mbufs
     * from the mempool, it means mbufs will not move from
     * 'mempool ring' --> 'mempool cache'.  In rte_mempool_full()
     * the ring is counted before caches, so we won't get false
     * positives in this use case and we handle false negatives.
     *
     * If future implementations of rte_mempool_full() were to change
     * it could be possible for a false positive.  Even that would
     * likely be ok, as there are additional checks during mempool
     * freeing but it would make things racey. */
    return rte_mempool_full(mp);
}

/* Free unused mempools. */
static void
doca_mp_sweep(void)
    OVS_EXCLUDED(doca_mp_mutex)
{
    struct doca_mp *dmp;

    ovs_mutex_lock(&doca_mp_mutex);

    LIST_FOR_EACH_SAFE (dmp, list_node, &doca_mp_list) {
        if (dmp->dead && doca_mp_full(dmp->mp)) {
            VLOG_DBG("Freeing mempool \"%s\"", dmp->mp->name);
            ovs_list_remove(&dmp->list_node);
            rte_mempool_free(dmp->mp);
            rte_free(dmp);
        }
    }

    ovs_mutex_unlock(&doca_mp_mutex);
}

static void
netdev_doca_mempool_unconfigure(struct netdev_doca *dev)
{
    struct netdev_dpdk_common *common = &dev->common;

    if (!netdev_doca_is_esw_mgr(&common->up) || !dev->doca_mp) {
        return;
    }

    dev->doca_mp->dead = true;

    doca_mp_sweep();
}

static int
netdev_doca_mempool_configure(struct netdev_doca *dev)
    OVS_REQUIRES(dev->common.mutex)
{
    struct netdev_dpdk_common *common = &dev->common;
    uint32_t buf_size = netdev_dpdk_buf_size(common->requested_mtu);
    const char *netdev_name = netdev_get_name(&common->up);
    int socket_id = common->requested_socket_id;
    struct doca_mp *dmp;
    uint32_t mbuf_size;
    uint32_t n_mbufs;
    int mtu;

    if (!netdev_doca_is_esw_mgr(&common->up)) {
        struct netdev_doca *esw_dev;

        esw_dev = netdev_doca_cast(dev->esw_ctx->esw_netdev);

        common->mp = esw_dev->common.mp;
        common->mtu = esw_dev->common.mtu;
        common->requested_mtu = common->mtu;
        common->max_packet_len = esw_dev->common.max_packet_len;
        return 0;
    }

    mtu = FRAME_LEN_TO_MTU(buf_size);
    mbuf_size = MTU_TO_FRAME_LEN(mtu);
    n_mbufs = doca_calculate_mbufs(dev);

    /* Sweep mempools before create. */
    doca_mp_sweep();

    dmp = doca_rte_zmalloc("dmp", sizeof *dmp);
    if (!dmp) {
        return ENOMEM;
    }

    dmp->mp = netdev_dpdk_mp_create_pool(netdev_name, n_mbufs, mbuf_size,
                                         socket_id);
    if (!dmp->mp) {
        VLOG_ERR("%s: Failed to create mempool", netdev_name);
        return ENOMEM;
    }

    VLOG_DBG("%s: Allocated a mempool of %u mbufs of size %u "
             "on socket %d with %d Rx and %d Tx queues, "
             "cache line size of %u",
             netdev_name, n_mbufs, mbuf_size, socket_id,
             common->requested_n_rxq, common->requested_n_txq,
             RTE_CACHE_LINE_SIZE);
    common->mp = dmp->mp;
    dev->doca_mp = dmp;
    common->mtu = common->requested_mtu;
    common->socket_id = common->requested_socket_id;
    common->max_packet_len = MTU_TO_FRAME_LEN(common->mtu);

    ovs_mutex_lock(&doca_mp_mutex);
    ovs_list_push_back(&doca_mp_list, &dmp->list_node);
    ovs_mutex_unlock(&doca_mp_mutex);

    return 0;
}

static int
doca_eth_dev_port_config_complete(struct netdev_doca *dev,
                                  int n_rxq, int n_txq)
{
    struct netdev_dpdk_common *common = &dev->common;
    uint16_t conf_mtu;
    int diag;

    free(dev->sw_tx_stats);
    dev->sw_tx_stats = xcalloc(n_txq, sizeof *dev->sw_tx_stats);
    for (int i = 0; i < n_txq; i++) {
        atomic_init(&dev->sw_tx_stats[i].n_packets, 0);
        atomic_init(&dev->sw_tx_stats[i].n_bytes, 0);
    }

    common->up.n_rxq = n_rxq;
    common->up.n_txq = n_txq;

    diag = rte_eth_dev_set_mtu(common->port_id, common->mtu);
    if (diag) {
        /* A device may not support rte_eth_dev_set_mtu, in this case
         * flag a warning to the user and include the devices configured
         * MTU value that will be used instead. */
        if (-ENOTSUP == diag) {
            rte_eth_dev_get_mtu(common->port_id, &conf_mtu);
            VLOG_WARN("Interface %s does not support MTU configuration, "
                      "max packet size supported is %"PRIu16".",
                      common->up.name, conf_mtu);
        } else {
            VLOG_ERR("Interface %s MTU (%d) setup error: %s",
                     common->up.name, common->mtu, rte_strerror(-diag));
        }
    }

    return diag;
}

static int
doca_eth_dev_port_config(struct netdev_doca *dev,
                         const struct rte_eth_dev_info *info,
                         int n_rxq, int n_txq)
{
    struct netdev_dpdk_common *common = &dev->common;
    struct rte_eth_conf conf = port_conf;
    int diag = 0;
    int i;

    netdev_dpdk_build_port_conf(common, info, &conf);

    if (!netdev_doca_is_esw_mgr(&common->up)) {
        rte_eth_dev_configure(common->port_id, 0, 0, &conf);
        return doca_eth_dev_port_config_complete(dev, n_rxq, n_txq);
    }

    /* A device may report more queues than it makes available (this has
     * been observed for Intel xl710, which reserves some of them for
     * SRIOV):  rte_eth_*_queue_setup will fail if a queue is not
     * available.  When this happens we can retry the configuration
     * and request less queues. */
    while (n_rxq && n_txq) {
        if (diag) {
            VLOG_INFO("Retrying setup with (rxq:%d txq:%d)", n_rxq, n_txq);
        }

        diag = rte_eth_dev_configure(common->port_id, n_rxq,
                                     n_txq, &conf);
        if (diag) {
            VLOG_WARN("Interface %s eth_dev setup error %s",
                      common->up.name, rte_strerror(-diag));
            break;
        }

        for (i = 0; i < n_txq; i++) {
            diag = rte_eth_tx_queue_setup(common->port_id, i, common->txq_size,
                                          common->socket_id, NULL);
            if (diag) {
                VLOG_INFO("Interface %s unable to setup txq(%d): %s",
                          common->up.name, i, rte_strerror(-diag));
                break;
            }
        }

        if (i != n_txq) {
            /* Retry with less tx queues. */
            n_txq = i;
            continue;
        }

        for (i = 0; i < n_rxq; i++) {
            diag = rte_eth_rx_queue_setup(common->port_id, i, common->rxq_size,
                                          common->socket_id, NULL,
                                          common->mp);
            if (diag) {
                VLOG_INFO("Interface %s unable to setup rxq(%d): %s",
                          common->up.name, i, rte_strerror(-diag));
                break;
            }
        }

        if (i != n_rxq) {
            /* Retry with less rx queues. */
            n_rxq = i;
            continue;
        }

        return doca_eth_dev_port_config_complete(dev, n_rxq, n_txq);
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
    const char *netdev_name = netdev_get_name(&dev->common.up);
    struct ds rte_devargs = DS_EMPTY_INITIALIZER;
    struct netdev_doca_esw_ctx_arg ctx_arg;
    struct netdev_doca_esw_key esw_key;
    struct ibv_pd *pd;
    int rv = 0;

    ovs_assert(!dev->esw_ctx);

    if (netdev_doca_esw_key_parse(devargs, &esw_key)) {
        VLOG_ERR("%s: ESW key parsing failed for %s", netdev_name, devargs);
        return EINVAL;
    }

    ctx_arg = (struct netdev_doca_esw_ctx_arg) {
        .esw_key = &esw_key,
        .dev = dev,
    };

    dev->esw_ctx = refmap_ref(netdev_doca_esw_rfm, &esw_key, &ctx_arg);
    if (!dev->esw_ctx) {
        VLOG_ERR("%s: Could not get esw context for %s", netdev_name, devargs);
        return EINVAL;
    }

    if (doca_rdma_bridge_get_dev_pd(dev->esw_ctx->dev, &pd)) {
        VLOG_ERR("%s: Could not get pd for %s", netdev_name, devargs);
        rv = EINVAL;
        goto out;
    }

    if (dev->esw_ctx->cmd_fd == -1) {
        dev->esw_ctx->cmd_fd = dup(pd->context->cmd_fd);
        if (dev->esw_ctx->cmd_fd == -1) {
            VLOG_ERR("%s: Could not dup fd for %s. Error %s", netdev_name,
                     devargs, ovs_strerror(errno));
            rv = EBADF;
            goto out;
        }
    }

    ds_put_format(&rte_devargs, "%s,cmd_fd=%d,pd_handle=%u", devargs,
                  dev->esw_ctx->cmd_fd, pd->handle);

    VLOG_DBG("Probing '%s'", ds_cstr(&rte_devargs));
    if (rte_dev_probe(ds_cstr(&rte_devargs))) {
        VLOG_ERR("%s: DPDK probe failed for %s", netdev_name,
                 ds_cstr(&rte_devargs));
        close(dev->esw_ctx->cmd_fd);
        dev->esw_ctx->cmd_fd = -1;
        rv = ENODEV;
        goto out;
    }

out:
    ds_destroy(&rte_devargs);
    if (rv) {
        /* In case of an error, rollback. */
        netdev_doca_dev_close(dev);
    }

    return rv;
}

static int
netdev_doca_port_start(struct netdev *netdev)
    OVS_REQUIRES(doca_mutex)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_dpdk_common *common = &dev->common;
    const char *devargs = common->devargs;
    dpdk_port_t port_id = common->port_id;
    struct doca_flow_port_cfg *port_cfg;
    struct netdev_doca_esw_ctx *esw;
    int err;

    if (!rte_eth_dev_is_valid_port(dev->esw_mgr_port_id)) {
        VLOG_ERR("Cannot start port "DPDK_PORT_ID_FMT" '%s', invalid ESW "
                 "port", port_id,
                 devargs);
        return DOCA_ERROR_NOT_FOUND;
    }

    err = doca_flow_port_cfg_create(&port_cfg);
    if (err != DOCA_SUCCESS) {
        VLOG_ERR("Failed to create doca flow port_cfg. Error: %d (%s)",
                 err, doca_error_get_descr(err));
        return err;
    }

    esw = dev->esw_ctx;
    if (!esw) {
        err = DOCA_ERROR_INVALID_VALUE;
        goto out;
    }

    err = doca_flow_port_cfg_set_port_id(port_cfg, port_id);
    if (err != DOCA_SUCCESS) {
        VLOG_ERR("%s: Failed to set doca flow port_cfg port_id "
                 DPDK_PORT_ID_FMT". Error: %d (%s)",
                 netdev_get_name(netdev), port_id, err,
                 doca_error_get_descr(err));
        goto out;
    }

    if (!netdev_doca_is_esw_mgr(netdev)) {
        err = doca_dpdk_open_dev_rep_by_port_id(port_id, esw->dev,
                                                &dev->dev_rep);
        if (err != DOCA_SUCCESS) {
            VLOG_ERR("%s: Failed to open doca dev_rep for port_id "
                     DPDK_PORT_ID_FMT". Error: %d (%s)",
                     netdev_get_name(netdev), port_id, err,
                     doca_error_get_descr(err));
            goto out;
        }

        VLOG_DBG("%s: Opening doca dev_rep for port_id "DPDK_PORT_ID_FMT
                 ". %p", netdev_get_name(netdev), port_id, dev->dev_rep);

        err = doca_flow_port_cfg_set_dev_rep(port_cfg, dev->dev_rep);
        if (err != DOCA_SUCCESS) {
            VLOG_ERR("%s: Failed to set doca flow port_cfg dev_rep. "
                     "Error: %d (%s)", netdev_get_name(netdev), err,
                     doca_error_get_descr(err));
            goto out;
        }
    }

    err = doca_flow_port_cfg_set_dev(port_cfg, esw->dev);
    if (err != DOCA_SUCCESS) {
        VLOG_ERR("%s: Failed to set doca flow port_cfg dev. Error: %d (%s)",
                 netdev_get_name(netdev), err, doca_error_get_descr(err));
        goto out;
    }

    VLOG_INFO("%s: Starting '%s', port_id="DPDK_PORT_ID_FMT,
              netdev_get_name(netdev), devargs, port_id);

    if (common->port_id == dev->esw_mgr_port_id) {
        err = doca_flow_port_cfg_set_actions_mem_size(
                port_cfg, NETDEV_DOCA_ACTIONS_MEM_SIZE);
        if (err != DOCA_SUCCESS) {
            VLOG_ERR("Failed set_actions_mem_size for port_id "
                     DPDK_PORT_ID_FMT". Error: %d (%s)",
                     common->port_id, err,
                     doca_error_get_descr(err));
            goto out;
        }

        err = rte_eth_dev_start(common->port_id);
        if (err) {
            VLOG_ERR("Failed to start dpdk port_id "DPDK_PORT_ID_FMT
                     ". Error: %s", common->port_id,
                     rte_strerror(-err));
            err = DOCA_ERROR_DRIVER;
            goto out;
        }

        err = doca_flow_port_cfg_set_nr_resources(port_cfg,
                                                  DOCA_FLOW_RESOURCE_COUNTER,
                                                  ovs_doca_max_counters());
        if (err != DOCA_SUCCESS) {
            VLOG_ERR("Failed set_nr_resources counters for port_id "
                     DPDK_PORT_ID_FMT". Error: %d (%s)",
                     common->port_id, err,
                     doca_error_get_descr(err));
            goto out;
        }
    }

    err = doca_flow_port_start(port_cfg, &dev->port);
    if (err != DOCA_SUCCESS) {
        VLOG_ERR("Failed to start doca flow port_id "DPDK_PORT_ID_FMT
                 ". Error: %d (%s)", port_id, err,
                 doca_error_get_descr(err));
        goto out;
    }

    if (common->port_id == dev->esw_mgr_port_id) {
        err = netdev_doca_esw_init(netdev);
        if (err) {
            goto out;
        }
    }

    err = netdev_doca_egress_entry_init(dev);
    if (err != DOCA_SUCCESS) {
        goto out;
    }

    err = netdev_doca_rss_entries_init(netdev);
    if (err != DOCA_SUCCESS) {
        goto out;
    }

out:
    doca_flow_port_cfg_destroy(port_cfg);
    if (err) {
        netdev_doca_port_stop(netdev);
    }

    return err;
}

static bool
netdev_doca_rep_reconfigure(struct netdev_doca *dev OVS_UNUSED)
{
    return true;
}

static int
doca_eth_dev_init(struct netdev_doca *dev)
    OVS_REQUIRES(doca_mutex)
    OVS_REQUIRES(dev->common.mutex)
{
    struct netdev_dpdk_common *common = &dev->common;
    struct netdev *netdev = &common->up;
    struct rte_ether_addr eth_addr;
    struct rte_eth_dev_info info;
    int n_rxq, n_txq;
    int diag;

    diag = rte_eth_dev_info_get(common->port_id, &info);
    if (diag < 0) {
        VLOG_ERR("Interface %s rte_eth_dev_info_get error: %s",
                 common->up.name, rte_strerror(-diag));
        return -diag;
    }

    common->is_representor = common->devargs
        && strstr(common->devargs, "representor=");

    netdev_dpdk_detect_hw_ol_features(&dev->common, &info);

    n_rxq = MIN(info.max_rx_queues, common->up.n_rxq);
    n_txq = MIN(info.max_tx_queues, common->up.n_txq);

    diag = doca_eth_dev_port_config(dev, &info, n_rxq, n_txq);
    if (diag) {
        VLOG_ERR("Interface %s(rxq:%d txq:%d lsc interrupt mode:%s) "
                 "configure error: %s",
                 common->up.name, n_rxq, n_txq,
                 common->lsc_interrupt_mode ? "true" : "false",
                 rte_strerror(-diag));
        return -diag;
    }

    common->attached = true;
    diag = netdev_doca_port_start(netdev);
    if (diag) {
        VLOG_ERR("Failed to init DOCA port %s port_id "DPDK_PORT_ID_FMT
                 ". Error: %d (%s)", netdev_get_name(netdev),
                 common->port_id, diag, doca_error_get_descr(diag));
        return diag;
    }

    atomic_store(&common->started, true);

    netdev_dpdk_configure_xstats(&dev->common);

    memset(&eth_addr, 0x0, sizeof(eth_addr));
    rte_eth_macaddr_get(common->port_id, &eth_addr);

    VLOG_DBG_RL(&rl, "Port %d: "ETH_ADDR_FMT,
                common->port_id, ETH_ADDR_BYTES_ARGS(eth_addr.addr_bytes));

    memcpy(common->hwaddr.ea, eth_addr.addr_bytes, ETH_ADDR_LEN);
    if (rte_eth_link_get_nowait(common->port_id, &common->link) < 0) {
        memset(&common->link, 0, sizeof common->link);
    }

    /* Upon success of esw_mgr port, update the representor's field of it. */
    if (netdev_doca_get_esw_mgr_port_id(netdev) == common->port_id) {
        netdev_doca_do_foreach_representor(dev, netdev_doca_rep_reconfigure);
    }

    return 0;
}

static int
netdev_doca_reconfigure(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_dpdk_common *common = &dev->common;
    int err = 0;

    /* If an ESW manager is not attached to OVS, a representor cannot be
     * configured. */
    if (!netdev_doca_is_esw_mgr(netdev) &&
        netdev_doca_get_esw_mgr_port_id(netdev) ==
        DPDK_ETH_PORT_ID_INVALID) {
        return EOPNOTSUPP;
    }

    ovs_mutex_lock(&doca_mutex);
    ovs_mutex_lock(&dev->common.mutex);

    common->requested_n_rxq = common->user_n_rxq;

    if (netdev->n_txq == common->requested_n_txq
        && netdev->n_rxq == common->requested_n_rxq
        && common->mtu == common->requested_mtu
        && common->lsc_interrupt_mode == common->requested_lsc_interrupt_mode
        && common->rxq_size == common->requested_rxq_size
        && common->txq_size == common->requested_txq_size
        && eth_addr_equals(common->hwaddr, common->requested_hwaddr)
        && common->socket_id == common->requested_socket_id
        && dpdk_dev_is_started(common)) {
        /* Reconfiguration is unnecessary. */
        goto out;
    }

    netdev_doca_port_stop(netdev);

    err = netdev_doca_mempool_configure(dev);
    if (err) {
        goto out;
    }

    common->lsc_interrupt_mode = common->requested_lsc_interrupt_mode;

    netdev->n_txq = common->requested_n_txq;
    netdev->n_rxq = common->requested_n_rxq;
    if (!netdev_doca_is_esw_mgr(netdev)) {
        int esw_n_rxq;

        esw_n_rxq = dev->esw_ctx->n_rxq;
        if (common->requested_n_rxq != esw_n_rxq) {
            VLOG_WARN("%s: requested_n_rxq=%d is ignored. DOCA binds the "
                      "number of rx queues to the esw's n_rxq=%d",
                      netdev_get_name(netdev), common->requested_n_rxq,
                      esw_n_rxq);
        }

        netdev->n_rxq = esw_n_rxq;
    }

    common->rxq_size = common->requested_rxq_size;
    common->txq_size = common->requested_txq_size;

    rte_free(common->tx_q);
    common->tx_q = NULL;

    if (!eth_addr_equals(common->hwaddr, common->requested_hwaddr)) {
        err = netdev_dpdk_set_dev_etheraddr(&dev->common,
                                            common->requested_hwaddr);
        if (err) {
            goto out;
        }
    }

    err = doca_eth_dev_init(dev);
    if (err) {
        goto out;
    }

    netdev_dpdk_update_netdev_flags(&dev->common);

    /* If both requested and actual hw-addr were previously
     * unset (initialized to 0), then first device init above
     * will have set actual hw-addr to something new.
     * This would trigger spurious MAC reconfiguration unless
     * the requested MAC is kept in sync.
     *
     * This is harmless in case requested_hwaddr was
     * configured by the user, as netdev_dpdk_set_dev_etheraddr()
     * will have succeeded to get to this point. */
    common->requested_hwaddr = common->hwaddr;

    common->tx_q = netdev_dpdk_alloc_txq(netdev->n_txq);
    if (!common->tx_q) {
        err = ENOMEM;
    }

    netdev_change_seq_changed(netdev);

out:
    ovs_mutex_unlock(&dev->common.mutex);
    ovs_mutex_unlock(&doca_mutex);
    return err;
}

static int
common_construct(struct netdev *netdev, dpdk_port_t port_no, int socket_id)
    OVS_REQUIRES(doca_mutex)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_dpdk_common *common = &dev->common;

    ovs_mutex_init(&common->mutex);

    rte_spinlock_init(&common->stats_lock);

    /* If socket_id is negative, it means that the kernel fails
     * to obtain the pci numa info.  In that situation, always
     * use 'SOCKET0'. */
    common->socket_id = socket_id < 0 ? SOCKET0 : socket_id;
    common->requested_socket_id = common->socket_id;
    common->port_id = port_no;
    dev->esw_mgr_port_id = port_no;
    common->type = DPDK_DEV_ETH;
    common->flags = 0;
    common->requested_mtu = RTE_ETHER_MTU;
    common->max_packet_len = MTU_TO_FRAME_LEN(common->mtu);
    common->requested_lsc_interrupt_mode = 0;
    common->attached = false;
    atomic_store(&common->started, false);

    netdev->n_rxq = 0;
    netdev->n_txq = 0;
    common->user_n_rxq = NR_QUEUE;
    common->requested_n_rxq = NR_QUEUE;
    common->requested_n_txq = NR_QUEUE;
    common->requested_rxq_size = NIC_PORT_DEFAULT_RXQ_SIZE;
    common->requested_txq_size = NIC_PORT_DEFAULT_TXQ_SIZE;

    /* Initialize the flow control to NULL. */
    memset(&common->fc_conf, 0, sizeof common->fc_conf);

    /* Initialize the hardware offload flags to 0. */
    common->hw_ol_features = 0;

    common->rx_metadata_delivery_configured = false;

    common->flags = NETDEV_UP | NETDEV_PROMISC;

    common->rte_xstats_names = NULL;
    common->rte_xstats_names_size = 0;

    common->rte_xstats_ids = NULL;
    common->rte_xstats_ids_size = 0;

    common->sw_stats = xzalloc(sizeof *common->sw_stats);
    common->sw_stats->tx_retries = UINT64_MAX;

    ovs_list_push_back(&doca_list, &common->list_node);

    netdev_request_reconfigure(netdev);

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
    struct netdev_dpdk_common *common = &dev->common;

    ovs_mutex_lock(&common->mutex);
    netdev_dpdk_get_config_common(common, args);
    ovs_mutex_unlock(&common->mutex);

    return 0;
}

static bool
iface_exists(const char *name)
{
    char path[PATH_MAX];
    struct stat st;
    int n;

    n = snprintf(path, sizeof path, "/sys/class/net/%s", name);
    if (!(n >= 0 && n < sizeof path)) {
        return false;
    }

    return stat(path, &st) == 0;
}

static char *
netdev_doca_generate_devargs(const char *name, char *devargs, size_t maxlen,
                             char iface[IFNAMSIZ])
{
    char phys_port_name_[IFNAMSIZ], *phys_port_name = phys_port_name_;
    char pci[PCI_PRI_STR_SIZE + 1];
    char iface_tmp[IFNAMSIZ];
    char *mlx5_devargs;
    int controller_len;
    char *rep_part;
    bool is_rep;
    bool is_pf;
    int port;
    int len;

    if (!iface_exists(name)) {
        return NULL;
    }

    if (get_phys_iface_name(name, iface_tmp)) {
        VLOG_ERR("%s: Failed to get physical iface name", name);
        return NULL;
    }

    name = iface_tmp;
    ovs_strlcpy(iface, name, IFNAMSIZ);

    if (get_doca_dev_pci(name, pci, sizeof pci, &is_rep)) {
        VLOG_WARN("%s: Failed to get PCI address", name);
        return NULL;
    }

    if (get_phys_port_name(name, phys_port_name_, sizeof phys_port_name_)) {
        VLOG_WARN("%s: Failed to get phys_port_name", name);
        return NULL;
    }

    /* In some kernels, there is a controller prefix, like "c1".  Ignore it. */
    if (sscanf(phys_port_name, "c%d%n", &port, &controller_len) == 1) {
        phys_port_name += controller_len;
    }

    is_pf = false;

    if (sscanf(phys_port_name, "p%d", &port) == 1) {
        is_pf = true;
    } else if (sscanf(phys_port_name, "pf%d", &port) != 1) {
        VLOG_ERR("%s: unrecognized phys_port_name %s", name, phys_port_name);
        return NULL;
    }

    mlx5_devargs =
        "dv_xmeta_en=4,"
        "dv_flow_en=2,"
        "probe_opt_en=1";

    len = strlen(phys_port_name);

    /* HPF's phys_port_name is pf0/pf1. */
    if (len == 3 && !strncmp(phys_port_name, "pf", 2)) {
        /* "" to workaround a false positive checkpatch issue. */
        len = snprintf(devargs, maxlen, "%s,%s,representor=(pf%d)""vf65535",
                       pci, mlx5_devargs, port);
        if (len < 0 || len >= maxlen) {
            VLOG_ERR("%s: Failed to format devargs for HPF port", name);
            return NULL;
        }

        return devargs;
    }

    /* PF ports. */
    if (is_pf) {
        if (!is_rep) {
            len = snprintf(devargs, maxlen, "%s,%s", pci, mlx5_devargs);
        } else {
            len = snprintf(devargs, maxlen, "%s,%s,representor=pf%d", pci,
                           mlx5_devargs, port);
        }

        if (len < 0 || len >= maxlen) {
            VLOG_ERR("%s: Failed to format devargs for PF port", name);
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
        VLOG_ERR("%s: no vf/sf", phys_port_name);
        return NULL;
    }

    /* Format as (pfX)vfY or (pfX)sfY. */
    len = snprintf(devargs, maxlen, "%s,%s,representor=(%.*s)%s", pci,
                   mlx5_devargs, (int) (rep_part - phys_port_name),
                   phys_port_name, rep_part);
    if (len < 0 || len >= maxlen) {
        VLOG_ERR("%s: Failed to format devargs for representor port", name);
        return NULL;
    }

    return devargs;
}

static dpdk_port_t
netdev_doca_process_devargs(struct netdev_doca *dev,
                            const char *devargs, char **errp)
    OVS_REQUIRES(doca_mutex)
{
    dpdk_port_t new_port_id;

    new_port_id = netdev_dpdk_get_port_by_devargs(devargs);
    if (!rte_eth_dev_is_valid_port(new_port_id)) {
        int err;

        /* Device not found in DPDK, attempt to attach it. */
        err = netdev_doca_dev_probe(dev, devargs);
        if (err) {
            new_port_id = DPDK_ETH_PORT_ID_INVALID;
        } else {
            new_port_id = netdev_dpdk_get_port_by_devargs(devargs);
            if (rte_eth_dev_is_valid_port(new_port_id)) {
                /* Attach successful. */
                dev->common.attached = true;
                VLOG_INFO("Device '%s' attached", devargs);
            } else {
                /* Attach unsuccessful. */
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
netdev_doca_lookup_by_port_id(dpdk_port_t port_id)
    OVS_REQUIRES(doca_mutex)
{
    struct netdev_dpdk_common *common;

    common = netdev_dpdk_lookup_common_by_port_id(port_id, &doca_list);
    if (common) {
        return CONTAINER_OF(common, struct netdev_doca, common);
    }

    return NULL;
}

static dpdk_port_t
netdev_doca_find_esw_mgr_port_id(dpdk_port_t dev_port_id)
    OVS_REQUIRES(doca_mutex)
{
    struct rte_eth_dev_info info;
    struct netdev_doca *dev;
    uint16_t domain_id;

    if (!rte_eth_dev_is_valid_port(dev_port_id)) {
        return DPDK_ETH_PORT_ID_INVALID;
    }

    if (rte_eth_dev_info_get(dev_port_id, &info) < 0) {
        VLOG_DBG_RL(&rl, "Failed to retrieve device info for port "
                    DPDK_PORT_ID_FMT, dev_port_id);
        return DPDK_ETH_PORT_ID_INVALID;
    }

    domain_id = info.switch_info.domain_id;
    LIST_FOR_EACH (dev, common.list_node, &doca_list) {
        if (!rte_eth_dev_is_valid_port(dev->common.port_id)) {
            continue;
        }

        if (rte_eth_dev_info_get(dev->common.port_id, &info) < 0) {
            VLOG_DBG_RL(&rl, "Failed to retrieve device info for port "
                        DPDK_PORT_ID_FMT, dev->common.port_id);
            continue;
        }

        if (info.switch_info.domain_id == domain_id &&
            !(*info.dev_flags & RTE_ETH_DEV_REPRESENTOR)) {
            VLOG_DBG("Found ESW manager port "DPDK_PORT_ID_FMT" for "
                     "device "DPDK_PORT_ID_FMT, dev->common.port_id,
                     dev_port_id);
            return dev->common.port_id;
        }
    }

    return DPDK_ETH_PORT_ID_INVALID;
}

static int
netdev_doca_set_config(struct netdev *netdev, const struct smap *args,
                       char **errp)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_dpdk_common *common = &dev->common;
    const char *netdev_name = netdev_get_name(netdev);
    char generated[PATH_MAX];
    bool lsc_interrupt_mode;
    const char *new_devargs;
    char iface[IFNAMSIZ];
    const char *vf_mac;
    int err = 0;
    bool is_rep;

    ovs_mutex_lock(&doca_mutex);
    ovs_mutex_lock(&common->mutex);

    memset(iface, 0, sizeof iface);
    if (!common->devargs) {
        new_devargs = netdev_doca_generate_devargs(netdev_name, generated,
                                                   sizeof generated, iface);
        if (!new_devargs) {
            VLOG_WARN("%s: Could not generate DPDK devargs",
                      netdev_get_name(netdev));
            err = ENODEV;
            goto out;
        }

        common->devargs = xstrdup(new_devargs);
    }

    is_rep = strstr(common->devargs, "representor=");
    if (is_rep) {
        struct netdev_doca_esw_key esw_key;
        struct netdev_doca_esw_ctx *esw;

        if (netdev_doca_esw_key_parse(common->devargs, &esw_key)) {
            VLOG_ERR("%s: ESW_key parsing failed for %s",
                     netdev_name, common->devargs);
            err = EINVAL;
            goto out;
        }

        esw = refmap_try_ref(netdev_doca_esw_rfm, &esw_key);
        if (!esw) {
            goto out;
        }

        refmap_unref(netdev_doca_esw_rfm, esw);
    }

    netdev_dpdk_set_rxq_config(common, args);

    /* Don't process dpdk-devargs if value is unchanged and port id
     * is valid. */
    if (!(rte_eth_dev_is_valid_port(common->port_id) && common->attached)) {
        dpdk_port_t new_port_id =
            netdev_doca_process_devargs(dev, common->devargs, errp);

        if (!rte_eth_dev_is_valid_port(new_port_id)) {
            err = EINVAL;
        } else if (new_port_id == common->port_id) {
            /* Already configured, do not reconfigure again. */
            err = 0;
        } else {
            struct netdev_doca *dup_dev;

            dup_dev = netdev_doca_lookup_by_port_id(new_port_id);
            if (dup_dev) {
                VLOG_WARN_BUF(errp, "'%s' is trying to use device '%s' "
                              "which is already in use by '%s'",
                              netdev_get_name(netdev), common->devargs,
                              netdev_get_name(&dup_dev->common.up));
                err = EADDRINUSE;
            } else {
                int sid = rte_eth_dev_socket_id(new_port_id);

                common->requested_socket_id = sid < 0 ? SOCKET0 : sid;
                common->port_id = new_port_id;
                dev->esw_mgr_port_id =
                    netdev_doca_find_esw_mgr_port_id(new_port_id);
                netdev_request_reconfigure(&common->up);
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

        if (!common->is_representor) {
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
        } else if (!eth_addr_equals(common->requested_hwaddr, mac)) {
            common->requested_hwaddr = mac;
            netdev_request_reconfigure(netdev);
        }
    }

    lsc_interrupt_mode = smap_get_bool(args, "dpdk-lsc-interrupt", false);
    if (common->requested_lsc_interrupt_mode != lsc_interrupt_mode) {
        common->requested_lsc_interrupt_mode = lsc_interrupt_mode;
        netdev_request_reconfigure(netdev);
    }

out:
    ovs_mutex_unlock(&common->mutex);
    ovs_mutex_unlock(&doca_mutex);

    return err;
}

static void
dispatch_rx_packets_by_port(struct dp_packet_batch *rx_batch,
                            struct netdev_doca_port_queue
                                *pq[RTE_MAX_ETHPORTS],
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
            COVERAGE_INC(netdev_doca_rx_drop_no_mark);
            dp_packet_delete(pkt);
            continue;
        }

        pkt->has_mark = false;
        if (!rte_eth_dev_is_valid_port(port_id)) {
            COVERAGE_INC(netdev_doca_rx_drop_invalid_port);
            dp_packet_delete(pkt);
            continue;
        }

        pkt_size = dp_packet_size(pkt);
        rv = rte_ring_sp_enqueue(pq[port_id][queue_id].ring, pkt);
        if (rv) {
            COVERAGE_INC(netdev_doca_rx_drop_ring_full);
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
    struct netdev_dpdk_common *common = &dev->common;
    struct netdev_doca_port_queue *pq;
    struct dp_packet_batch rx_batch;
    dpdk_port_t esw_mgr_port_id;
    dpdk_port_t port_id;
    uint64_t old_count;
    int nb_rx;

    if (OVS_UNLIKELY(!(common->flags & NETDEV_UP) ||
                     !dpdk_dev_is_started(common))) {
        return EAGAIN;
    }

    esw_mgr_port_id = dev->esw_ctx->port_id;
    port_id = common->port_id;

    if (port_id == esw_mgr_port_id) {
        rx_batch.count =
            rte_eth_rx_burst(esw_mgr_port_id, rxq->queue_id,
                             (struct rte_mbuf **) rx_batch.packets,
                             NETDEV_MAX_BURST);
        if (rx_batch.count == 0) {
            return 0;
        }

        dispatch_rx_packets_by_port(&rx_batch, dev->esw_ctx->port_queues,
                                    rxq->queue_id);
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
            *qfill = rte_ring_count(pq->ring);
        } else {
            *qfill = 0;
        }
    }

    return 0;
}

static inline void
packet_set_meta(struct dp_packet *p, uint32_t meta)
{
    *RTE_MBUF_DYNFIELD(&p->mbuf, rte_flow_dynf_metadata_offs,
                       uint32_t *) = meta;
    p->mbuf.ol_flags |= RTE_MBUF_DYNFLAG_TX_METADATA;
}

static int
netdev_doca_send(struct netdev *netdev, int qid,
                 struct dp_packet_batch *batch, bool concurrent_txq)
{
    struct rte_mbuf **pkts = (struct rte_mbuf **) batch->packets;
    uint32_t port_id_meta = netdev_doca_get_port_id(netdev);
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    size_t cnt, pkt_cnt = dp_packet_batch_size(batch);
    struct netdev_dpdk_common *common = &dev->common;
    int batch_cnt = dp_packet_batch_size(batch);
    struct netdev_dpdk_sw_stats stats;
    struct dp_packet *packet;
    bool need_copy = false;
    uint64_t n_bytes = 0;
    uint64_t old_count;
    int dropped;

    if (OVS_UNLIKELY(!(common->flags & NETDEV_UP))) {
        rte_spinlock_lock(&common->stats_lock);
        common->stats.tx_dropped += dp_packet_batch_size(batch);
        rte_spinlock_unlock(&common->stats_lock);
        dp_packet_delete_batch(batch, true);
        return 0;
    }

    if (OVS_UNLIKELY(concurrent_txq)) {
        qid = qid % common->up.n_txq;
        rte_spinlock_lock(&common->tx_q[qid].tx_lock);
    }

    memset(&stats, 0, sizeof stats);

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        if (packet->source != DPBUF_DPDK) {
            need_copy = true;
            break;
        }
    }

    /* Copy dp-packets to mbufs. */
    if (OVS_UNLIKELY(need_copy)) {
        cnt = netdev_dpdk_copy_batch_to_mbuf(common, batch);
        stats.tx_failure_drops += pkt_cnt - cnt;
        pkt_cnt = cnt;
    }

    /* Drop over-sized packets. */
    cnt = netdev_dpdk_filter_packet_len(common, pkts, pkt_cnt);
    stats.tx_mtu_exceeded_drops += pkt_cnt - cnt;
    pkt_cnt = cnt;

    /* Prepare each mbuf for hardware offloading. */
    cnt = netdev_dpdk_prep_hwol_batch(common, pkts, pkt_cnt);
    stats.tx_invalid_hwol_drops += pkt_cnt - cnt;

    batch->count = cnt;
    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        /* Set metadata for egress pipe rules to match on. */
        packet_set_meta(packet, port_id_meta);
        n_bytes += dp_packet_size(packet);
    }

    atomic_add_relaxed(&dev->sw_tx_stats[qid].n_packets, batch->count,
                       &old_count);
    atomic_add_relaxed(&dev->sw_tx_stats[qid].n_bytes, n_bytes, &old_count);

    dropped = netdev_dpdk_eth_tx_burst(common, dev->esw_mgr_port_id,
                                       qid, pkts, cnt);
    stats.tx_failure_drops += dropped;
    dropped += batch_cnt - cnt;
    if (OVS_UNLIKELY(dropped)) {
        struct netdev_dpdk_sw_stats *sw_stats = common->sw_stats;

        rte_spinlock_lock(&common->stats_lock);
        common->stats.tx_dropped += dropped;
        sw_stats->tx_failure_drops += stats.tx_failure_drops;
        sw_stats->tx_mtu_exceeded_drops += stats.tx_mtu_exceeded_drops;
        sw_stats->tx_invalid_hwol_drops += stats.tx_invalid_hwol_drops;
        rte_spinlock_unlock(&common->stats_lock);
    }

    if (OVS_UNLIKELY(concurrent_txq)) {
        rte_spinlock_unlock(&common->tx_q[qid].tx_lock);
    }

    return 0;
}

#define NETDEV_DOCA_CLASS_COMMON                            \
    .is_pmd = true,                                         \
    .alloc = netdev_doca_alloc,                             \
    .dealloc = netdev_doca_dealloc,                         \
    .get_numa_id = netdev_dpdk_get_numa_id,                 \
    .set_etheraddr = netdev_dpdk_set_etheraddr,             \
    .get_etheraddr = netdev_dpdk_get_etheraddr,             \
    .get_mtu = netdev_dpdk_get_mtu,                         \
    .set_mtu = netdev_doca_set_mtu,                         \
    .get_ifindex = netdev_dpdk_get_ifindex,                 \
    .get_carrier_resets = netdev_dpdk_get_carrier_resets,   \
    .set_miimon_interval = netdev_dpdk_set_miimon,          \
    .update_flags = netdev_dpdk_update_flags,               \
    .rxq_alloc = netdev_dpdk_rxq_alloc,                     \
    .rxq_construct = netdev_dpdk_rxq_construct,             \
    .rxq_destruct = netdev_dpdk_rxq_destruct,               \
    .rxq_dealloc = netdev_dpdk_rxq_dealloc

#define NETDEV_DOCA_CLASS_BASE                          \
    NETDEV_DOCA_CLASS_COMMON,                           \
    .init = netdev_doca_class_init,                     \
    .destruct = netdev_doca_destruct,                   \
    .set_tx_multiq = netdev_dpdk_set_tx_multiq,         \
    .get_carrier = netdev_dpdk_get_carrier,             \
    .get_stats = netdev_dpdk_get_stats,                 \
    .get_custom_stats = netdev_doca_get_custom_stats,   \
    .get_features = netdev_dpdk_get_features,           \
    .get_speed = netdev_dpdk_get_speed,                 \
    .get_status = netdev_doca_get_status,               \
    .reconfigure = netdev_doca_reconfigure,             \
    .rxq_recv = netdev_doca_rxq_recv

static const struct netdev_class netdev_doca_class = {
    .type = "doca",
    NETDEV_DOCA_CLASS_BASE,
    .construct = netdev_doca_construct,
    .get_config = netdev_doca_get_config,
    .set_config = netdev_doca_set_config,
    .send = netdev_doca_send,
};

void
netdev_doca_register(void)
{
    netdev_register_provider(&netdev_doca_class);
}
