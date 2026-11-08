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
#include <sys/stat.h>
#include <unistd.h>

#include <rte_bus.h>
#include <rte_config.h>
#include <rte_dev.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_pci.h>
#include <rte_pmd_mlx5.h>
#include <rte_ring.h>
#include <rte_version.h>

#include <doca_bitfield.h>
#include <doca_dev.h>
#include <doca_dpdk.h>
#include <doca_flow.h>
#include <doca_rdma_bridge.h>

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

#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_doca);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

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

/* Contains all 'struct netdev_doca's. */
static struct ovs_list doca_list = OVS_LIST_INITIALIZER(&doca_list);

/* Hidden dpdk netdevs whose netdev_close() must run outside netdev_mutex.
 * destruct() is called with that mutex held, and it is not recursive.
 * doca_dev is closed after those netdevs: rte_dev_remove() closes cmd_fd. */
struct netdev_doca_esw_close {
    struct ovs_list list_node;
    struct netdev *netdev;
    struct doca_dev *doca_dev;
    char *pci_addr;
    int cmd_fd;
};

static struct ovs_list doca_esw_close_list
    = OVS_LIST_INITIALIZER(&doca_esw_close_list);

static void
netdev_doca_queue_close(struct netdev *netdev, struct doca_dev *doca_dev,
                        const char *pci_addr, int cmd_fd)
{
    struct netdev_doca_esw_close *close = xmalloc(sizeof *close);

    close->netdev = netdev;
    close->doca_dev = doca_dev;
    close->pci_addr = pci_addr ? xstrdup(pci_addr) : NULL;
    close->cmd_fd = cmd_fd;
    ovs_list_push_back(&doca_esw_close_list, &close->list_node);
}

static void
netdev_doca_destruct(struct netdev *netdev);

static int
netdev_doca_port_stop(struct netdev_doca *);

static bool
netdev_doca_is_started(const struct netdev_doca *dev)
{
    bool started;

    atomic_read_explicit(&dev->started, &started, memory_order_acquire);
    return started;
}

static int
netdev_doca_egress_pipe_init(struct netdev_doca *dev)
{
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

    return ovs_doca_pipe_create(dev, &match, NULL, &monitor, NULL,
                                NULL, NULL, &fwd, NULL, RTE_MAX_ETHPORTS, true,
                                true, UINT64_C(1) << AUX_QUEUE, "EGRESS",
                                &dev->esw_ctx->egress_pipe);
}

static void
netdev_doca_egress_pipe_uninit(struct netdev_doca *dev)
{
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    ovs_doca_destroy_pipe(&esw->egress_pipe);
}

static int
netdev_doca_rss_pipe_init(struct netdev_doca *dev)
{
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

    rv = ovs_doca_pipe_create(dev, &match, NULL, &monitor,
                              &actions, &actions, NULL, &fwd, NULL,
                              NETDEV_DOCA_RSS_NUM_ENTRIES * RTE_MAX_ETHPORTS,
                              false, false, UINT64_C(1) << AUX_QUEUE, "RSS",
                              &dev->esw_ctx->rss_pipe);
    return rv;
}

static void
netdev_doca_rss_pipe_uninit(struct netdev_doca *dev)
{
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
netdev_doca_rss_entries_init(struct netdev_doca *dev)
{
    struct netdev_dpdk_common *common = &dev->common;
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;
    dpdk_port_t port_id = dev->port_id;
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

        ret = ovs_doca_add_entry(dev, AUX_QUEUE, esw->rss_pipe, &match,
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
netdev_doca_rss_entries_uninit(struct netdev_doca *dev)
{
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    for (int i = 0; i < NETDEV_DOCA_RSS_NUM_ENTRIES; i++) {
        ovs_doca_remove_entry(esw, AUX_QUEUE, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT,
                              &dev->rss_entries[i]);
    }
}

static int
netdev_doca_meta_tag0_pipe_init(struct netdev_doca *dev)
{
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

    return ovs_doca_pipe_create(dev, &match, NULL, NULL, &actions,
                                &actions_masks, NULL, &fwd, NULL, 1, false,
                                false, UINT64_C(1) << AUX_QUEUE, "META_TAG0",
                                &dev->esw_ctx->meta_tag0_pipe);
}

static void
netdev_doca_meta_tag0_pipe_uninit(struct netdev_doca *dev)
{
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    ovs_doca_destroy_pipe(&esw->meta_tag0_pipe);
}

static int
netdev_doca_meta_tag0_rule_init(struct netdev_doca *dev)
{
    struct netdev *netdev = &dev->common.up;
    struct doca_flow_pipe_entry **pentry;
    struct doca_flow_pipe *pipe;
    int ret;

    pentry = &dev->esw_ctx->meta_tag0_entry;
    pipe = dev->esw_ctx->meta_tag0_pipe;

    ret = ovs_doca_add_entry(dev, AUX_QUEUE, pipe, NULL, NULL, NULL, NULL,
                             DOCA_FLOW_ENTRY_FLAGS_NO_WAIT, pentry);
    if (ret != DOCA_SUCCESS) {
        VLOG_ERR("%s: Failed to create meta-tag0 rule. Error: %d (%s)",
                 netdev_get_name(netdev), ret, doca_error_get_descr(ret));
    }

    return ret;
}

static void
netdev_doca_meta_tag0_rule_uninit(struct netdev_doca *dev)
{
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    ovs_doca_remove_entry(esw, AUX_QUEUE, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT,
                          &dev->esw_ctx->meta_tag0_entry);
}

static int
netdev_doca_pre_miss_pipe_init(struct netdev_doca *dev)
{
    struct netdev *netdev = &dev->common.up;
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

    return ovs_doca_pipe_create(dev, &match, NULL, NULL, NULL, NULL, NULL,
                                &fwd, &miss, PRE_MISS_N_TYPES, false,
                                false, UINT64_C(1) << AUX_QUEUE, "PRE_MISS",
                                &dev->esw_ctx->pre_miss_pipe);
}

static void
netdev_doca_pre_miss_pipe_uninit(struct netdev_doca *dev)
{
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    ovs_doca_destroy_pipe(&esw->pre_miss_pipe);
}

static int
netdev_doca_pre_miss_rules_init(struct netdev_doca *dev)
{
    struct netdev *netdev = &dev->common.up;
    struct doca_flow_pipe_entry **pentry;
    struct ovs_doca_flow_match match;
    int ret;

    memset(&match, 0, sizeof match);

    for (int i = 0; i < PRE_MISS_N_TYPES; i++) {
        pentry = &dev->esw_ctx->pre_miss_entries[i];

        match.d.outer.eth.type = htons(pre_miss_mapping[i]);
        ret = ovs_doca_add_entry(dev, AUX_QUEUE,
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
netdev_doca_pre_miss_rules_uninit(struct netdev_doca *dev)
{
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    for (int i = 0; i < PRE_MISS_N_TYPES; i++) {
        ovs_doca_remove_entry(esw, AUX_QUEUE, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT,
                              &esw->pre_miss_entries[i]);
    }
}

static int
netdev_doca_root_pipe_init(struct netdev_doca *dev)
{
    struct doca_flow_fwd miss;

    memset(&miss, 0, sizeof miss);
    miss.type = DOCA_FLOW_FWD_PIPE;
    miss.next_pipe = dev->esw_ctx->pre_miss_pipe;

    return ovs_doca_pipe_create(dev, NULL, NULL, NULL, NULL, NULL, NULL,
                                NULL, &miss, 0, false, true, 0, "ROOT",
                                &dev->esw_ctx->root_pipe);
}

static void
netdev_doca_root_pipe_uninit(struct netdev_doca *dev)
{
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    ovs_doca_destroy_pipe(&esw->root_pipe);
}

static int
netdev_doca_egress_entry_init(struct netdev_doca *dev)
{
    struct doca_flow_pipe *pipe = dev->esw_ctx->egress_pipe;
    dpdk_port_t port_id = dev->port_id;
    struct ovs_doca_flow_match match;
    struct doca_flow_fwd fwd;
    int ret;

    memset(&match, 0, sizeof match);
    memset(&fwd, 0, sizeof fwd);

    match.d.meta.pkt_meta = (OVS_FORCE doca_be32_t) DOCA_HTOBE32(port_id);

    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = port_id;

    ret = ovs_doca_add_entry(dev, AUX_QUEUE, pipe, &match, NULL, NULL,
                             &fwd, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT,
                             &dev->egress_entry);
    if (ret != DOCA_SUCCESS) {
        VLOG_ERR("Failed to create egress pipe entry. Error: %d (%s)", ret,
                 doca_error_get_descr(ret));
    }

    return ret;
}

static void
netdev_doca_egress_entry_uninit(struct netdev_doca *dev)
{
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;

    ovs_doca_remove_entry(esw, AUX_QUEUE, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT,
                          &dev->egress_entry);
}

static void
netdev_doca_slowpath_esw_uninit(struct netdev_doca *dev)
{
    netdev_doca_root_pipe_uninit(dev);
    netdev_doca_pre_miss_rules_uninit(dev);
    netdev_doca_pre_miss_pipe_uninit(dev);
    netdev_doca_meta_tag0_rule_uninit(dev);
    netdev_doca_meta_tag0_pipe_uninit(dev);
    netdev_doca_rss_pipe_uninit(dev);
    netdev_doca_egress_pipe_uninit(dev);
}

static int
netdev_doca_slowpath_esw_init(struct netdev_doca *dev)
{
    struct netdev *netdev = &dev->common.up;
    int rv;

#define ESW_INIT_CMD(func)                                                \
    do {                                                                  \
        rv = (func)(dev);                                                 \
        if (rv == DOCA_SUCCESS) {                                         \
            break;                                                        \
        }                                                                 \
        VLOG_ERR("%s: eSwitch initialization failed, %s() with error: "   \
                 "%d (%s)", netdev_get_name(netdev), #func, rv,           \
                 doca_error_get_descr(rv));                               \
        return rv;                                                        \
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
netdev_doca_esw_port_uninit(struct netdev_doca *dev)
{
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

    netdev_doca_slowpath_esw_uninit(dev);
}

static int
netdev_doca_esw_init(struct netdev_doca *dev)
{
    struct netdev_dpdk_common *common = &dev->common;
    struct netdev *netdev = &common->up;
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;
    uint16_t pid;
    int rv;

    esw->esw_port = dev->port;
    esw->esw_netdev = netdev;
    esw->port_id = dev->port_id;
    esw->n_rxq = netdev->n_rxq;

    rv = netdev_doca_slowpath_esw_init(dev);
    if (rv != DOCA_SUCCESS) {
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
    netdev_doca_esw_port_uninit(dev);
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
     * 3. If not, try to find in the representors of this ESW. */
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
     * the format of ../../.../<lower-dev>.  Extract the lower device. */
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
    return CONTAINER_OF(netdev, struct netdev_doca, common.up);
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
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_dpdk_common *common = &dev->common;

    ovs_mutex_lock(&dev->mutex);
    if (common->requested_mtu != mtu) {
        if (dev->is_representor) {
            VLOG_WARN("%s: setting requested MTU %d is ignored for "
                      "representor", netdev_get_name(netdev), mtu);
            goto out;
        }

        common->requested_mtu = mtu;
        if (dev->esw_eth) {
            netdev_set_mtu(&dev->esw_eth->common.up, mtu);
        }
        netdev_request_reconfigure(netdev);
    }

out:
    ovs_mutex_unlock(&dev->mutex);

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
    memset(ctx->steering_queues, 0, sizeof ctx->steering_queues);

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

static void
netdev_doca_run(const struct netdev_class *netdev_class OVS_UNUSED)
{
    struct netdev_doca_esw_close *entry;

    LIST_FOR_EACH_POP (entry, list_node, &doca_esw_close_list) {
        if (entry->netdev) {
            netdev_close(entry->netdev);
        }

        if (entry->doca_dev) {
            int err = doca_dev_close(entry->doca_dev);

            if (err != DOCA_SUCCESS) {
                VLOG_ERR("Failed to close doca dev %s. Error: %d (%s)",
                         entry->pci_addr ? entry->pci_addr : "",
                         err, doca_error_get_descr(err));
            }

            if (entry->cmd_fd != -1) {
                close(entry->cmd_fd);
            }
        }

        free(entry->pci_addr);
        free(entry);
    }
}

static void
netdev_doca_wait(const struct netdev_class *netdev_class OVS_UNUSED)
{
    if (!ovs_list_is_empty(&doca_esw_close_list)) {
        poll_immediate_wake();
    }
}

static int
netdev_doca_class_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (!ovsthread_once_start(&once)) {
        return 0;
    }

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
 * Return EINVAL for error or 0 for success. */
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
{
    bool need_reconfigure = false;
    struct rte_pci_addr esw_pci;
    struct rte_pci_addr rep_pci;
    struct netdev_doca *dev;

    if (netdev_doca_parse_dpdk_devargs_pci(esw_dev->devargs,
                                           &esw_pci)) {
        return;
    }

    LIST_FOR_EACH (dev, list_node, &doca_list) {
        if (esw_dev == dev) {
            continue;
        }

        if (!dev->devargs ||
            netdev_doca_parse_dpdk_devargs_pci(dev->devargs,
                                               &rep_pci)) {
            continue;
        }

        if (rte_pci_addr_cmp(&rep_pci, &esw_pci)) {
            continue;
        }

        ovs_mutex_lock(&dev->mutex);
        need_reconfigure |= cb(dev);
        ovs_mutex_unlock(&dev->mutex);
        netdev_request_reconfigure(&dev->common.up);
    }

    if (need_reconfigure) {
        /* If a representor is reconfigured a result of its ESW manager
         * change, it might not be synced in the bridge's database.  Signal it
         * to reconfigure, to make it right. */
        rtnetlink_report_link();
    }
}

static void
netdev_doca_dev_close(struct netdev_doca *dev)
{
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;
    char *pci_addr;
    bool last;
    int err;

    /* The Ethernet device is owned by the shadow dpdk netdev.  It stops,
     * closes, and detaches that device. */
    if (!esw) {
        return;
    }

    pci_addr = xstrdup(esw->pci_addr);

    last = refmap_unref(netdev_doca_esw_rfm, esw);
    /* The last reference closes the DOCA device after the shadow netdev has
     * been closed: rte_dev_remove() closes cmd_fd.  With no shadow, nothing
     * has probed and the device can be closed here. */
    if (last && esw->dev) {
        if (dev->eth || dev->esw_eth) {
            netdev_doca_queue_close(NULL, esw->dev, pci_addr, -1);
            esw->dev = NULL;
            esw->cmd_fd = -1;
        } else {
            VLOG_DBG("Closing '%s'", pci_addr);
            err = doca_dev_close(esw->dev);
            if (err != DOCA_SUCCESS) {
                VLOG_ERR("Failed to close doca dev %s. Error: %d (%s)",
                         pci_addr, err, doca_error_get_descr(err));
            }

            esw->dev = NULL;
            if (esw->cmd_fd != -1) {
                close(esw->cmd_fd);
            } else {
                esw->cmd_fd = -1;
            }
        }
    }

    dev->esw_ctx = NULL;
    free(pci_addr);
}

static bool
netdev_doca_rep_stop(struct netdev_doca *dev)
{
    if (!netdev_doca_is_started(dev)) {
        return false;
    }

    /* Leave the shadow dpdk port and esw_ctx in place.  They stay until this
     * representor is destroyed, so the shared device is not removed early. */
    netdev_doca_port_stop(dev);

    return true;
}

static int
netdev_doca_port_stop(struct netdev_doca *dev)
{
    struct netdev *netdev = &dev->common.up;
    bool started = netdev_doca_is_started(dev);
    int err = 0;

    if (started) {
        if (!dev->is_representor) {
            netdev_doca_do_foreach_representor(dev, netdev_doca_rep_stop);
        }

        VLOG_INFO("%s: Stopping '%s', port_id="DPDK_PORT_ID_FMT,
                  netdev_get_name(netdev), dev->devargs,
                  dev->port_id);
        atomic_store_explicit(&dev->started, false, memory_order_release);
    }

    netdev_doca_rss_entries_uninit(dev);
    netdev_doca_egress_entry_uninit(dev);

    if (!dev->is_representor) {
        netdev_doca_esw_port_uninit(dev);
    }

    if (dev->port) {
        err = doca_flow_port_stop(dev->port);
        dev->port = NULL;
    }

    if (dev->is_representor && dev->dev_rep) {
        VLOG_DBG("%s: Closing doca dev_rep for port_id "DPDK_PORT_ID_FMT
                 ". %p", netdev_get_name(netdev), dev->port_id,
                 dev->dev_rep);
        err = doca_dev_rep_close(dev->dev_rep);
        if (err != DOCA_SUCCESS) {
            VLOG_ERR("Failed to close doca dev_rep with port id "
                     DPDK_PORT_ID_FMT". Error: %d (%s)",
                     dev->port_id, err, doca_error_get_descr(err));
        }

        dev->dev_rep = NULL;
    }

    return err;
}

static void
netdev_doca_destruct(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    netdev_doca_port_stop(dev);

    /* Shadow closes are queued before dev_close(), which may append the
     * DOCA device close.  run() then detaches the Ethernet device first. */
    if (dev->eth && dev->eth != dev->esw_eth) {
        netdev_doca_queue_close(&dev->eth->common.up, NULL, NULL, -1);
    }

    if (dev->esw_eth) {
        netdev_doca_queue_close(&dev->esw_eth->common.up, NULL, NULL, -1);
    }

    if (dev->attached) {
        netdev_doca_dev_close(dev);
        dev->port_id = DPDK_ETH_PORT_ID_INVALID;

        VLOG_INFO("%s: Device '%s' has been removed", netdev_get_name(netdev),
                  dev->devargs);
    }
    dev->eth = NULL;
    dev->esw_eth = NULL;
    ovs_list_remove(&dev->list_node);

    free(dev->sw_tx_stats);
    free(dev->peer_name);
    free(dev->devargs);
    netdev_dpdk_common_destruct(&dev->common);
    ovs_mutex_destroy(&dev->mutex);
}

static void
netdev_doca_get_sw_custom_stats(const struct netdev *netdev,
                                struct netdev_custom_stats *custom_stats)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_dpdk_common *common = &dev->common;
    int stat_offset, i, n;

#define SW_CSTATS                    \
    SW_CSTAT(tx_failure_drops)

    stat_offset = custom_stats->size;

#define SW_CSTAT(NAME) + 1
    custom_stats->size += SW_CSTATS;
#undef SW_CSTAT

    custom_stats->counters = xrealloc(custom_stats->counters,
                                      custom_stats->size *
                                      sizeof *custom_stats->counters);

    ovs_mutex_lock(&dev->mutex);

    rte_spinlock_lock(&common->stats_lock);
    i = stat_offset;
#define SW_CSTAT(NAME) \
    custom_stats->counters[i++].value = common->sw_stats->NAME;
    SW_CSTATS;
#undef SW_CSTAT
    rte_spinlock_unlock(&common->stats_lock);

    ovs_mutex_unlock(&dev->mutex);

    i = stat_offset;
    n = stat_offset;
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
}

static int
netdev_doca_get_custom_stats(const struct netdev *netdev,
                             struct netdev_custom_stats *custom_stats)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw_ctx = dev->esw_ctx;
    dpdk_port_t port_id = dev->port_id;
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

    if (!netdev_doca_is_started(dev)) {
        return EAGAIN;
    }

    if (!dev->is_representor) {
        netdev_get_custom_stats(&dev->esw_eth->common.up, custom_stats);
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
                     dev->devargs, stats_name, i, err,
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
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    if (!dev->esw_eth) {
        return ENODEV;
    }

    return netdev_get_status(&dev->esw_eth->common.up, args);
}

static int
netdev_doca_esw_key_parse(const char *devargs,
                          struct netdev_doca_esw_key *esw_key)
{
    struct rte_pci_addr *rte_pci = &esw_key->rte_pci;

    memset(esw_key, 0, sizeof *esw_key);
    return netdev_doca_parse_dpdk_devargs_pci(devargs, rte_pci);
}

/* Open the shared DOCA device and build the device arguments the shadow dpdk
 * port probes with.  The Ethernet device itself is probed by netdev-dpdk. */
static int
netdev_doca_esw_prepare(struct netdev_doca *dev, const char *devargs,
                        struct ds *probe_devargs)
{
    const char *netdev_name = netdev_get_name(&dev->common.up);
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

    rv = doca_rdma_bridge_get_dev_pd(dev->esw_ctx->dev, &pd);
    if (rv != DOCA_SUCCESS) {
        VLOG_ERR("%s: Could not get protection domain (PD) for %s. "
                 "Error: %d (%s", netdev_name, devargs, rv,
                 doca_error_get_descr(rv));
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

    ds_put_format(probe_devargs, "%s,cmd_fd=%d,pd_handle=%u", devargs,
                  dev->esw_ctx->cmd_fd, pd->handle);

out:
    if (rv) {
        /* In case of an error, rollback the above refmap_ref()
         * which initialized the device. */
        netdev_doca_dev_close(dev);
    }

    return rv;
}

/* Probe, configure, and start a hidden dpdk netdev for this port's Ethernet
 * device.  zero_queues is a representor: its Ethernet device carries the link
 * and has no Rx/Tx queues.  The netdev is marked attached so the last sibling
 * detaches the device. */
static int
netdev_doca_open_shadow(const char *name, const char *probe_devargs,
                        bool zero_queues, struct netdev_dpdk_eth **ethp)
{
    struct netdev_dpdk_eth *eth;
    struct netdev *netdev;
    struct smap config;
    int err;

    err = netdev_open(name, "dpdk", &netdev);
    if (err) {
        VLOG_WARN("Failed to open shadow netdev '%s': %s",
                  name, ovs_strerror(err));
        return err;
    }

    smap_init(&config);
    smap_add(&config, "dpdk-devargs", probe_devargs);
    err = netdev_set_config(netdev, &config, NULL);
    smap_destroy(&config);
    if (err) {
        VLOG_WARN("Failed to configure shadow netdev '%s': %s",
                  name, ovs_strerror(err));
        netdev_close(netdev);
        return err;
    }

    eth = netdev_dpdk_eth_cast(netdev);
    if (zero_queues) {
        netdev_dpdk_eth_set_no_queues(netdev);
    }

    /* netdev-dpdk marks attached only when this shadow probes the device.
     * A sibling port does not.  Mark every shadow so the last one detaches
     * the device. */
    eth->attached = true;

    err = netdev_reconfigure(netdev);
    if (err) {
        VLOG_WARN("Failed to reconfigure shadow netdev '%s': %s",
                  name, ovs_strerror(err));
        netdev_close(netdev);
        return err;
    }

    if (!rte_eth_dev_is_valid_port(eth->port_id)) {
        netdev_close(netdev);
        return ENODEV;
    }

    *ethp = eth;
    VLOG_INFO("Opened shadow '%s' for port "DPDK_PORT_ID_FMT,
              name, eth->port_id);
    return 0;
}

static int
netdev_doca_port_start(struct netdev_doca *dev)
{
    struct netdev *netdev = &dev->common.up;
    const char *devargs = dev->devargs;
    dpdk_port_t port_id = dev->port_id;
    struct doca_flow_port_cfg *port_cfg;
    struct netdev_doca_esw_ctx *esw;
    int err;

    if (!dev->esw_eth) {
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

    if (dev->is_representor) {
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

    if (!dev->is_representor) {
        err = doca_flow_port_cfg_set_actions_mem_size(
                port_cfg, NETDEV_DOCA_ACTIONS_MEM_SIZE);
        if (err != DOCA_SUCCESS) {
            VLOG_ERR("Failed set_actions_mem_size for port_id "
                     DPDK_PORT_ID_FMT". Error: %d (%s)",
                     dev->port_id, err,
                     doca_error_get_descr(err));
            goto out;
        }

        err = doca_flow_port_cfg_set_nr_resources(port_cfg,
                                                  DOCA_FLOW_RESOURCE_COUNTER,
                                                  ovs_doca_max_counters());
        if (err != DOCA_SUCCESS) {
            VLOG_ERR("Failed set_nr_resources counters for port_id "
                     DPDK_PORT_ID_FMT". Error: %d (%s)",
                     dev->port_id, err,
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

    if (!dev->is_representor) {
        err = netdev_doca_esw_init(dev);
        if (err != DOCA_SUCCESS) {
            goto out;
        }
    }

    err = netdev_doca_egress_entry_init(dev);
    if (err != DOCA_SUCCESS) {
        goto out;
    }

    err = netdev_doca_rss_entries_init(dev);
    if (err != DOCA_SUCCESS) {
        goto out;
    }

out:
    doca_flow_port_cfg_destroy(port_cfg);
    if (err != DOCA_SUCCESS) {
        netdev_doca_port_stop(dev);
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
    OVS_REQUIRES(dev->mutex)
{
    struct netdev_dpdk_common *common = &dev->common;
    struct netdev *netdev = &common->up;
    struct rte_ether_addr eth_addr;
    int diag;

    diag = netdev_doca_port_start(dev);
    if (diag != DOCA_SUCCESS) {
        VLOG_ERR("Failed to init DOCA port %s port_id "DPDK_PORT_ID_FMT
                 ". Error: %d (%s)", netdev_get_name(netdev),
                 dev->port_id, diag, doca_error_get_descr(diag));
        return diag;
    }

    atomic_store_explicit(&dev->started, true, memory_order_release);

    memset(&eth_addr, 0x0, sizeof(eth_addr));
    rte_eth_macaddr_get(dev->port_id, &eth_addr);

    VLOG_DBG_RL(&rl, "Port %d: "ETH_ADDR_FMT,
                dev->port_id, ETH_ADDR_BYTES_ARGS(eth_addr.addr_bytes));

    memcpy(common->hwaddr.ea, eth_addr.addr_bytes, ETH_ADDR_LEN);

    /* Upon success of esw_mgr port, update the representor's field of it. */
    if (!dev->is_representor) {
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
    if (!dev->esw_eth) {
        return EOPNOTSUPP;
    }

    ovs_mutex_lock(&dev->mutex);

    /* esw_eth is not a datapath port, so dpif-netdev never sets its Tx queue
     * count.  Every DOCA port transmits on esw_eth using its own queue id. */
    if (!dev->is_representor) {
        netdev_set_tx_multiq(&dev->esw_eth->common.up,
                             common->requested_n_txq);
    }

    if (netdev->n_txq == common->requested_n_txq
        && netdev->n_rxq == common->requested_n_rxq
        && common->mtu == common->requested_mtu
        && eth_addr_equals(common->hwaddr, dev->requested_hwaddr)
        && common->socket_id == common->requested_socket_id
        && netdev_doca_is_started(dev)
        && !netdev_is_reconf_required(&dev->esw_eth->common.up)) {
        /* Reconfiguration is unnecessary. */
        goto out;
    }

    netdev_doca_port_stop(dev);

    if (!dev->is_representor
        && netdev_is_reconf_required(&dev->esw_eth->common.up)) {
        netdev_reconfigure(&dev->esw_eth->common.up);
    }

    /* DOCA ports use esw_eth's mempool for packet allocation. */
    common->dpdk_mp = dev->esw_eth->common.dpdk_mp;
    common->mtu = dev->esw_eth->common.mtu;
    common->max_packet_len = dev->esw_eth->common.max_packet_len;
    common->hw_ol_features = dev->esw_eth->common.hw_ol_features;
    netdev_dpdk_common_update_ol_flags(common);
    common->socket_id = common->requested_socket_id;

    if (dev->is_representor && dev->eth
        && dev->eth->common.mtu != common->mtu) {
        netdev_set_mtu(&dev->eth->common.up, common->mtu);
        if (netdev_is_reconf_required(&dev->eth->common.up)) {
            netdev_reconfigure(&dev->eth->common.up);
        }
    }

    netdev->n_txq = common->requested_n_txq;
    netdev->n_rxq = common->requested_n_rxq;
    if (dev->is_representor) {
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

    rte_free(common->tx_q);
    common->tx_q = NULL;

    err = doca_eth_dev_init(dev);
    if (err) {
        goto out;
    }

    /* If both requested and actual hw-addr were previously
     * unset (initialized to 0), then first device init above
     * will have set actual hw-addr to something new.
     * This would trigger spurious MAC reconfiguration unless
     * the requested MAC is kept in sync.
     *
     * This is harmless in case requested_hwaddr was
     * configured by the user, as netdev_dpdk_set_dev_etheraddr()
     * will have succeeded to get to this point. */
    dev->requested_hwaddr = common->hwaddr;

    free(dev->sw_tx_stats);
    dev->sw_tx_stats = xzalloc(netdev->n_txq * sizeof *dev->sw_tx_stats);

    common->tx_q = dpdk_zmalloc(netdev->n_txq * sizeof *common->tx_q);
    if (!common->tx_q) {
        err = ENOMEM;
        goto out;
    }

    netdev_change_seq_changed(netdev);

out:
    ovs_mutex_unlock(&dev->mutex);
    return err;
}

static int
netdev_doca_construct(struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    netdev_dpdk_common_construct(&dev->common, SOCKET0);

    ovs_mutex_init(&dev->mutex);
    dev->port_id = DPDK_ETH_PORT_ID_INVALID;
    dev->esw_eth = NULL;
    dev->eth = NULL;
    dev->devargs = NULL;
    dev->attached = false;
    dev->sw_tx_stats = NULL;
    dev->esw_ctx = NULL;
    dev->port = NULL;
    dev->peer_name = NULL;
    dev->dev_rep = NULL;
    dev->egress_entry = NULL;
    memset(dev->rss_entries, 0, sizeof dev->rss_entries);

    ovs_list_push_back(&doca_list, &dev->list_node);

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

    /* In some kernels, there is a controller prefix, for example "c1pf0".
     * Have a pointer that skips it. */
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

    /* HPF's phys_port_name for example c1pf0. */
    if (len == 3 && !strncmp(phys_port_name, "pf", 2)) {
        len = snprintf(devargs, maxlen, "%s,%s,representor=%.*s(pf%d)vf65535",
                       pci, mlx5_devargs,
                       (int) (phys_port_name - phys_port_name_),
                       phys_port_name_, port);
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
    len = snprintf(devargs, maxlen, "%s,%s,representor=%.*s(%.*s)%s", pci,
                   mlx5_devargs, (int) (phys_port_name - phys_port_name_),
                   phys_port_name_, (int) (rep_part - phys_port_name),
                   phys_port_name, rep_part);
    if (len < 0 || len >= maxlen) {
        VLOG_ERR("%s: Failed to format devargs for representor port", name);
        return NULL;
    }

    return devargs;
}

static struct netdev_doca *
netdev_doca_lookup_by_port_id(dpdk_port_t port_id)
{
    struct netdev_doca *dev;

    LIST_FOR_EACH (dev, list_node, &doca_list) {
        if (dev->port_id == port_id) {
            return dev;
        }
    }

    return NULL;
}

static int
netdev_doca_acquire_esw_eth(struct netdev_doca *dev)
{
    char esw_name[PCI_PRI_STR_SIZE + sizeof "doca-esw-"];
    struct netdev_dpdk_eth *esw_eth;
    struct netdev *esw_netdev;
    int err;

    if (dev->esw_eth) {
        return 0;
    }

    if (!dev->esw_ctx || !dev->esw_ctx->pci_addr[0]) {
        return ENODEV;
    }

    /* The ESW manager port's shadow probed this device and owns the queues
     * every DOCA port transmits on. */
    snprintf(esw_name, sizeof esw_name, "doca-esw-%s", dev->esw_ctx->pci_addr);

    err = netdev_open(esw_name, "dpdk", &esw_netdev);
    if (err) {
        VLOG_WARN("Failed to open ESW manager netdev '%s': %s",
                  esw_name, ovs_strerror(err));
        return err;
    }

    esw_eth = netdev_dpdk_eth_cast(esw_netdev);
    if (!rte_eth_dev_is_valid_port(esw_eth->port_id)) {
        VLOG_WARN("ESW manager netdev '%s' is not probed", esw_name);
        netdev_close(esw_netdev);
        return ENODEV;
    }

    dev->esw_eth = esw_eth;
    VLOG_INFO("Acquired ESW manager '%s' (port "DPDK_PORT_ID_FMT") for "
              "port "DPDK_PORT_ID_FMT, esw_name, esw_eth->port_id,
              dev->port_id);
    return 0;
}

static int
netdev_doca_set_config(struct netdev *netdev, const struct smap *args,
                       char **errp)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_dpdk_common *common = &dev->common;
    const char *netdev_name = netdev_get_name(netdev);
    char generated[PATH_MAX];
    const char *new_devargs;
    char iface[IFNAMSIZ];
    const char *vf_mac;
    int err = 0;
    bool is_rep;

    ovs_mutex_lock(&dev->mutex);

    memset(iface, 0, sizeof iface);
    if (!dev->devargs) {
        new_devargs = netdev_doca_generate_devargs(netdev_name, generated,
                                                   sizeof generated, iface);
        if (!new_devargs) {
            VLOG_WARN("%s: Could not generate DPDK devargs",
                      netdev_get_name(netdev));
            err = ENODEV;
            goto out;
        }

        dev->devargs = xstrdup(new_devargs);
    }

    is_rep = strstr(dev->devargs, "representor=");
    dev->is_representor = is_rep;

    /* A representor is probed only after its ESW manager has created the
     * shared context.  Until then, leave the port without configuration. */
    if (is_rep) {
        struct netdev_doca_esw_key esw_key;
        struct netdev_doca_esw_ctx *esw;

        if (netdev_doca_esw_key_parse(dev->devargs, &esw_key)) {
            VLOG_ERR("%s: ESW key parsing failed for %s",
                     netdev_name, dev->devargs);
            err = EINVAL;
            goto out;
        }

        esw = refmap_try_ref(netdev_doca_esw_rfm, &esw_key);
        if (!esw) {
            goto out;
        }

        refmap_unref(netdev_doca_esw_rfm, esw);
    }

    /* Don't probe again once this port's shadow dpdk netdev is up. */
    if (!dev->eth) {
        struct ds probe_devargs = DS_EMPTY_INITIALIZER;
        char shadow_name[128];

        err = netdev_doca_esw_prepare(dev, dev->devargs, &probe_devargs);
        if (!err) {
            struct netdev_dpdk_eth *eth = NULL;

            if (is_rep) {
                snprintf(shadow_name, sizeof shadow_name, "doca-eth-%s",
                         netdev_name);
            } else {
                snprintf(shadow_name, sizeof shadow_name, "doca-esw-%s",
                         dev->esw_ctx->pci_addr);
            }

            err = netdev_doca_open_shadow(shadow_name,
                                          ds_cstr(&probe_devargs),
                                          is_rep, &eth);
            if (!err) {
                struct netdev_doca *dup_dev;
                struct rte_eth_dev_info info;
                int sid;

                dup_dev = netdev_doca_lookup_by_port_id(eth->port_id);
                if (dup_dev) {
                    VLOG_WARN_BUF(errp, "'%s' is trying to use device '%s' "
                                  "which is already in use by '%s'",
                                  netdev_name, dev->devargs,
                                  netdev_get_name(&dup_dev->common.up));
                    netdev_close(&eth->common.up);
                    err = EADDRINUSE;
                } else if (!is_rep
                           && !rte_eth_dev_info_get(eth->port_id, &info)
                           && (*info.dev_flags & RTE_ETH_DEV_REPRESENTOR)) {
                    VLOG_WARN_BUF(errp, "'%s' shadow matched representor "
                                  "port "DPDK_PORT_ID_FMT,
                                  netdev_name, eth->port_id);
                    netdev_close(&eth->common.up);
                    err = ENODEV;
                } else {
                    dev->eth = eth;
                    dev->port_id = eth->port_id;
                    dev->attached = true;
                    sid = rte_eth_dev_socket_id(dev->port_id);
                    common->requested_socket_id = sid < 0 ? SOCKET0 : sid;
                    if (!is_rep) {
                        dev->esw_eth = eth;
                    }

                    netdev_request_reconfigure(netdev);
                }
            }
        }
        if (err && dev->esw_ctx && !dev->eth) {
            netdev_doca_dev_close(dev);
        }

        ds_destroy(&probe_devargs);
    }

    if (!err && is_rep && !dev->esw_eth) {
        err = netdev_doca_acquire_esw_eth(dev);
    }

    if (err) {
        goto out;
    }

    if (!dev->is_representor && dev->esw_eth) {
        struct smap esw_config;

        smap_clone(&esw_config, args);
        smap_replace(&esw_config, "dpdk-devargs", dev->esw_eth->devargs);
        err = netdev_set_config(&dev->esw_eth->common.up, &esw_config, errp);
        smap_destroy(&esw_config);
        if (err) {
            goto out;
        }
    }

    vf_mac = smap_get(args, "dpdk-vf-mac");
    if (vf_mac) {
        struct eth_addr mac;

        if (!dev->is_representor) {
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

out:
    ovs_mutex_unlock(&dev->mutex);

    return err;
}

static void
netdev_doca_dispatch_rx(struct netdev_doca *dev, uint16_t queue_id,
                        struct dp_packet_batch *rx_batch)
{
    struct netdev_doca_port_queue **pq = dev->esw_ctx->port_queues;
    struct netdev_dpdk_common *common = &dev->common;
    struct dp_packet *pkt;
    uint64_t old_count;
    uint32_t pkt_size;
    uint32_t port_id;
    int dropped = 0;
    int rv;

    DP_PACKET_BATCH_FOR_EACH (i, pkt, rx_batch) {
        if (!dp_packet_has_flow_mark(pkt, &port_id)) {
            dp_packet_delete(pkt);
            dropped++;
            continue;
        }

        pkt->has_mark = false;
        if (!rte_eth_dev_is_valid_port(port_id)) {
            dp_packet_delete(pkt);
            dropped++;
            continue;
        }

        pkt_size = dp_packet_size(pkt);
        rv = rte_ring_sp_enqueue(pq[port_id][queue_id].ring, pkt);
        if (rv) {
            dp_packet_delete(pkt);
            dropped++;
            continue;
        }

        atomic_add_relaxed(&pq[port_id][queue_id].n_packets, 1, &old_count);
        atomic_add_relaxed(&pq[port_id][queue_id].n_bytes, pkt_size,
                           &old_count);
    }

    if (OVS_UNLIKELY(dropped)) {
        rte_spinlock_lock(&common->stats_lock);
        common->stats.rx_dropped += dropped;
        rte_spinlock_unlock(&common->stats_lock);
    }
}

static int
netdev_doca_rxq_recv(struct netdev_rxq *rxq, struct dp_packet_batch *batch,
                     int *qfill)
{
    struct netdev_doca *dev = netdev_doca_cast(rxq->netdev);
    struct netdev_dpdk_common *common = &dev->common;
    struct netdev_doca_port_queue *pq;
    dpdk_port_t port_id;
    int nb_rx;

    if (OVS_UNLIKELY(!(common->flags & NETDEV_UP) ||
                     !netdev_doca_is_started(dev))) {
        return EAGAIN;
    }

    port_id = dev->port_id;

    if (!dev->is_representor) {
        struct dp_packet_batch rx_batch;

        dp_packet_batch_init(&rx_batch);
        if (!netdev_dpdk_eth_rx_burst(dev->esw_eth, rxq->queue_id,
                                      &rx_batch)) {
            return EAGAIN;
        }

        netdev_doca_dispatch_rx(dev, rxq->queue_id, &rx_batch);
    }

    pq = &dev->esw_ctx->port_queues[port_id][rxq->queue_id];
    batch->count =
        rte_ring_sc_dequeue_burst(pq->ring, (void **) batch->packets,
                                  NETDEV_MAX_BURST, NULL);
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

static void
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
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_dpdk_common *common = &dev->common;
    uint32_t port_id_meta = dev->port_id;
    int batch_cnt = dp_packet_batch_size(batch);
    struct netdev_dpdk_sw_stats stats;
    struct dp_packet *packet;
    uint64_t n_bytes = 0;
    uint64_t old_count;
    size_t cnt;
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

    cnt = netdev_dpdk_common_send(common, batch, &stats);
    batch->count = cnt;
    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        /* Set metadata for egress pipe rules to match on. */
        packet_set_meta(packet, port_id_meta);
        n_bytes += dp_packet_size(packet);
    }

    atomic_add_relaxed(&dev->sw_tx_stats[qid].n_packets, cnt, &old_count);
    atomic_add_relaxed(&dev->sw_tx_stats[qid].n_bytes, n_bytes, &old_count);

    dropped = netdev_dpdk_eth_tx_burst(dev->esw_eth, qid, pkts, cnt);

    stats.tx_failure_drops += dropped;
    dropped += batch_cnt - cnt;
    if (OVS_UNLIKELY(dropped)) {
        struct netdev_dpdk_sw_stats *sw_stats = common->sw_stats;

        rte_spinlock_lock(&common->stats_lock);
        common->stats.tx_dropped += dropped;
        sw_stats->tx_failure_drops += stats.tx_failure_drops;
        rte_spinlock_unlock(&common->stats_lock);
    }

    if (OVS_UNLIKELY(concurrent_txq)) {
        rte_spinlock_unlock(&common->tx_q[qid].tx_lock);
    }

    return 0;
}

static int
netdev_doca_get_numa_id(const struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    int numa = netdev_dpdk_common_get_numa_id(&dev->common);
    ovs_mutex_unlock(&dev->mutex);

    return numa;
}

static int
netdev_doca_set_etheraddr(struct netdev *netdev, const struct eth_addr mac)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    if (!eth_addr_equals(dev->requested_hwaddr, mac)) {
        dev->requested_hwaddr = mac;
        netdev_request_reconfigure(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_doca_get_etheraddr(const struct netdev *netdev, struct eth_addr *mac)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    netdev_dpdk_common_get_etheraddr(&dev->common, mac);
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_doca_get_mtu(const struct netdev *netdev, int *mtup)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    netdev_dpdk_common_get_mtu(&dev->common, mtup);
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_doca_get_ifindex(const struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    int ifindex;

    ovs_mutex_lock(&dev->mutex);
    ifindex = netdev_dpdk_common_get_ifindex(&dev->common);
    ovs_mutex_unlock(&dev->mutex);

    return ifindex;
}

static int
netdev_doca_get_carrier(const struct netdev *netdev, bool *carrier)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    if (dev->eth) {
        *carrier = netdev_get_carrier(&dev->eth->common.up);
        return 0;
    }

    if (!dev->esw_eth) {
        *carrier = false;
        return 0;
    }

    *carrier = netdev_get_carrier(&dev->esw_eth->common.up);
    return 0;
}

static long long int
netdev_doca_get_carrier_resets(const struct netdev *netdev)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    if (dev->eth) {
        return netdev_get_carrier_resets(&dev->eth->common.up);
    }

    if (!dev->esw_eth) {
        return 0;
    }

    return netdev_get_carrier_resets(&dev->esw_eth->common.up);
}

static int
netdev_doca_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw_ctx = dev->esw_ctx;
    struct netdev_dpdk_common *common = &dev->common;
    dpdk_port_t port_id = dev->port_id;
    uint64_t n_packets, n_bytes;

    if (!dev->esw_eth) {
        return EOPNOTSUPP;
    }

    if (!dev->is_representor) {
        int err = netdev_get_stats(&dev->esw_eth->common.up, stats);

        if (!err) {
            rte_spinlock_lock(&common->stats_lock);
            stats->tx_dropped += common->stats.tx_dropped;
            stats->rx_dropped += common->stats.rx_dropped;
            rte_spinlock_unlock(&common->stats_lock);
        }
        return err;
    }

    memset(stats, 0, sizeof *stats);

    for (unsigned int i = 0; i < esw_ctx->n_rxq; i++) {
        atomic_read_relaxed(&esw_ctx->port_queues[port_id][i].n_packets,
                            &n_packets);
        atomic_read_relaxed(&esw_ctx->port_queues[port_id][i].n_bytes,
                            &n_bytes);
        stats->rx_packets += n_packets;
        stats->rx_bytes += n_bytes;
    }

    for (int i = 0; i < netdev->n_txq; i++) {
        atomic_read_relaxed(&dev->sw_tx_stats[i].n_packets, &n_packets);
        atomic_read_relaxed(&dev->sw_tx_stats[i].n_bytes, &n_bytes);
        stats->tx_packets += n_packets;
        stats->tx_bytes += n_bytes;
    }

    rte_spinlock_lock(&common->stats_lock);
    stats->tx_dropped = common->stats.tx_dropped;
    stats->rx_dropped = common->stats.rx_dropped;
    rte_spinlock_unlock(&common->stats_lock);

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

    if (!dev->esw_eth) {
        return EOPNOTSUPP;
    }

    return netdev_get_features(&dev->esw_eth->common.up, current, advertised,
                               supported, peer);
}

static int
netdev_doca_get_speed(const struct netdev *netdev, uint32_t *current,
                      uint32_t *max)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    if (!dev->esw_eth) {
        return EOPNOTSUPP;
    }

    return netdev_get_speed(&dev->esw_eth->common.up, current, max);
}

static int
netdev_doca_set_tx_multiq(struct netdev *netdev, unsigned int n_txq)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    if (dev->common.requested_n_txq != (int) n_txq) {
        dev->common.requested_n_txq = n_txq;
        netdev_request_reconfigure(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_doca_set_miimon(struct netdev *netdev OVS_UNUSED,
                       long long int interval OVS_UNUSED)
{
    return 0;
}

static int
netdev_doca_update_flags(struct netdev *netdev, enum netdev_flags off,
                         enum netdev_flags on, enum netdev_flags *old_flagsp)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_dpdk_common *common = &dev->common;

    ovs_mutex_lock(&dev->mutex);
    *old_flagsp = common->flags;
    common->flags |= on;
    common->flags &= ~off;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static struct netdev_rxq *
netdev_doca_rxq_alloc(void)
{
    struct netdev_rxq *rxq = dpdk_zmalloc(sizeof *rxq);

    return rxq;
}

static int
netdev_doca_rxq_construct(struct netdev_rxq *rxq OVS_UNUSED)
{
    return 0;
}

static void
netdev_doca_rxq_destruct(struct netdev_rxq *rxq OVS_UNUSED)
{
}

static void
netdev_doca_rxq_dealloc(struct netdev_rxq *rxq)
{
    rte_free(rxq);
}

static int
netdev_doca_get_config(const struct netdev *netdev, struct smap *args)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    smap_add_format(args, "n_rxq", "%d", dev->common.requested_n_rxq);
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static const struct netdev_class netdev_doca_class = {
    .type = "doca",
    .is_pmd = true,
    .run = netdev_doca_run,
    .wait = netdev_doca_wait,
    .init = netdev_doca_class_init,
    .alloc = netdev_doca_alloc,
    .construct = netdev_doca_construct,
    .destruct = netdev_doca_destruct,
    .dealloc = netdev_doca_dealloc,
    .get_config = netdev_doca_get_config,
    .set_config = netdev_doca_set_config,
    .get_numa_id = netdev_doca_get_numa_id,
    .set_tx_multiq = netdev_doca_set_tx_multiq,
    .send = netdev_doca_send,
    .set_etheraddr = netdev_doca_set_etheraddr,
    .get_etheraddr = netdev_doca_get_etheraddr,
    .get_mtu = netdev_doca_get_mtu,
    .set_mtu = netdev_doca_set_mtu,
    .get_ifindex = netdev_doca_get_ifindex,
    .get_carrier = netdev_doca_get_carrier,
    .get_carrier_resets = netdev_doca_get_carrier_resets,
    .get_stats = netdev_doca_get_stats,
    .get_custom_stats = netdev_doca_get_custom_stats,
    .get_features = netdev_doca_get_features,
    .get_speed = netdev_doca_get_speed,
    .get_status = netdev_doca_get_status,
    .set_miimon_interval = netdev_doca_set_miimon,
    .update_flags = netdev_doca_update_flags,
    .reconfigure = netdev_doca_reconfigure,
    .rxq_alloc = netdev_doca_rxq_alloc,
    .rxq_construct = netdev_doca_rxq_construct,
    .rxq_destruct = netdev_doca_rxq_destruct,
    .rxq_dealloc = netdev_doca_rxq_dealloc,
    .rxq_recv = netdev_doca_rxq_recv,
};

void
netdev_doca_register(void)
{
    netdev_register_provider(&netdev_doca_class);
}
