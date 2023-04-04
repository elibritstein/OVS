/*
 * Copyright (c) 2023 NVIDIA Corporation.
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

#include <doca_flow.h>
#include <rte_flow.h>
#include <sys/types.h>

#include "ovs-doca.h"
#include "dp-packet.h"
#include "dpdk-offload-provider.h"
#include "openvswitch/vlog.h"
#include "offload-metadata.h"
#include "netdev-dpdk.h"
#include "netdev-vport.h"
#include "util.h"

/*
 * DOCA offload implementation for DPDK provider.
 *
 * The CT offload implementation over basic pipes is designed as such:
 *
 * +--------------------------------------------------------------------------------------------+
 * |  Control pipes                                                                             |
 * |                                                                                            |
 * |           ┌─[ CT Zone X ]─────┐          +---------------------------------+               |
 * |           │  ┌─[ CT Zone Y ]─────┐       | Basic pipes                     |               |
 * |           │  │  ┌─[ CT Zone Z ]─────┐    |                                 |               |
 * |           │  │  │  ┌─────────┐      │    |                                 |               |
 * |           │  │  │  │ct_zone=Z├──────┼──────────────────────────────────────────────┐       |
 * |           │  │  │  └─────────┘hit   │    |                                 |       │       |
 * |           │  │  │                   │    |     ┌─[ IPv4 x UDP ]────┐       |       │       |
 * |           │  │  │    ┌──────────┐   │    |     │                   │       |       │       |
 * | ┌───────┐ │  │  │    │IPv4 + UDP├───┼─────────►│  ┌─[ IPv4 x TCP ]────┐    |       │       |
 * | │Pre-CT ├──────►│    └──────────┘hit│    |     │  │                   │    |       │       |
 * | └───────┘ │  │  │    ┌──────────┐   │    |     │  │  ┌───────┐        │    |       │       |
 * |           │  │  │    │IPv4 + TCP├───┼───────────────►│CT-SNAT├──┐     │    |       │       |
 * |           │  │  │    └──────────┘hit│    |     │  │  └───┬───┘  │     │    |       │       |
 * |           │  │  │                   │    |     │  │ miss │      │hit  │    |    ┌──▼────┐  |
 * |           │  │  │       ┌─────────┐ │    |     │  │  ┌───▼───┐  └──────────────►│       │  |
 * |           │  │  │       │Catch-all│ │    |     │  │  │CT-DNAT├─────────────────►│Post-CT│  |
 * |           └──│  │       └────┬────┘ │    |     │  │  └───┬───┘  ┌──────────────►│       │  |
 * |              └──│            │      │    |     │  │ miss │      │hit  │    |    └───────┘  |
 * |                 └────────────┼──────┘    |     │  │  ┌───▼───┐  │     │    |               |
 * |                              │           |     │  │  │  CT   ├──┘     │    |               |
 * |                              │           |     │  │  └───┬───┘        │    |               |
 * |                              │           |     └──│ miss │            │    |               |
 * |                              │           |        └──────┼────────────┘    |               |
 * |                              │           +------------│--│-----------------+               |
 * |                              ▼                        ▼  ▼                                 |
 * |                       ┌─[ Miss pipe ]───────────────────────────┐                          |
 * |                       │         Go to software datapath         │                          |
 * |                       └─────────────────────────────────────────┘                          |
 * +--------------------------------------------------------------------------------------------+
 *
 * This model is replicated once per eswitch.
 *
 * A megaflow that contains a 'ct()' action is split
 * into its 'pre-CT' and 'post-CT' part. The pre-CT is inserted
 * into the eswitch root pipe, and contains the megaflow original
 * match.
 *
 * On match, to execute CT, the packet is sent to the 'CT-zone' pipes,
 * one pipe per CT zone ID. If the ct_zone value is already set on the packet
 * and the value matches that of the current CT-zone pipe, then CT is known
 * to have already been executed. The packet is thus immediately forwarded to
 * post-CT. Post-CT contains the rest of the original megaflow that was not
 * used in pre-CT.
 *
 * If this ct_zone match fails, then either CT was never executed, or
 * it was executed in a different CT zone. If it matches the currently
 * supported CT (network x protocol) tuple, then its ct_zone is set and
 * it is forwarded to the corresponding CT pipe chain. If no (net x proto)
 * tuple matches, then CT is not supported for this flow and the packet
 * goes to software.
 *
 * A CT pipe chain exist per supported (net x proto) tuple, e.g.
 * there is one for (ipv4 + TCP), one for (ipv4 + UDP), etc.
 *
 * Each chain is constituted of all supported CT actions:
 * plain CT forwarding with no packet modification, CT-SNAT with
 * header source fields modifications, or CT-DNAT with header
 * destination fields modifications.
 *
 * If no entry is found in the CT-SNAT pipe, the CT-DNAT pipe
 * is attempted, then finally the CT-PLAIN pipe. If any of those
 * three hit, then CT is executed and the packet is forwarded to post-CT.
 *
 * On the final miss in CT-PLAIN, the packet is forwarded to the
 * miss pipe, which will send it to the software datapath.
 *
 * The diagram was drawn with https://asciiflow.com/ and edited in VIM.
 */

#define ENTRY_PROCESS_TIMEOUT_MS 1000
#define NUM_ZONE_FLOWS 4
/* TBD until doca can support insertion from more than one queue */
#define AUX_QUEUE 0

VLOG_DEFINE_THIS_MODULE(dpdk_offload_doca);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);

enum ct_nw_type {
    CT_NW_IP4, /* CT on IPv4 networks. */
    NUM_CT_NW,
};

enum ct_tp_type {
    CT_TP_UDP, /* CT on UDP datagrams. */
    CT_TP_TCP, /* CT on TCP streams. */
    NUM_CT_TP,
};

enum ct_action_type {
    CT_ACTION_PLAIN, /* Plain CT action, without packet modification. */
    CT_ACTION_DNAT, /* CT with destination fields header rewrite. */
    CT_ACTION_SNAT, /* CT with source fields header rewrite. */
    CT_ACTION_NULL,
    NUM_CT_ACTIONS = CT_ACTION_NULL,
};

/* As described in the model above, a CT chain executes
 * several CT actions, each done by its supported CT pipe.
 * For each of the CT action type, a match is attempted
 * in its pipe, and on miss goes to the next CT action.
 *
 * This introduces dependencies between the CT pipes.
 * As we attempt CT-SNAT first, then CT-DNAT, then CT-PLAIN,
 * that means the CT-SNAT depends on CT-DNAT to exist, etc.
 *
 * Express this in the following table, used to properly
 * order pipe creation and destruction.
 */

enum ct_action_type ct_action_next[] = {
    [CT_ACTION_PLAIN] = CT_ACTION_NULL, /* No dependency. */
    [CT_ACTION_DNAT] = CT_ACTION_PLAIN,
    [CT_ACTION_SNAT] = CT_ACTION_DNAT,
    [CT_ACTION_NULL] = CT_ACTION_SNAT, /* Chains start here. */
};

struct doca_basic_pipe_ctx {
    struct doca_flow_pipe *pipe;
    struct doca_ctl_pipe_ctx *fwd_pipe_ctx;
    struct doca_ctl_pipe_ctx *miss_pipe_ctx;
};

struct doca_ctl_pipe_ctx {
    struct doca_flow_pipe *pipe;
};

OVS_ASSERT_PACKED(struct doca_eswitch_ctx,
    struct doca_flow_port *esw_port;
    struct doca_ctl_pipe_ctx *root_pipe_ctx;
    struct doca_basic_pipe_ctx ct_pipes[NUM_CT_NW][NUM_CT_TP][NUM_CT_ACTIONS];
    struct fixed_rule zone_flows[2][NUM_ZONE_FLOWS][MAX_ZONE_ID + 1];
);

OVS_ASSERT_PACKED(struct doca_ctl_pipe_key,
    uint32_t group_id;
    uint32_t esw_mgr_port_id;
);

struct doca_ctl_pipe_arg {
    struct netdev *netdev;
    uint32_t group_id;
};

static struct doca_eswitch_ctx *
doca_eswitch_ctx_get(struct netdev *netdev);

static inline enum ct_nw_type
l3_to_nw_type(enum doca_flow_l3_type l3_type)
{
    switch (l3_type) {
    case DOCA_FLOW_L3_TYPE_IP4: return CT_NW_IP4;
    case DOCA_FLOW_L3_TYPE_IP6:
    case DOCA_FLOW_L3_TYPE_NONE: return NUM_CT_NW;
    };
    return NUM_CT_NW;
}

static inline enum ct_tp_type
l4_to_tp_type(enum doca_flow_l4_type_ext l4_type)
{
    switch (l4_type) {
    case DOCA_FLOW_L4_TYPE_EXT_TCP: return CT_TP_TCP;
    case DOCA_FLOW_L4_TYPE_EXT_UDP: return CT_TP_UDP;
    case DOCA_FLOW_L4_TYPE_EXT_ICMP:
    case DOCA_FLOW_L4_TYPE_EXT_ICMP6:
    case DOCA_FLOW_L4_TYPE_EXT_NONE: return NUM_CT_TP;
    }
    return NUM_CT_TP;
}

static inline enum ct_action_type
get_ct_action_type(uint32_t group, struct doca_flow_actions *actions)
{
    struct doca_flow_header_format *outer;

    switch (group) {
    case CT_TABLE_ID:
        return CT_ACTION_PLAIN;
    case CTNAT_TABLE_ID:
        /* Get the 'first' action of the CT chain. */
        if (!actions) {
            return ct_action_next[CT_ACTION_NULL];
        }
        outer = &actions->outer;
        /* Determine SNAT or DNAT. */
        /* In case of a PAT, L3 type doesn't matter. */
        if (outer->l4_type_ext == DOCA_FLOW_L4_TYPE_EXT_TCP) {
            if (outer->tcp.l4_port.dst_port) {
                actions->action_idx = 1;
                return CT_ACTION_DNAT;
            }
            if (outer->tcp.l4_port.src_port) {
                actions->action_idx = 1;
                return CT_ACTION_SNAT;
            }
        } else if (outer->l4_type_ext == DOCA_FLOW_L4_TYPE_EXT_UDP) {
            if (outer->udp.l4_port.dst_port) {
                actions->action_idx = 1;
                return CT_ACTION_DNAT;
            }
            if (outer->udp.l4_port.src_port) {
                actions->action_idx = 1;
                return CT_ACTION_SNAT;
            }
        }
        if (outer->l3_type == DOCA_FLOW_L3_TYPE_IP4) {
            if (outer->ip4.dst_ip) {
                return CT_ACTION_DNAT;
            }
            if (outer->ip4.src_ip) {
                return CT_ACTION_SNAT;
            }
        } else if (outer->l3_type == DOCA_FLOW_L3_TYPE_IP6) {
            if (!is_all_zeros(&outer->ip6.dst_ip, sizeof outer->ip6.dst_ip)) {
                return CT_ACTION_DNAT;
            }
            if (!is_all_zeros(&outer->ip6.src_ip, sizeof outer->ip6.src_ip)) {
                return CT_ACTION_SNAT;
            }
        } else {
            /* Redirection is for CT-NAT but there is actually no NAT action.
             * Go to plain-ct.
             */
            return CT_ACTION_PLAIN;
        }
        OVS_NOT_REACHED();
    default:
        return CT_ACTION_NULL;
    }
    OVS_NOT_REACHED();
}

static inline bool
is_ct_group(uint32_t group)
{
    return group == CT_TABLE_ID || group == CTNAT_TABLE_ID;
}

static bool
is_ct_zone_group_id(uint32_t group)
{
    return ((group >= CT_TABLE_ID + MIN_ZONE_ID &&
             group <= CT_TABLE_ID + MAX_ZONE_ID) ||
            (group >= CTNAT_TABLE_ID + MIN_ZONE_ID &&
             group <= CTNAT_TABLE_ID + MAX_ZONE_ID));
}

static inline enum ct_action_type
ct_action_prev(enum ct_action_type cur)
{
    for (int i = 0; i < NUM_CT_ACTIONS; i++) {
        if (ct_action_next[i] == cur) {
            return i;
        }
    }
    return CT_ACTION_NULL;
}

static int
doca_ctl_pipe_ctx_init(void *ctx_, void *arg_, uint32_t id OVS_UNUSED)
{
    struct doca_ctl_pipe_ctx *ctx = ctx_;
    struct doca_ctl_pipe_arg *arg = arg_;
    struct doca_flow_pipe_cfg cfg;
    char pipe_name[50];
    uint32_t group_id;
    bool is_root;
    int ret;

    /* The pipe for recirc = 0 without any tunnel involved is
     * global and shared among devices on the esw. It is a root pipe.
     */
    group_id = arg->group_id;
    is_root = group_id == 0;
    snprintf(pipe_name, sizeof pipe_name, "OVS_CTL_PIPE_%" PRIu32, group_id);

    memset(&cfg, 0, sizeof cfg);
    cfg.attr.name = pipe_name;
    cfg.attr.type = DOCA_FLOW_PIPE_CONTROL;
    cfg.attr.is_root = is_root;
    cfg.port = doca_flow_port_switch_get();

    if (is_ct_zone_group_id(group_id)) {
        cfg.attr.nb_flows = NUM_ZONE_FLOWS;
    } else if (group_id == MISS_TABLE_ID) {
        cfg.attr.nb_flows = 1;
    } else if (group_id == CT_TABLE_ID || group_id == CTNAT_TABLE_ID) {
        cfg.attr.nb_flows = OVS_DOCA_MAX_CT_RULES;
    }

    ret = doca_flow_pipe_create(&cfg, NULL, NULL, &ctx->pipe);
    if (ret) {
        VLOG_ERR("%s: Failed to create ctl pipe: %d (%s)",
                 netdev_get_name(arg->netdev), ret, doca_get_error_string(ret));
    }
    return ret;
}

static void
doca_ctl_pipe_ctx_uninit(void *ctx_)
{
    struct doca_ctl_pipe_ctx *ctx = ctx_;

    doca_flow_pipe_destroy(ctx->pipe);
    ctx->pipe = NULL;
}

static struct ds *
dump_doca_ctl_pipe_ctx(struct ds *s, void *key_, void *ctx_, void *arg_ OVS_UNUSED)
{
    struct doca_ctl_pipe_key *key = key_;
    struct doca_ctl_pipe_ctx *ctx = ctx_;

    if (ctx) {
        ds_put_format(s, "pipe=%p, ", ctx->pipe);
    }
    ds_put_format(s, "group_id=%"PRIu32", ", key->group_id);

    return s;
}

static struct offload_metadata *doca_ctl_pipe_md;

static void
doca_ctl_pipe_md_init(void)
{
    static struct ovsthread_once init_once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&init_once)) {
        struct offload_metadata_parameters params = {
            .priv_size = sizeof(struct doca_ctl_pipe_ctx),
            .priv_init = doca_ctl_pipe_ctx_init,
            .priv_uninit = doca_ctl_pipe_ctx_uninit,
        };
        unsigned int nb_thread = netdev_offload_thread_nb();

        doca_ctl_pipe_md = offload_metadata_create(nb_thread, "doca_ctl_pipe",
                                                   sizeof(struct doca_ctl_pipe_key),
                                                   dump_doca_ctl_pipe_ctx,
                                                   params);

        ovsthread_once_done(&init_once);
    }
}

static struct doca_ctl_pipe_ctx *
doca_ctl_pipe_ctx_ref(struct netdev *netdev, uint32_t group_id)
{
    struct doca_ctl_pipe_key key = {
        .group_id = group_id,
        .esw_mgr_port_id = netdev_dpdk_get_esw_mgr_port_id(netdev),
    };
    struct doca_ctl_pipe_arg arg = {
        .netdev = netdev,
        .group_id = group_id,
    };

    doca_ctl_pipe_md_init();
    return offload_metadata_priv_get(doca_ctl_pipe_md, &key, &arg, NULL, true);
}

static void
doca_ctl_pipe_ctx_unref(struct doca_ctl_pipe_ctx *ctx)
{
    doca_ctl_pipe_md_init();
    offload_metadata_priv_unref(doca_ctl_pipe_md,
                                netdev_offload_thread_id(),
                                ctx);
}

static struct reg_field reg_fields[] = {
    [REG_FIELD_CT_STATE] = {
        .type = REG_TYPE_TAG,
        .index = 0,
        .offset = 0,
        .mask = 0x000000FF,
    },
    [REG_FIELD_CT_ZONE] = {
        .type = REG_TYPE_TAG,
        .index = 0,
        .offset = 8,
        .mask = 0x000000FF,
    },
    [REG_FIELD_TUN_INFO] = {
        .type = REG_TYPE_TAG,
        .index = 0,
        .offset = 16,
        .mask = 0x0000FFFF,
    },
    [REG_FIELD_CT_MARK] = {
        .type = REG_TYPE_TAG,
        .index = 1,
        .offset = 0,
        .mask = 0xFFFFFFFF,
    },
    [REG_FIELD_CT_LABEL_ID] = {
        .type = REG_TYPE_TAG,
        .index = 2,
        .offset = 0,
        .mask = 0xFFFFFFFF,
    },
    [REG_FIELD_CT_CTX] = {
        .type = REG_TYPE_META,
        .index = 0,
        .offset = 0,
        .mask = 0x0000FFFF,
    },
    /* Since sFlow and CT will not work concurrently is it safe
     * to have the reg_fields use the same bits for SFLOW_CTX and CT_CTX.
     */
    [REG_FIELD_SFLOW_CTX] = {
        .type = REG_TYPE_META,
        .index = 0,
        .offset = 0,
        .mask = 0x0000FFFF,
    },
    [REG_FIELD_FLOW_INFO] = {
        .type = REG_TYPE_META,
        .index = 0,
        .offset = 16,
        .mask = 0x0000FFFF,
    },
};

static struct reg_field *
dpdk_offload_doca_get_reg_fields(void)
{
    return reg_fields;
}

static void
doca_translate_gre_key_item(const struct rte_flow_item *item,
                            struct doca_flow_match *doca_spec,
                            struct doca_flow_match *doca_mask)
{
    const rte_be32_t *key_spec, *key_mask;

    doca_spec->tun.type = DOCA_FLOW_TUN_GRE;
    doca_mask->tun.type = DOCA_FLOW_TUN_GRE;

    key_spec = item->spec;
    key_mask = item->mask;

    if (item->spec) {
        doca_spec->tun.gre_key = *key_spec;
    }
    if (item->mask) {
        doca_mask->tun.gre_key = *key_mask;
    }
}

static void
doca_translate_gre_item(const struct rte_flow_item *item,
                        struct doca_flow_match *doca_spec,
                        struct doca_flow_match *doca_mask)
{
    const struct rte_gre_hdr *greh_spec, *greh_mask;

    doca_spec->tun.type = DOCA_FLOW_TUN_GRE;
    doca_mask->tun.type = DOCA_FLOW_TUN_GRE;

    greh_spec = (struct rte_gre_hdr *) item->spec;
    greh_mask = (struct rte_gre_hdr *) item->mask;

    if (item->spec) {
        doca_spec->tun.key_present = greh_spec->k;
    }
    if (item->mask) {
        doca_mask->tun.key_present = greh_mask->k;
    }
}

static void
doca_translate_geneve_item(const struct rte_flow_item *item,
                           struct doca_flow_match *doca_spec,
                           struct doca_flow_match *doca_mask)
{
    const struct rte_flow_item_geneve *gnv_spec = item->spec;
    const struct rte_flow_item_geneve *gnv_mask = item->mask;

    if (!item->spec || !item->mask) {
        return;
    }

    doca_spec->tun.type = DOCA_FLOW_TUN_GENEVE;
    doca_spec->tun.geneve.vni =
        get_unaligned_be32(ALIGNED_CAST(ovs_be32 *, gnv_spec->vni));

    doca_mask->tun.type = DOCA_FLOW_TUN_GENEVE;
    doca_mask->tun.geneve.vni =
        get_unaligned_be32(ALIGNED_CAST(ovs_be32 *, gnv_mask->vni));
}

static void
doca_translate_vxlan_item(const struct rte_flow_item *item,
                          struct doca_flow_match *doca_spec,
                          struct doca_flow_match *doca_mask)
{
    const struct rte_flow_item_vxlan *vxlan_spec = item->spec;
    const struct rte_flow_item_vxlan *vxlan_mask = item->mask;
    ovs_be32 spec_vni, mask_vni;

    doca_spec->tun.type = DOCA_FLOW_TUN_VXLAN;
    if (item->spec) {
        spec_vni = get_unaligned_be32(ALIGNED_CAST(ovs_be32 *,
                    vxlan_spec->vni));
        doca_spec->tun.vxlan_tun_id = spec_vni;
    }

    doca_mask->tun.type = DOCA_FLOW_TUN_VXLAN;
    if (item->mask) {
        mask_vni = get_unaligned_be32(ALIGNED_CAST(ovs_be32 *,
                    vxlan_mask->vni));
        doca_mask->tun.vxlan_tun_id = mask_vni;
    }
}

static int
doca_translate_items(struct netdev *netdev OVS_UNUSED,
                     const struct rte_flow_attr *attr,
                     const struct rte_flow_item *items,
                     struct doca_flow_match *doca_spec,
                     struct doca_flow_match *doca_mask)
{
    struct doca_flow_header_format *doca_hdr_spec, *doca_hdr_mask;

    /* Start by filling out outer header match and
     * switch to inner in case we encounter a tnl proto.
     */
    doca_hdr_spec = &doca_spec->outer;
    doca_hdr_mask = &doca_mask->outer;

    for (; items->type != RTE_FLOW_ITEM_TYPE_END; items++) {
        int item_type = items->type;

        if (item_type == RTE_FLOW_ITEM_TYPE_PORT_ID) {
            const struct rte_flow_item_port_id *spec = items->spec;

            /* Only recirc_id 0 (group_id == 0) may hold flows
             * from different source ports since it's the root table.
             * For every other recirc_id we have a table per port and
             * therefore we can skip matching on port id for those
             * tables.
             */
            if (attr->group > 0) {
                continue;
            }

            doca_spec->meta.port_meta = spec->id;
            doca_mask->meta.port_meta = 0xFFFFFFFF;
        } else if (item_type == RTE_FLOW_ITEM_TYPE_ETH) {
            const struct rte_flow_item_eth *spec = items->spec;
            const struct rte_flow_item_eth *mask = items->mask;

            if (items->spec) {
                memcpy(doca_hdr_spec->eth.dst_mac, &spec->dst,
                       sizeof doca_hdr_spec->eth.dst_mac);
                memcpy(doca_hdr_spec->eth.src_mac, &spec->src,
                       sizeof doca_hdr_spec->eth.src_mac);
                doca_hdr_spec->eth.type = spec->type;
            }
            if (items->mask) {
                memcpy(doca_hdr_mask->eth.dst_mac, &mask->dst,
                       sizeof doca_hdr_mask->eth.dst_mac);
                memcpy(doca_hdr_mask->eth.src_mac, &mask->src,
                       sizeof doca_hdr_mask->eth.src_mac);
                doca_hdr_mask->eth.type = mask->type;
            }
        } else if (item_type == RTE_FLOW_ITEM_TYPE_VLAN) {
            const struct rte_flow_item_vlan *spec = items->spec;
            const struct rte_flow_item_vlan *mask = items->mask;

            /* HW supports match on one Ethertype, the Ethertype following the
             * last VLAN tag of the packet (see PRM). DOCA API has only that one.
             * Add a match on it as part of the doca eth header.
             */
            doca_hdr_spec->eth.type = spec->inner_type;
            doca_hdr_mask->eth.type = mask->inner_type;
            doca_hdr_spec->eth_vlan[0].tci = spec->tci;
            doca_hdr_mask->eth_vlan[0].tci = mask->tci;
            doca_hdr_spec->l2_valid_headers = DOCA_FLOW_L2_VALID_HEADER_VLAN_0;
            doca_hdr_mask->l2_valid_headers = DOCA_FLOW_L2_VALID_HEADER_VLAN_0;
        /* L3 */
        } else if (item_type == RTE_FLOW_ITEM_TYPE_IPV4) {
            const struct rte_flow_item_ipv4 *spec = items->spec;
            const struct rte_flow_item_ipv4 *mask = items->mask;

            doca_hdr_spec->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            if (items->spec) {
                doca_hdr_spec->ip4.next_proto = spec->hdr.next_proto_id;
                doca_hdr_spec->ip4.src_ip = spec->hdr.src_addr;
                doca_hdr_spec->ip4.dst_ip = spec->hdr.dst_addr;
                doca_hdr_spec->ip4.ttl = spec->hdr.time_to_live;
                doca_hdr_spec->ip4.dscp_ecn = spec->hdr.type_of_service;
            }

            doca_hdr_mask->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            if (items->mask) {
                doca_hdr_mask->ip4.next_proto = mask->hdr.next_proto_id;
                doca_hdr_mask->ip4.src_ip = mask->hdr.src_addr;
                doca_hdr_mask->ip4.dst_ip = mask->hdr.dst_addr;
                doca_hdr_mask->ip4.ttl = mask->hdr.time_to_live;
                doca_hdr_mask->ip4.dscp_ecn = mask->hdr.type_of_service;
            }
            /*TODO: handle ip frag checks */
        } else if (item_type == RTE_FLOW_ITEM_TYPE_IPV6) {
            const struct rte_flow_item_ipv6 *spec = items->spec;
            const struct rte_flow_item_ipv6 *mask = items->mask;

            doca_hdr_spec->l3_type = DOCA_FLOW_L3_TYPE_IP6;
            if (items->spec) {
                memcpy(doca_hdr_spec->ip6.dst_ip, spec->hdr.dst_addr,
                       sizeof doca_hdr_spec->ip6.dst_ip);
                memcpy(doca_hdr_spec->ip6.src_ip, spec->hdr.src_addr,
                       sizeof doca_hdr_spec->ip6.src_ip);
                doca_hdr_spec->ip6.next_proto = spec->hdr.proto;
                doca_hdr_spec->ip6.dscp_ecn = spec->hdr.vtc_flow;
                doca_hdr_spec->ip6.hop_limit = spec->hdr.hop_limits;
            }

            doca_hdr_mask->l3_type = DOCA_FLOW_L3_TYPE_IP6;
            if (items->mask) {
                memcpy(doca_hdr_mask->ip6.dst_ip, mask->hdr.dst_addr,
                       sizeof doca_hdr_mask->ip6.dst_ip);
                memcpy(doca_hdr_mask->ip6.src_ip, mask->hdr.src_addr,
                       sizeof doca_hdr_mask->ip6.src_ip);
                doca_hdr_mask->ip6.next_proto = mask->hdr.hop_limits;
                doca_hdr_mask->ip6.dscp_ecn = mask->hdr.vtc_flow;
                doca_hdr_mask->ip6.hop_limit = mask->hdr.hop_limits;
            }
        /* L4 */
        } else if (item_type == RTE_FLOW_ITEM_TYPE_UDP) {
            const struct rte_flow_item_udp *spec = items->spec;
            const struct rte_flow_item_udp *mask = items->mask;

            doca_hdr_spec->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
            if (items->spec) {
                doca_hdr_spec->udp.l4_port.src_port = spec->hdr.src_port;
                doca_hdr_spec->udp.l4_port.dst_port = spec->hdr.dst_port;
            }

            doca_hdr_mask->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
            if (items->mask) {
                doca_hdr_mask->udp.l4_port.src_port = mask->hdr.src_port;
                doca_hdr_mask->udp.l4_port.dst_port = mask->hdr.dst_port;
            }
        } else if (item_type ==  RTE_FLOW_ITEM_TYPE_TCP) {
            const struct rte_flow_item_tcp *spec = items->spec;
            const struct rte_flow_item_tcp *mask = items->mask;

            doca_hdr_spec->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
            if (items->spec) {
                doca_hdr_spec->tcp.l4_port.src_port = spec->hdr.src_port;
                doca_hdr_spec->tcp.l4_port.dst_port = spec->hdr.dst_port;
                doca_hdr_spec->tcp.flags = spec->hdr.tcp_flags;
            }

            doca_hdr_mask->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
            if (items->mask) {
                doca_hdr_mask->tcp.l4_port.src_port = mask->hdr.src_port;
                doca_hdr_mask->tcp.l4_port.dst_port = mask->hdr.dst_port;
                doca_hdr_mask->tcp.flags = mask->hdr.tcp_flags;
            }
        } else if (item_type == RTE_FLOW_ITEM_TYPE_VXLAN) {
            doca_translate_vxlan_item(items, doca_spec, doca_mask);

            doca_hdr_spec = &doca_spec->inner;
            doca_hdr_mask = &doca_mask->inner;
        } else if (item_type == RTE_FLOW_ITEM_TYPE_GRE) {
            doca_translate_gre_item(items, doca_spec, doca_mask);

            doca_hdr_spec = &doca_spec->inner;
            doca_hdr_mask = &doca_mask->inner;
        } else if (item_type == RTE_FLOW_ITEM_TYPE_GRE_KEY) {
            doca_translate_gre_key_item(items, doca_spec, doca_mask);

            doca_hdr_spec = &doca_spec->inner;
            doca_hdr_mask = &doca_mask->inner;
        } else if (item_type == RTE_FLOW_ITEM_TYPE_GENEVE) {
            doca_translate_geneve_item(items, doca_spec, doca_mask);

            doca_hdr_spec = &doca_spec->inner;
            doca_hdr_mask = &doca_mask->inner;
        } else if (item_type == RTE_FLOW_ITEM_TYPE_ICMP) {
            const struct rte_flow_item_icmp *spec = items->spec;
            const struct rte_flow_item_icmp *mask = items->mask;

            doca_hdr_spec->l4_type_ext  = DOCA_FLOW_L4_TYPE_EXT_ICMP;
            if (items->spec) {
                doca_hdr_spec->icmp.type  = spec->hdr.icmp_type;
                doca_hdr_spec->icmp.code  = spec->hdr.icmp_code;
            }

            doca_hdr_mask->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ICMP;
            if (items->mask) {
                doca_hdr_mask->icmp.type  = mask->hdr.icmp_type;
                doca_hdr_mask->icmp.code  = mask->hdr.icmp_code;
            }
        } else if (item_type == RTE_FLOW_ITEM_TYPE_TAG) {
            const struct rte_flow_item_tag *spec = items->spec;
            const struct rte_flow_item_tag *mask = items->mask;

            if (items->spec) {
                doca_spec->meta.u32[spec->index] |= spec->data & mask->data;
            }

            if (items->mask) {
                doca_mask->meta.u32[spec->index] |= mask->data;
            }
        } else if (item_type == OVS_RTE_FLOW_ITEM_TYPE(FLOW_INFO)) {
            uint32_t reg_offset = reg_fields[REG_FIELD_FLOW_INFO].offset;
            uint32_t reg_mask = reg_fields[REG_FIELD_FLOW_INFO].mask;
            const struct rte_flow_item_mark *spec = items->spec;

            if (spec) {
                doca_spec->meta.pkt_meta |= (spec->id & reg_mask) << reg_offset;
                doca_mask->meta.pkt_meta |= reg_mask << reg_offset;
            }
        } else {
            VLOG_DBG_RL(&rl, "item %d is not supported", item_type);
            return -1;
        }
    }

    return 0;
}

static int
doca_translate_geneve_encap(const struct genevehdr *geneve,
                            struct doca_flow_actions *dacts)
{
    struct doca_flow_encap_action *encap = &dacts->encap;

    encap->tun.type = DOCA_FLOW_TUN_GENEVE;
    encap->tun.geneve.ver_opt_len = geneve->opt_len;
    encap->tun.geneve.ver_opt_len |= geneve->ver << 6;
    encap->tun.geneve.o_c = geneve->critical << 6;
    encap->tun.geneve.o_c |= geneve->oam << 7;
    encap->tun.geneve.next_proto = geneve->proto_type;
    encap->tun.geneve.vni = get_16aligned_be32(&geneve->vni);

    dacts->has_encap = true;

    return 0;
}

static int
doca_translate_gre_encap(const struct gre_base_hdr *gre,
                         struct doca_flow_actions *dacts)
{
    struct doca_flow_encap_action *encap = &dacts->encap;
    const void *gre_key;

    /* Doca does not support L2 GRE. Until it does, disable this offload. */
    return -1;
    encap->tun.protocol = gre->protocol;
    encap->tun.type = DOCA_FLOW_TUN_GRE;
    encap->tun.key_present = !!(gre->flags & htons(GRE_KEY));

    gre_key = gre + 1;
    if (encap->tun.key_present) {
        const uint32_t *key = gre_key;

        encap->tun.gre_key = *key;
    }

    dacts->has_encap = true;

    return 0;
}

static int
doca_translate_raw_encap(const struct rte_flow_action *action,
                         struct doca_flow_actions *dacts)
{
    struct doca_flow_header_format *outer = &dacts->encap.outer;
    const struct raw_encap_data *data = action->conf;
    struct ovs_16aligned_ip6_hdr *ip6;
    struct vlan_header *vlan;
    struct udp_header *udp;
    struct eth_header *eth;
    struct ip_header *ip;
    uint16_t proto;
    void *l4;

    /* L2 */
    eth = find_raw_encap_spec(data, RTE_FLOW_ITEM_TYPE_ETH);
    if (!eth) {
        return -1;
    }

    memcpy(&outer->eth.src_mac, &eth->eth_src, DOCA_ETHER_ADDR_LEN);
    memcpy(&outer->eth.dst_mac, &eth->eth_dst, DOCA_ETHER_ADDR_LEN);

    proto = eth->eth_type;
    if (proto == htons(ETH_TYPE_VLAN_8021Q)) {
        vlan = ALIGNED_CAST(struct vlan_header *, (uint8_t *) (eth + 1));
        outer->eth_vlan[0].tci = vlan->vlan_tci;
        outer->l2_valid_headers = DOCA_FLOW_L2_VALID_HEADER_VLAN_0;
        proto = vlan->vlan_next_type;
    }

    /* L3 */
    if (proto == htons(ETH_TYPE_IP)) {
        ip = find_raw_encap_spec(data, RTE_FLOW_ITEM_TYPE_IPV4);
        if (!ip) {
            return -1;
        }

        outer->l3_type = DOCA_FLOW_L3_TYPE_IP4;
        outer->ip4.src_ip = get_16aligned_be32(&ip->ip_src);
        outer->l3_type = DOCA_FLOW_L3_TYPE_IP4;
        outer->ip4.dst_ip = get_16aligned_be32(&ip->ip_dst);
        outer->ip4.ttl = ip->ip_ttl;
        l4 = ip + 1;
    } else if (proto == htons(ETH_TYPE_IPV6)) {
        ip6 = find_raw_encap_spec(data, RTE_FLOW_ITEM_TYPE_IPV6);
        if (!ip6) {
            return -1;
        }

        outer->l3_type = DOCA_FLOW_L3_TYPE_IP6;
        memcpy(&outer->ip6.src_ip, &ip6->ip6_src, sizeof ip6->ip6_src);
        outer->l3_type = DOCA_FLOW_L3_TYPE_IP6;
        memcpy(&outer->ip6.dst_ip, &ip6->ip6_dst, sizeof ip6->ip6_dst);
        outer->ip6.hop_limit = ip6->ip6_hlim;
        l4 = ip6 + 1;
    } else {
        return -1;
    }

    /* Tunnel */
    if (data->tnl_type == OVS_VPORT_TYPE_GRE) {
        return doca_translate_gre_encap(l4, dacts);
    }

    udp = l4;
    if (data->tnl_type == OVS_VPORT_TYPE_GENEVE) {
        return doca_translate_geneve_encap((void *) (udp + 1), dacts);
    }

    return -1;
}

static int
doca_translate_vxlan_encap(const struct rte_flow_action *action,
                           struct doca_flow_actions *dacts)
{
    const struct rte_flow_action_vxlan_encap *conf = action->conf;
    struct doca_flow_header_format *outer = &dacts->encap.outer;
    struct rte_flow_item *items = conf->definition;

    for (; items->type != RTE_FLOW_ITEM_TYPE_END; items++) {
        int item_type = items->type;

        if (item_type == RTE_FLOW_ITEM_TYPE_ETH) {
            const struct eth_header *eth = items->spec;

            memcpy(&outer->eth.src_mac, &eth->eth_src, DOCA_ETHER_ADDR_LEN);
            memcpy(&outer->eth.dst_mac, &eth->eth_dst, DOCA_ETHER_ADDR_LEN);
        } else if (item_type == RTE_FLOW_ITEM_TYPE_VLAN) {
            const struct vlan_header *vx_vlan = items->spec;

            outer->eth_vlan[0].tci = vx_vlan->vlan_tci;
        } else if (item_type == RTE_FLOW_ITEM_TYPE_IPV4) {
            const struct ip_header *ip = items->spec;

            outer->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            memcpy(&outer->ip4.src_ip, &ip->ip_src, sizeof ip->ip_src);
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            memcpy(&outer->ip4.dst_ip, &ip->ip_dst, sizeof ip->ip_dst);
        } else if (item_type == RTE_FLOW_ITEM_TYPE_IPV6) {
            const struct ovs_16aligned_ip6_hdr *ip6 = items->spec;

            outer->l3_type = DOCA_FLOW_L3_TYPE_IP6;
            memcpy(&outer->ip4.src_ip, &ip6->ip6_src, sizeof ip6->ip6_src);
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP6;
            memcpy(&outer->ip4.dst_ip, &ip6->ip6_dst, sizeof ip6->ip6_dst);
        } else if (item_type == RTE_FLOW_ITEM_TYPE_UDP) {
            /* doca adds UDP encap automatically */
            continue;
        } else if (item_type == RTE_FLOW_ITEM_TYPE_VXLAN) {
            const struct vxlanhdr *vxlan = items->spec;

            dacts->encap.tun.type = DOCA_FLOW_TUN_VXLAN;
            memcpy(&dacts->encap.tun.vxlan_tun_id, &vxlan->vx_vni,
                   sizeof vxlan->vx_vni);
        } else {
            return -1;
        }
    }

    dacts->has_encap = true;

    return 0;
}

static int
doca_translate_actions(struct netdev *netdev OVS_UNUSED,
                       struct doca_flow_match *spec,
                       const struct rte_flow_action *actions,
                       struct doca_flow_actions *dacts,
                       struct doca_flow_actions *dacts_masks,
                       struct doca_flow_fwd *fwd,
                       struct doca_flow_monitor *monitor,
                       struct doca_flow_handle_resources *flow_res)
{
    struct doca_flow_header_format *outer_masks = &dacts_masks->outer;
    struct doca_flow_header_format *outer = &dacts->outer;
    bool vlan_act_push = false;

    for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
        int act_type = actions->type;

        if (act_type == RTE_FLOW_ACTION_TYPE_DROP) {
            fwd->type = DOCA_FLOW_FWD_DROP;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_MAC_SRC) {
            memcpy(&outer->eth.src_mac, actions->conf, DOCA_ETHER_ADDR_LEN);
            memset(&outer_masks->eth.src_mac, 0xFF,
                   sizeof outer_masks->eth.src_mac);
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_MAC_DST) {
            memcpy(&outer->eth.dst_mac, actions->conf, DOCA_ETHER_ADDR_LEN);
            memset(&outer_masks->eth.dst_mac, 0xFF,
                   sizeof outer_masks->eth.dst_mac);
        } else if (act_type == RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID) {
            const struct rte_flow_action_of_set_vlan_vid *rte_vlan_vid;

            rte_vlan_vid = actions->conf;
            /* If preceeded by vlan push action, this is a new
             * vlan tag. Otherwise, perfrom vlan modification.
             */
            if (vlan_act_push) {
                dacts->push.type = DOCA_FLOW_PUSH_ACTION_VLAN;
                dacts->push.vlan.tci = rte_vlan_vid->vlan_vid;
                dacts->has_push = true;
            } else {
                outer->eth_vlan[0].tci = rte_vlan_vid->vlan_vid;
                memset(&outer_masks->eth_vlan[0].tci, 0xFF,
                       sizeof outer_masks->eth_vlan[0].tci);
            }
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC) {
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            outer->ip4.src_ip = *(__be32 *) actions->conf;
            memset(&outer_masks->ip4.src_ip, 0xFF,
                   sizeof outer_masks->ip4.src_ip);
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_IPV4_DST) {
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            outer->ip4.dst_ip = *(__be32 *) actions->conf;
            memset(&outer_masks->ip4.dst_ip, 0xFF,
                   sizeof outer_masks->ip4.dst_ip);
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_IPV4_TTL) {
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            outer->ip4.ttl = *(__u8 *) actions->conf;
            memset(&outer_masks->ip4.ttl, 0xFF,
                   sizeof outer_masks->ip4.ttl);
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_IPV6_HOP) {
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP6;
            outer->ip6.hop_limit = *(__u8 *) actions->conf;
            memset(&outer_masks->ip6.hop_limit, 0xFF,
                   sizeof outer_masks->ip6.hop_limit);
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC) {
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP6;
            memcpy(&outer->ip6.src_ip, actions->conf, sizeof outer->ip6.src_ip);
            memset(&outer_masks->ip6.src_ip, 0xFF,
                   sizeof outer_masks->ip6.src_ip);
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_IPV6_DST) {
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP6;
            memcpy(&outer->ip6.dst_ip, actions->conf, sizeof outer->ip6.dst_ip);
            memset(&outer_masks->ip6.dst_ip, 0xFF,
                   sizeof outer_masks->ip6.dst_ip);
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_TP_SRC) {
            doca_be16_t src_port = *(doca_be16_t *) actions->conf;

            outer->l4_type_ext = spec->outer.l4_type_ext;
            if (spec->outer.l4_type_ext == DOCA_FLOW_L4_TYPE_EXT_TCP) {
                outer->tcp.l4_port.src_port = src_port;
                memset(&outer_masks->tcp.l4_port.src_port, 0xFF,
                       sizeof outer_masks->tcp.l4_port.src_port);
            } else if (spec->outer.l4_type_ext == DOCA_FLOW_L4_TYPE_EXT_UDP) {
                outer->udp.l4_port.src_port = src_port;
                memset(&outer_masks->udp.l4_port.src_port, 0xFF,
                       sizeof outer_masks->udp.l4_port.src_port);
            } else {
                OVS_NOT_REACHED();
            }
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_TP_DST) {
            doca_be16_t dst_port = *(doca_be16_t *) actions->conf;

            outer->l4_type_ext = spec->outer.l4_type_ext;
            if (spec->outer.l4_type_ext == DOCA_FLOW_L4_TYPE_EXT_TCP) {
                outer->tcp.l4_port.dst_port = dst_port;
                memset(&outer_masks->tcp.l4_port.dst_port, 0xFF,
                       sizeof outer_masks->tcp.l4_port.dst_port);
            } else if (spec->outer.l4_type_ext == DOCA_FLOW_L4_TYPE_EXT_UDP) {
                outer->udp.l4_port.dst_port = dst_port;
                memset(&outer_masks->udp.l4_port.dst_port, 0xFF,
                       sizeof outer_masks->udp.l4_port.dst_port);
            } else {
                OVS_NOT_REACHED();
            }
        } else if (act_type == RTE_FLOW_ACTION_TYPE_PORT_ID) {
            const struct rte_flow_action_port_id *port_id = actions->conf;

            fwd->type = DOCA_FLOW_FWD_PORT;
            fwd->port_id = port_id->id;
        } else if ((act_type == RTE_FLOW_ACTION_TYPE_NVGRE_DECAP) ||
                   (act_type == RTE_FLOW_ACTION_TYPE_VXLAN_DECAP) ||
                   (act_type == RTE_FLOW_ACTION_TYPE_RAW_DECAP)) {
            /* VXLAN, L3 GRE and GENEVE are supported natively.
             * L2 GRE is not however.
             */
            if (act_type == RTE_FLOW_ACTION_TYPE_NVGRE_DECAP) {
                return -1;
            }
            dacts->decap = true;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_COUNT) {
            monitor->flags |= DOCA_FLOW_MONITOR_COUNT;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_JUMP) {
            const struct rte_flow_action_jump *jump = actions->conf;
            struct doca_ctl_pipe_ctx *next_pipe_ctx;

            next_pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, jump->group);
            if (!next_pipe_ctx) {
                return -1;
            }

            fwd->type = DOCA_FLOW_FWD_PIPE;
            fwd->next_pipe = next_pipe_ctx->pipe;
            flow_res->next_pipe_ctx = next_pipe_ctx;
            flow_res->next_group = jump->group;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP) {
            if (doca_translate_vxlan_encap(actions, dacts)) {
                return -1;
            }
        } else if (act_type == RTE_FLOW_ACTION_TYPE_RAW_ENCAP) {
            if (doca_translate_raw_encap(actions, dacts)) {
                return -1;
            }
        } else if (act_type == OVS_RTE_FLOW_ACTION_TYPE(FLOW_INFO)) {
            uint32_t reg_offset = reg_fields[REG_FIELD_FLOW_INFO].offset;
            const struct rte_flow_action_mark *mark = actions->conf;
            uint32_t reg_mask = reg_fields[REG_FIELD_FLOW_INFO].mask;

            dacts->meta.pkt_meta |= (mark->id & reg_mask) << reg_offset;
            dacts_masks->meta.pkt_meta |= reg_mask << reg_offset;
        } else if (act_type == OVS_RTE_FLOW_ACTION_TYPE_CT_INFO) {
            const struct rte_flow_action_set_meta *set_meta = actions->conf;
            uint32_t reg_offset = reg_fields[REG_FIELD_CT_CTX].offset;
            uint32_t reg_mask = reg_fields[REG_FIELD_CT_CTX].mask;

            dacts->meta.pkt_meta |= (set_meta->data & reg_mask) << reg_offset;
            dacts_masks->meta.pkt_meta |= (set_meta->mask & reg_mask) << reg_offset;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_TAG) {
            const struct rte_flow_action_set_tag *set_tag = actions->conf;
            uint8_t index = set_tag->index;

            dacts->meta.u32[index] |= set_tag->data;
            dacts_masks->meta.u32[index] |= set_tag->mask;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_OF_POP_VLAN) {
            /* Current support is for a single VLAN tag */
            if (dacts->pop) {
                return -1;
            }
            dacts->pop = true;
            dacts_masks->pop = true;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN) {
            if (vlan_act_push) {
                return -1;
            }
            vlan_act_push = true;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP) {
            continue;
        } else {
            return -1;
        }
    }

    return 0;
}

static int
create_doca_basic_flow_entry(struct netdev *netdev,
                             unsigned int queue_id,
                             struct doca_flow_pipe *pipe,
                             struct doca_flow_match *spec,
                             struct doca_flow_actions *actions,
                             struct doca_flow_monitor *monitor,
                             struct doca_flow_fwd *fwd,
                             struct doca_flow_handle *hndl,
                             struct rte_flow_error *error)
{
    struct doca_flow_pipe_entry *entry;
    struct doca_eswitch_ctx *esw_ctx;
    doca_error_t err;

    err = doca_flow_pipe_add_entry(queue_id, pipe, spec, actions, monitor, fwd,
                                   DOCA_FLOW_NO_WAIT, hndl, &entry);
    if (err) {
        VLOG_WARN_RL(&rl, "%s: Failed to create basic pipe entry. Error: %d (%s)",
                     netdev_get_name(netdev), err, doca_get_error_string(err));
        error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
        error->message = doca_get_error_string(err);
        return -1;
    }

    esw_ctx = doca_eswitch_ctx_get(netdev);
    err = doca_flow_entries_process(esw_ctx->esw_port, queue_id,
                                    ENTRY_PROCESS_TIMEOUT_MS, 1);
    if (err) {
        VLOG_WARN_RL(&rl, "%s: Failed to poll completion of pipe entry insertion. Error: %d (%s)",
                     netdev_get_name(netdev), err, doca_get_error_string(err));
        error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
        error->message = doca_get_error_string(err);
        return -1;
    }

    hndl->flow = entry;

    return 0;
}

static struct doca_flow_pipe_entry *
create_doca_ctl_flow_entry(struct netdev *netdev,
                           unsigned int queue_id,
                           struct doca_ctl_pipe_ctx *self_pipe_ctx,
                           uint32_t prio,
                           struct doca_flow_match *spec,
                           struct doca_flow_match *mask,
                           struct doca_flow_actions *actions,
                           struct doca_flow_actions *actions_masks,
                           struct doca_flow_monitor *monitor,
                           struct doca_flow_fwd *fwd,
                           struct rte_flow_error *error)
{
    struct doca_flow_pipe *pipe = self_pipe_ctx->pipe;
    struct doca_flow_pipe_entry *entry;
    doca_error_t err;

    err = doca_flow_pipe_control_add_entry(queue_id, prio, pipe, spec, mask,
                                           actions, actions_masks, NULL, monitor, fwd,
                                           NULL, &entry);
    if (err) {
        VLOG_WARN_RL(&rl, "%s: Failed to create ctl pipe entry. Error: %d (%s)",
                     netdev_get_name(netdev), err, doca_get_error_string(err));
        error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
        error->message = doca_get_error_string(err);
        return NULL;
    }

    return entry;
}

static struct doca_flow_pipe *
doca_get_ct_pipe(struct doca_eswitch_ctx *ctx,
                 uint32_t group,
                 struct doca_flow_match *spec,
                 struct doca_flow_actions *actions)
{
    enum ct_action_type ct_type;
    enum ct_nw_type nw_type;
    enum ct_tp_type tp_type;

    if (ctx == NULL) {
        return NULL;
    }

    ct_type = get_ct_action_type(group, actions);

    nw_type = l3_to_nw_type(spec->outer.l3_type);
    if (nw_type >= NUM_CT_NW) {
        VLOG_DBG_RL(&rl, "Unsupported CT network type.");
        return NULL;
    }

    tp_type = l4_to_tp_type(spec->outer.l4_type_ext);
    if (tp_type >= NUM_CT_TP) {
        VLOG_DBG_RL(&rl, "Unsupported CT protocol type.");
        return NULL;
    }

    return ctx->ct_pipes[nw_type][tp_type][ct_type].pipe;
}

static struct doca_flow_handle *
create_doca_flow_handle(struct netdev *netdev,
                        unsigned int queue_id,
                        uint32_t prio,
                        uint32_t group,
                        struct doca_flow_match *spec,
                        struct doca_flow_match *mask,
                        struct doca_flow_actions *actions,
                        struct doca_flow_actions *actions_masks,
                        struct doca_flow_monitor *monitor,
                        struct doca_flow_fwd *fwd,
                        struct doca_flow_handle_resources *flow_res,
                        struct dpdk_offload_handle *doh,
                        struct rte_flow_error *error)
{
    struct doca_ctl_pipe_ctx *pipe_ctx = NULL;
    struct doca_flow_handle *hndl;

    hndl = &doh->dfh;

    if (is_ct_group(group)) {
        struct doca_eswitch_ctx *ctx = doca_eswitch_ctx_get(netdev);
        struct doca_flow_pipe *pipe;

        if (ctx == NULL) {
            error->type = RTE_FLOW_ERROR_TYPE_UNSPECIFIED;
            error->message = "CT offload is not initialized";
            goto err_pipe;
        }

        pipe = doca_get_ct_pipe(ctx, group, spec, actions);
        if (pipe == NULL) {
            error->type = RTE_FLOW_ERROR_TYPE_UNSPECIFIED;
            error->message = "Unsupported CT type";
            goto err_pipe;
        }
        if (create_doca_basic_flow_entry(netdev, queue_id, pipe, spec, actions,
                                         monitor, fwd, hndl, error)) {
            error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
            error->message = "Failed to insert rule";
            goto err_insert;
        }
    } else {
        /* get self table pointer */
        pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, group);
        if (!pipe_ctx) {
            error->type = RTE_FLOW_ERROR_TYPE_UNSPECIFIED;
            error->message = "Could not create table";
            goto err_pipe;
        }
        /* insert rule */
        hndl->flow = create_doca_ctl_flow_entry(netdev, queue_id, pipe_ctx,
                                                prio, spec, mask, actions,
                                                actions_masks, monitor, fwd,
                                                error);
        if (!hndl->flow) {
            error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
            error->message = "Could not insert rule";
            goto err_insert;
        }
    }

    memcpy(&hndl->flow_res, flow_res, sizeof *flow_res);
    hndl->flow_res.self_pipe_ctx = pipe_ctx;
    hndl->flow_res.group = group;

    return hndl;

err_insert:
    if (pipe_ctx) {
        doca_ctl_pipe_ctx_unref(pipe_ctx);
    }
err_pipe:
    return NULL;
}

static int
dpdk_offload_doca_create(struct netdev *netdev,
                         const struct rte_flow_attr *attr,
                         struct rte_flow_item *items,
                         struct rte_flow_action *actions,
                         struct dpdk_offload_handle *doh,
                         struct rte_flow_error *error)
{
    unsigned int tid = netdev_offload_thread_id();
    struct doca_flow_actions dacts, dacts_masks;
    struct doca_flow_handle_resources flow_res;
    struct doca_flow_monitor monitor;
    struct doca_flow_handle *hndl;
    struct doca_flow_match mask;
    struct doca_flow_match spec;
    unsigned int queue_id = tid;
    struct doca_flow_fwd fwd;
    uint32_t prio;

    memset(&dacts_masks, 0x0, sizeof dacts_masks);
    memset(&flow_res, 0x0, sizeof flow_res);
    memset(&monitor, 0x0, sizeof monitor);
    memset(&dacts, 0x0, sizeof dacts);
    memset(&mask, 0x0, sizeof mask);
    memset(&spec, 0x0, sizeof spec);
    memset(&fwd, 0x0, sizeof fwd);

    if (doca_translate_items(netdev, attr, items, &spec, &mask)) {
        error->type = RTE_FLOW_ERROR_TYPE_ITEM;
        error->message = "Could not create items";
        doh->rte_flow = NULL;
        return -1;
    }

    /* parse actions */
    if (doca_translate_actions(netdev, &spec, actions, &dacts, &dacts_masks,
                               &fwd, &monitor, &flow_res)) {
        error->type = RTE_FLOW_ERROR_TYPE_ACTION;
        error->message = "Could not create actions";
        doh->rte_flow = NULL;
        return -1;
    }

    prio = flow_res.next_group == MISS_TABLE_ID;
    hndl = create_doca_flow_handle(netdev, queue_id, prio, attr->group, &spec,
                                   &mask, &dacts, &dacts_masks, &monitor, &fwd,
                                   &flow_res, doh, error);
    if (!hndl) {
        /* change to free doca flow resources function */
        if (flow_res.next_pipe_ctx) {
            doca_ctl_pipe_ctx_unref(flow_res.next_pipe_ctx);
        }
        return -1;
    }

    return 0;
}

static doca_error_t
destroy_doca_flow_entry(struct doca_flow_pipe_entry *flow,
                        unsigned int queue_id)
{
    return doca_flow_pipe_rm_entry(queue_id, DOCA_FLOW_NO_WAIT, flow);
}

static int
destroy_doca_flow_handle(struct doca_flow_handle *dfh,
                         unsigned int queue_id,
                         struct rte_flow_error *error)
{
    doca_error_t err;

    err = destroy_doca_flow_entry(dfh->flow, queue_id);
    if (err) {
        if (error) {
            error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
            error->message = doca_get_error_string(err);
        }
        return -1;
    }

    if (dfh->flow_res.next_pipe_ctx) {
        doca_ctl_pipe_ctx_unref(dfh->flow_res.next_pipe_ctx);
    }

    doca_ctl_pipe_ctx_unref(dfh->flow_res.self_pipe_ctx);

    return 0;
}

static int
dpdk_offload_doca_destroy(struct netdev *netdev OVS_UNUSED,
                          struct dpdk_offload_handle *doh,
                          struct rte_flow_error *error,
                          bool esw_port_id OVS_UNUSED)
{
    unsigned int tid = netdev_offload_thread_id();
    unsigned int queue_id = tid;

    return destroy_doca_flow_handle(&doh->dfh, queue_id, error);
}

static int
dpdk_offload_doca_query_count(struct netdev *netdev,
                              struct dpdk_offload_handle *doh,
                              struct rte_flow_query_count *query,
                              struct rte_flow_error *error)
{
    struct doca_flow_pipe_entry *doca_flow;
    struct doca_flow_handle *hndl;
    struct doca_flow_query stats;
    doca_error_t err;

    hndl = &doh->dfh;
    doca_flow = hndl->flow;

    memset(query, 0, sizeof *query);
    memset(&stats, 0, sizeof stats);

    err = doca_flow_query_entry(doca_flow, &stats);
    if (err) {
        VLOG_WARN_RL(&rl, "%s: Failed to query doca_flow: %p. Error %d (%s)",
                     netdev_get_name(netdev), doca_flow, err,
                     doca_get_error_string(err));
        error->type = RTE_FLOW_ERROR_TYPE_UNSPECIFIED;
        error->message = doca_get_error_string(err);
        return -1;
    }

    query->hits = stats.total_pkts;
    query->bytes = stats.total_bytes;

    return 0;
}

OVS_UNUSED static struct rte_flow_action_handle *
dpdk_offload_doca_shared_create(struct netdev *netdev OVS_UNUSED,
                                const struct rte_flow_action *action OVS_UNUSED,
                                struct rte_flow_error *error OVS_UNUSED)
{
    return NULL;
}

OVS_UNUSED static int
dpdk_offload_doca_shared_destroy(int port_id OVS_UNUSED,
                                 struct rte_flow_action_handle *act_hdl OVS_UNUSED,
                                 struct rte_flow_error *error OVS_UNUSED)
{
    return -1;
}

OVS_UNUSED static int
dpdk_offload_doca_shared_query(int port_id OVS_UNUSED,
                               struct rte_flow_action_handle *act_hdl OVS_UNUSED,
                               void *data OVS_UNUSED,
                               struct rte_flow_error *error OVS_UNUSED)
{
    return -1;
}

static void
dpdk_offload_doca_get_pkt_recover_info(struct dp_packet *p,
                                       struct dpdk_offload_recovery_info *info)
{
    memset(info, 0, sizeof *info);
    if (dpdk_offload_get_reg_field(p, REG_FIELD_FLOW_INFO,
                                   &info->flow_miss_id)) {
        dp_packet_set_flow_mark(p, info->flow_miss_id);
        dpdk_offload_get_reg_field(p, REG_FIELD_CT_CTX,
                                   &info->ct_miss_id);
    }
}

static int
dpdk_offload_doca_netdev_data_destroy(void *data)
{
    struct netdev *netdev = data;

    if (netdev_vport_is_vport_class(netdev->netdev_class)) {
        return 0;
    }

    return netdev_dpdk_doca_port_destroy(netdev);
}

static void
dpdk_offload_doca_update_stats(struct dpif_flow_stats *stats,
                               struct dpif_flow_attrs *attrs,
                               struct rte_flow_query_count *query)
{
    if (attrs) {
        attrs->dp_layer = "doca";
    }

    if (stats->n_packets != query->hits) {
        query->hits_set = 1;
        query->bytes_set = 1;
    }

    stats->n_packets = query->hits;
    stats->n_bytes = query->bytes;
}

static void
doca_fixed_rule_uninit(struct fixed_rule *fr)
{
    if (!fr->doh.dfh.flow) {
        return;
    }

    destroy_doca_flow_handle(&fr->doh.dfh, AUX_QUEUE, NULL);
    fr->doh.dfh.flow = NULL;
}

static void
doca_ct_zones_uninit(struct doca_eswitch_ctx *ctx)
{
    struct fixed_rule *fr;
    uint32_t zone_id;
    int nat, i;

    if (netdev_is_zone_tables_disabled()) {
        return;
    }

    for (nat = 0; nat < 2; nat++) {
        for (i = 0; i < NUM_ZONE_FLOWS; i++) {
            for (zone_id = MIN_ZONE_ID; zone_id <= MAX_ZONE_ID; zone_id++) {
                fr = &ctx->zone_flows[nat][i][zone_id];
                doca_fixed_rule_uninit(fr);
            }
        }
    }
}

static int
doca_create_ct_zone_revisit_rule(struct netdev *netdev, uint32_t group,
                                 uint16_t zone, int nat,
                                 struct dpdk_offload_handle *doh)
{
    struct doca_flow_handle_resources flow_res;
    struct doca_ctl_pipe_ctx *next_pipe_ctx;
    uint32_t ct_state_spec, ct_state_mask;
    uint32_t ct_zone_spec, ct_zone_mask;
    struct doca_flow_handle *hndl;
    struct rte_flow_error error;
    struct doca_flow_match mask;
    struct doca_flow_match spec;
    struct reg_field *reg_field;
    struct doca_flow_fwd fwd;

    memset(&flow_res, 0x0, sizeof flow_res);
    memset(&mask, 0x0, sizeof mask);
    memset(&spec, 0x0, sizeof spec);
    memset(&fwd, 0x0, sizeof fwd);

    /* If the zone is the same, and already visited ct/ct-nat, skip
     * ct/ct-nat and jump directly to post-ct.
     */
    reg_field = &reg_fields[REG_FIELD_CT_ZONE];
    ct_zone_spec = zone << reg_field->offset;
    ct_zone_mask = reg_field->mask << reg_field->offset;
    reg_field = &reg_fields[REG_FIELD_CT_STATE];
    ct_state_spec = OVS_CS_F_TRACKED;
    if (nat) {
        ct_state_spec |= OVS_CS_F_NAT_MASK;
    }
    ct_state_spec <<= reg_field->offset;
    ct_state_mask = ct_state_spec;

    /* Merge ct_zone and ct_state matches in a single item. */
    spec.meta.u32[reg_field->index] |= ct_zone_spec | ct_state_spec;
    mask.meta.u32[reg_field->index] |= ct_zone_mask | ct_state_mask;

    next_pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, POSTCT_TABLE_ID);
    if (!next_pipe_ctx) {
        return -1;
    }

    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = next_pipe_ctx->pipe;
    flow_res.next_pipe_ctx = next_pipe_ctx;
    flow_res.next_group = POSTCT_TABLE_ID;

    hndl = create_doca_flow_handle(netdev, AUX_QUEUE, 0, group, &spec, &mask,
                                   NULL, NULL, NULL, &fwd, &flow_res, doh,
                                   &error);
    if (!hndl) {
        return -1;
    }
    return 0;
}

static int
doca_create_ct_zone_uphold_rule(struct netdev *netdev,
                                struct doca_eswitch_ctx *ctx, uint32_t group,
                                uint16_t zone, int nat, bool match_tcp,
                                struct dpdk_offload_handle *doh)
{
    struct doca_flow_actions dacts, dacts_masks;
    struct doca_flow_handle_resources flow_res;
    struct doca_flow_handle *hndl;
    struct doca_flow_match spec;
    struct doca_flow_match mask;
    struct rte_flow_error error;
    struct reg_field *reg_field;
    struct doca_flow_fwd fwd;
    uint32_t next_group;

    memset(&dacts_masks, 0x0, sizeof dacts_masks);
    memset(&flow_res, 0x0, sizeof flow_res);
    memset(&dacts, 0x0, sizeof dacts);
    memset(&fwd, 0x0, sizeof fwd);
    memset(&spec, 0, sizeof spec);
    memset(&mask, 0, sizeof mask);

    spec.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    if (match_tcp) {
        spec.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
        mask.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
        /* Ensure that none of SYN | RST | FIN flag is set in
         * packets going to CT: they must miss and go to SW. */
        mask.outer.tcp.flags = TCP_SYN | TCP_RST | TCP_FIN;
    } else {
        spec.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
        mask.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
    }

    reg_field = &reg_fields[REG_FIELD_CT_ZONE];
    dacts.meta.u32[reg_field->index] |= zone << reg_field->offset;
    dacts_masks.meta.u32[reg_field->index] |= reg_field->mask << reg_field->offset;

    next_group = nat ? CTNAT_TABLE_ID : CT_TABLE_ID;

    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = doca_get_ct_pipe(ctx, next_group, &spec, NULL);
    flow_res.next_pipe_ctx = NULL;
    flow_res.next_group = next_group;

    hndl = create_doca_flow_handle(netdev, AUX_QUEUE, 1, group, &spec, &mask,
                                   &dacts, &dacts_masks, NULL, &fwd, &flow_res,
                                   doh, &error);
    if (!hndl) {
        return -1;
    }
    return 0;
}

static int
doca_create_ct_zone_miss_rule(struct netdev *netdev, uint32_t group,
                              struct dpdk_offload_handle *doh)
{
    struct doca_flow_handle_resources flow_res;
    struct doca_ctl_pipe_ctx *pipe_ctx;
    struct doca_flow_handle *hndl;
    struct rte_flow_error error;
    struct doca_flow_fwd fwd;

    memset(&flow_res, 0, sizeof flow_res);
    memset(&fwd, 0, sizeof fwd);

    pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, MISS_TABLE_ID);
    if (!pipe_ctx) {
        return -1;
    }

    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = pipe_ctx->pipe;
    flow_res.next_pipe_ctx = pipe_ctx;
    flow_res.next_group = MISS_TABLE_ID;

    hndl = create_doca_flow_handle(netdev, AUX_QUEUE, 2, group, NULL, NULL,
                                   NULL, NULL, NULL, &fwd, &flow_res, doh,
                                   &error);
    if (!hndl) {
        return -1;
    }
    return 0;
}

static int
doca_ct_zones_init(struct netdev *netdev, struct doca_eswitch_ctx *ctx)
{
    struct fixed_rule *fr;
    uint32_t base_group;
    uint32_t zone_id;
    int nat;

    if (netdev_is_zone_tables_disabled()) {
        return 0;
    }

    /* Merge the tag match for zone and state only if they are
     * at the same index. */
    ovs_assert(reg_fields[REG_FIELD_CT_ZONE].index == reg_fields[REG_FIELD_CT_STATE].index);

    for (nat = 0; nat < 2; nat++) {
        base_group = nat ? CTNAT_TABLE_ID : CT_TABLE_ID;

        for (zone_id = MIN_ZONE_ID; zone_id <= MAX_ZONE_ID; zone_id++) {
            /* If the zone is already set, then CT for this zone has already
             * been executed: skip to post-ct. */

            fr = &ctx->zone_flows[nat][0][zone_id];
            if (doca_create_ct_zone_revisit_rule(netdev, base_group + zone_id,
                                                 zone_id, nat, &fr->doh)) {
                goto err;
            }

            /* Otherwise, set the zone and go to CT/CT-NAT. */

            fr = &ctx->zone_flows[nat][1][zone_id];
            if (doca_create_ct_zone_uphold_rule(netdev, ctx,
                                                base_group + zone_id, zone_id,
                                                nat, false, &fr->doh)) {
                goto err;
            }

            fr = &ctx->zone_flows[nat][2][zone_id];
            if (doca_create_ct_zone_uphold_rule(netdev, ctx,
                                                base_group + zone_id,
                                                zone_id, nat, true, &fr->doh)) {
                goto err;
            }

            /* Finally if the CT-zone was never visited, but the packet does
             * not match either TCP(!SFR) or UDP, miss and go to SW. */

            fr = &ctx->zone_flows[nat][3][zone_id];
            if (doca_create_ct_zone_miss_rule(netdev, base_group + zone_id,
                                              &fr->doh)) {
                goto err;
            }
        }
    }

    return 0;

err:
    doca_ct_zones_uninit(ctx);
    return -1;
}

static void
doca_ct_pipe_destroy(struct doca_eswitch_ctx *ctx,
                     enum ct_nw_type nw_type, enum ct_tp_type tp_type,
                     enum ct_action_type ct_type)
{
    enum ct_action_type prev = ct_action_prev(ct_type);
    struct doca_basic_pipe_ctx *pipe_ctx;

    if (prev != CT_ACTION_NULL) {
        /* First destroy any previous pipe in the chain,
         * if not already done. */
        doca_ct_pipe_destroy(ctx, nw_type, tp_type, prev);
    }

    pipe_ctx = &ctx->ct_pipes[nw_type][tp_type][ct_type];

    if (pipe_ctx->fwd_pipe_ctx) {
        doca_ctl_pipe_ctx_unref(pipe_ctx->fwd_pipe_ctx);
        pipe_ctx->fwd_pipe_ctx = NULL;
    }
    if (pipe_ctx->miss_pipe_ctx) {
        doca_ctl_pipe_ctx_unref(pipe_ctx->miss_pipe_ctx);
        pipe_ctx->miss_pipe_ctx = NULL;
    }
    if (pipe_ctx->pipe) {
        doca_flow_pipe_destroy(pipe_ctx->pipe);
        pipe_ctx->pipe = NULL;
    }
}

static void
doca_ct_pipes_destroy(struct doca_eswitch_ctx *ctx)
{
    int i, j, k;

    for (i = 0; i < NUM_CT_NW; i++) {
        for (j = 0; j < NUM_CT_TP; j++) {
            for (k = 0; k < NUM_CT_ACTIONS; k++) {
                doca_ct_pipe_destroy(ctx, i, j, k);
            }
        }
    }
}

static void
doca_basic_pipe_name(struct ds *s, struct netdev *netdev,
                     enum ct_nw_type nw_type,
                     enum ct_tp_type tp_type,
                     enum ct_action_type ct_type)
{
    ds_put_format(s, "OVS_BASIC_PIPE_%d",
                  netdev_dpdk_get_esw_mgr_port_id(netdev));

    switch (nw_type) {
    case CT_NW_IP4:
        ds_put_cstr(s, "_IP4");
        break;
    case NUM_CT_NW:
       OVS_NOT_REACHED();
    }

    switch (tp_type) {
    case CT_TP_UDP:
        ds_put_cstr(s, "_UDP");
        break;
    case CT_TP_TCP:
        ds_put_cstr(s, "_TCP");
        break;
    case NUM_CT_TP:
       OVS_NOT_REACHED();
    }

    switch (ct_type) {
    case CT_ACTION_PLAIN:
        ds_put_cstr(s, "_CT");
        break;
    case CT_ACTION_DNAT:
        ds_put_cstr(s, "_CT_DNAT");
        break;
    case CT_ACTION_SNAT:
        ds_put_cstr(s, "_CT_SNAT");
        break;
    case CT_ACTION_NULL:
       OVS_NOT_REACHED();
    };
}

static struct doca_flow_match ct_matches[NUM_CT_NW][NUM_CT_TP] = {
    [CT_NW_IP4] = {
        [CT_TP_UDP] = {
            .outer.l3_type = DOCA_FLOW_L3_TYPE_IP4,
            .outer.ip4.src_ip = UINT32_MAX,
            .outer.ip4.dst_ip = UINT32_MAX,
            .outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP,
            .outer.udp.l4_port.src_port = UINT16_MAX,
            .outer.udp.l4_port.dst_port = UINT16_MAX,
        },
        [CT_TP_TCP] = {
            .outer.l3_type = DOCA_FLOW_L3_TYPE_IP4,
            .outer.ip4.src_ip = UINT32_MAX,
            .outer.ip4.dst_ip = UINT32_MAX,
            .outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP,
            .outer.tcp.l4_port.src_port = UINT16_MAX,
            .outer.tcp.l4_port.dst_port = UINT16_MAX,
        },
    },
};

#define CT_PIPE_ACT_ARR_SIZE 2

static int
doca_ct_pipe_init(struct netdev *netdev, struct doca_eswitch_ctx *ctx,
                  enum ct_nw_type nw_type, enum ct_tp_type tp_type,
                  enum ct_action_type ct_type)
{
    struct doca_flow_actions *actions_masks_list[CT_PIPE_ACT_ARR_SIZE];
    struct doca_flow_header_format *outer_masks[CT_PIPE_ACT_ARR_SIZE];
    struct doca_flow_actions actions_masks[CT_PIPE_ACT_ARR_SIZE];
    struct doca_flow_actions *actions_list[CT_PIPE_ACT_ARR_SIZE];
    struct doca_flow_header_format *outer[CT_PIPE_ACT_ARR_SIZE];
    struct doca_flow_actions actions[CT_PIPE_ACT_ARR_SIZE];
    struct doca_ctl_pipe_ctx *miss_pipe_ctx = NULL;
    struct doca_ctl_pipe_ctx *fwd_pipe_ctx = NULL;
    struct doca_basic_pipe_ctx *pipe_ctx;
    struct doca_flow_match match_mask;
    struct doca_flow_pipe *miss_pipe;
    struct doca_flow_monitor monitor;
    struct doca_flow_pipe_cfg cfg;
    enum ct_action_type next_ct;
    struct doca_flow_fwd miss;
    struct doca_flow_fwd fwd;
    struct reg_field *ct_reg;
    struct ds pipe_name;
    int nb_actions = 0;
    uint32_t reg_mask;
    int ret, i;

    pipe_ctx = &ctx->ct_pipes[nw_type][tp_type][ct_type];

    /* Do not re-init a pipe if already done. */
    if (pipe_ctx->pipe != NULL) {
        return 0;
    }

    /* Make sure the next pipe in the CT chain is already
     * initialized before linking to it from this one. */
    if (ct_action_next[ct_type] != CT_ACTION_NULL) {
        ret = doca_ct_pipe_init(netdev, ctx, nw_type, tp_type,
                                ct_action_next[ct_type]);
        if (ret) {
            return ret;
        }
    }

    memset(&cfg, 0, sizeof cfg);
    memset(&fwd, 0, sizeof fwd);
    memset(&miss, 0, sizeof miss);
    memset(actions, 0, sizeof actions);
    memset(actions_masks, 0, sizeof actions_masks);
    memset(&monitor, 0, sizeof monitor);

    ds_init(&pipe_name);
    doca_basic_pipe_name(&pipe_name, netdev, nw_type, tp_type, ct_type);

    outer[0] = &actions[0].outer;
    outer[1] = &actions[1].outer;
    outer_masks[0] = &actions_masks[0].outer;
    outer_masks[1] = &actions_masks[1].outer;
    /* Finalize the action templates. */
    if (nw_type == CT_NW_IP4) {
        switch (ct_type) {
        case CT_ACTION_PLAIN:
            nb_actions = 1;
            break;
        case CT_ACTION_DNAT:
            nb_actions = 2;
            outer[0]->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            outer[0]->ip4.dst_ip = UINT32_MAX;
            outer[1]->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            outer[1]->ip4.dst_ip = UINT32_MAX;
            if (tp_type == CT_TP_UDP) {
                outer[1]->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
                outer[1]->udp.l4_port.dst_port = UINT16_MAX;
            } else {
                outer[1]->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
                outer[1]->tcp.l4_port.dst_port = UINT16_MAX;
            }
            break;
        case CT_ACTION_SNAT:
            nb_actions = 2;
            outer[0]->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            outer[0]->ip4.src_ip = UINT32_MAX;
            outer[1]->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            outer[1]->ip4.src_ip = UINT32_MAX;
            if (tp_type == CT_TP_UDP) {
                outer[1]->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
                outer[1]->udp.l4_port.src_port = UINT16_MAX;
            } else {
                outer[1]->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
                outer[1]->tcp.l4_port.src_port = UINT16_MAX;
            }
            break;
        case CT_ACTION_NULL:
            OVS_NOT_REACHED();
            break;
        };
    } else {
        OVS_NOT_REACHED();
    }

    memcpy(outer_masks[0], outer[0], sizeof *outer_masks[0]);
    memcpy(outer_masks[1], outer[1], sizeof *outer_masks[1]);
    for (i = 0; i < ARRAY_SIZE(actions); i++) {
        enum dpdk_reg_id set_tags[] = {
            REG_FIELD_CT_STATE,
            REG_FIELD_CT_MARK,
            REG_FIELD_CT_LABEL_ID,
        };
        int j;

        ct_reg = &reg_fields[REG_FIELD_CT_CTX];
        reg_mask = ct_reg->mask << ct_reg->offset;
        /* Use 0xFFFs values to set pkt_meta in the action upon pipe create
         * and have the mask in the actions_mask
         */
        actions[i].meta.pkt_meta = UINT32_MAX;
        actions_masks[i].meta.pkt_meta = ct_reg->mask << ct_reg->offset;
        for (j = 0; j < ARRAY_SIZE(set_tags); j++) {
            ct_reg = &reg_fields[set_tags[j]];
            reg_mask = ct_reg->mask << ct_reg->offset;
            /* Use 0xFFFs values to set meta.u32 in the action upon pipe create
             * and have the mask in the actions_mask
             */
            actions[i].meta.u32[ct_reg->index] = UINT32_MAX;
            actions_masks[i].meta.u32[ct_reg->index] |= reg_mask;
        }
        actions_list[i] = &actions[i];
        actions_masks_list[i] = &actions_masks[i];
    }

    /* Finalize the match templates. */
    ct_reg = &reg_fields[REG_FIELD_CT_ZONE];
    reg_mask = ct_reg->mask << ct_reg->offset;
    ct_matches[CT_NW_IP4][CT_TP_UDP].meta.u32[ct_reg->index] = reg_mask;
    ct_matches[CT_NW_IP4][CT_TP_TCP].meta.u32[ct_reg->index] = reg_mask;
    /* The mask is identical to the match itself. */
    match_mask = ct_matches[nw_type][tp_type];

    monitor.flags = DOCA_FLOW_MONITOR_COUNT;

    cfg.attr.name = ds_cstr(&pipe_name);
    cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
    cfg.attr.is_root = false;
    cfg.attr.nb_actions = nb_actions,
    cfg.attr.nb_flows = OVS_DOCA_MAX_CT_RULES;
    cfg.port = doca_flow_port_switch_get();
    cfg.match = &ct_matches[nw_type][tp_type];
    cfg.match_mask = &match_mask;
    cfg.actions = actions_list;
    cfg.actions_masks = actions_masks_list;
    cfg.monitor = &monitor;

    fwd_pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, POSTCT_TABLE_ID);
    if (fwd_pipe_ctx == NULL) {
        VLOG_ERR("%s: Failed to take a reference on post-ct table",
                 netdev_get_name(netdev));
        return -1;
    }
    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = fwd_pipe_ctx->pipe;

    next_ct = ct_action_next[ct_type];
    if (next_ct != CT_ACTION_NULL) {
        miss_pipe = ctx->ct_pipes[nw_type][tp_type][next_ct].pipe;
    } else {
        miss_pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, MISS_TABLE_ID);
        if (miss_pipe_ctx == NULL) {
            VLOG_ERR("%s: Failed to take a reference on miss table",
                     netdev_get_name(netdev));
            return -1;
        }
        miss_pipe = miss_pipe_ctx->pipe;
    }
    miss.type = DOCA_FLOW_FWD_PIPE;
    miss.next_pipe = miss_pipe;

    ret = doca_flow_pipe_create(&cfg, &fwd, &miss, &pipe_ctx->pipe);
    if (ret) {
        VLOG_ERR("%s: Failed to create basic pipe: %d (%s)",
                 netdev_get_name(netdev), ret,
                 doca_get_error_string(ret));
        goto error;
    }

    pipe_ctx->fwd_pipe_ctx = fwd_pipe_ctx;
    pipe_ctx->miss_pipe_ctx = miss_pipe_ctx;
    ds_destroy(&pipe_name);
    return 0;

error:
    doca_ctl_pipe_ctx_unref(fwd_pipe_ctx);
    doca_ctl_pipe_ctx_unref(miss_pipe_ctx);
    ds_destroy(&pipe_name);
    return ret;
}

static int
doca_ct_pipes_init(struct netdev *netdev, struct doca_eswitch_ctx *ctx)
{
    int i, j, k;

    for (i = 0; i < NUM_CT_NW; i++) {
        for (j = 0; j < NUM_CT_TP; j++) {
            for (k = 0; k < NUM_CT_ACTIONS; k++) {
                if (doca_ct_pipe_init(netdev, ctx, i, j, k)) {
                    goto error;
                }
            }
        }
    }

    return 0;

error:
    /* Rollback any pipe creation. */
    doca_ct_pipes_destroy(ctx);
    return -1;
}

static struct offload_metadata *doca_eswitch_md;

static void
doca_eswitch_ctx_uninit(void *ctx_)
{
    struct doca_eswitch_ctx *ctx = ctx_;

    doca_ct_zones_uninit(ctx);
    doca_ct_pipes_destroy(ctx);
    if (ctx->root_pipe_ctx != NULL) {
        doca_ctl_pipe_ctx_unref(ctx->root_pipe_ctx);
    }
    ctx->root_pipe_ctx = NULL;
    ctx->esw_port = NULL;
}

static int
doca_eswitch_ctx_init(void *ctx_, void *arg_, uint32_t id OVS_UNUSED)
{
    struct netdev *netdev = (struct netdev *) arg_;
    struct doca_eswitch_ctx *ctx = ctx_;

    ctx->root_pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, 0);
    if (ctx->root_pipe_ctx == NULL) {
        goto error;
    }

    if (doca_ct_pipes_init(netdev, ctx)) {
        goto error;
    }

    if (doca_ct_zones_init(netdev, ctx)) {
        goto error;
    }

    ctx->esw_port = doca_flow_port_switch_get();

    return 0;

error:
    VLOG_ERR("%s: Failed to init eswitch %d",
             netdev_get_name(netdev),
             netdev_dpdk_get_esw_mgr_port_id(netdev));
    doca_eswitch_ctx_uninit(ctx);
    return -1;
}

static struct ds *
dump_doca_eswitch(struct ds *s, void *key_, void *ctx_, void *arg_ OVS_UNUSED)
{
    struct doca_flow_port *esw_port = key_;
    struct doca_eswitch_ctx *ctx = ctx_;

    if (ctx) {
        ds_put_format(s, "ct_zone_rules_array=%p",
                      ctx->zone_flows);
    }
    ds_put_format(s, "esw_port=%p, ", esw_port);

    return s;
}

static void
doca_eswitch_init(void)
{
    static struct ovsthread_once init_once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&init_once)) {
        struct offload_metadata_parameters params = {
            .priv_size = sizeof(struct doca_eswitch_ctx),
            .priv_init = doca_eswitch_ctx_init,
            .priv_uninit = doca_eswitch_ctx_uninit,
        };

        /* Only one thread (main) handles the eswitch offload metadata. */
        doca_eswitch_md = offload_metadata_create(1, "doca_eswitch",
                                                  sizeof(struct doca_flow_port *),
                                                  dump_doca_eswitch, params);

        ovsthread_once_done(&init_once);
    }
}

/* Get the current eswitch context for this netdev,
 * /!\ without taking a reference, and without creating it!
 * The eswitch context must have been initialized once
 * beforehand using 'doca_eswitch_ctx_ref()' for this netdev.
 */
static struct doca_eswitch_ctx *
doca_eswitch_ctx_get(struct netdev *netdev)
{
    struct netdev_offload_dpdk_data *data;

    data = (struct netdev_offload_dpdk_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);
    return data->eswitch_ctx;
}

static struct doca_eswitch_ctx *
doca_eswitch_ctx_ref(struct netdev *netdev)
{
    struct doca_flow_port *esw_port = doca_flow_port_switch_get();

    doca_eswitch_init();
    return offload_metadata_priv_get(doca_eswitch_md, &esw_port, netdev,
                                     NULL, true);
}

static void
doca_eswitch_ctx_unref(struct doca_eswitch_ctx *ctx)
{
    offload_metadata_priv_unref(doca_eswitch_md,
                                netdev_offload_thread_id(),
                                ctx);
}

static void
dpdk_offload_doca_aux_tables_uninit(struct netdev *netdev)
{
    struct netdev_offload_dpdk_data *data;

    if (netdev_vport_is_vport_class(netdev->netdev_class)) {
        return;
    }

    data = (struct netdev_offload_dpdk_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);

    doca_eswitch_ctx_unref(data->eswitch_ctx);
}

static int
dpdk_offload_doca_aux_tables_init(struct netdev *netdev)
{
    struct netdev_offload_dpdk_data *data;
    struct doca_eswitch_ctx *ctx;

    if (netdev_vport_is_vport_class(netdev->netdev_class)) {
        return 0;
    }

    ctx = doca_eswitch_ctx_ref(netdev);
    if (!ctx) {
        VLOG_ERR("%s: Failed to get doca eswitch ctx", netdev_get_name(netdev));
        return -1;
    }

    data = (struct netdev_offload_dpdk_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);
    data->eswitch_ctx = ctx;

    return 0;
}

struct dpdk_offload_api dpdk_offload_api_doca = {
    .create = dpdk_offload_doca_create,
    .destroy = dpdk_offload_doca_destroy,
    .query_count = dpdk_offload_doca_query_count,
    .get_packet_recover_info = dpdk_offload_doca_get_pkt_recover_info,
    .reg_fields = dpdk_offload_doca_get_reg_fields,
    .netdev_data_destroy = dpdk_offload_doca_netdev_data_destroy,
    .update_stats = dpdk_offload_doca_update_stats,
    .aux_tables_init = dpdk_offload_doca_aux_tables_init,
    .aux_tables_uninit = dpdk_offload_doca_aux_tables_uninit,
};
