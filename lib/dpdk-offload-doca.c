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

VLOG_DEFINE_THIS_MODULE(dpdk_offload_doca);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);

OVS_ASSERT_PACKED(struct doca_eswitch_ctx,
    struct doca_flow_port *esw_port;
    struct fixed_rule ct_nat_miss;
    struct fixed_rule zone_flows[2][2][MAX_ZONE_ID + 1];
);

struct doca_flow_handle_resources {
     uint32_t group;
     struct doca_ctl_pipe_ctx *self_pipe;
     uint32_t next_group;
     struct doca_ctl_pipe_ctx *next_pipe;
};

struct doca_flow_handle {
     struct doca_flow_pipe_entry *flow;
     struct doca_flow_handle_resources flow_res;
};

OVS_ASSERT_PACKED(struct doca_ctl_pipe_key,
    uint32_t group_id;
    uint32_t esw_mgr_port_id;
);

struct doca_ctl_pipe_ctx {
    struct doca_flow_pipe *pipe;
};

struct doca_ctl_pipe_arg {
    struct netdev *netdev;
    struct doca_flow_pipe_cfg cfg;
};

static int
doca_ctl_pipe_ctx_init(void *ctx_, void *arg_, uint32_t id OVS_UNUSED)
{
    struct doca_ctl_pipe_ctx *ctx = ctx_;
    struct doca_ctl_pipe_arg *arg = arg_;
    int ret;

    ret = doca_flow_pipe_create(&arg->cfg, NULL, NULL, &ctx->pipe);
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

static bool
is_ct_zone_group_id(uint32_t group)
{
    return ((group >= CT_TABLE_ID + MIN_ZONE_ID &&
             group <= CT_TABLE_ID + MAX_ZONE_ID) ||
            (group >= CTNAT_TABLE_ID + MIN_ZONE_ID &&
             group <= CTNAT_TABLE_ID + MAX_ZONE_ID));
}

static struct doca_ctl_pipe_ctx *
doca_ctl_pipe_ctx_ref(struct netdev *netdev,
                      uint32_t group_id)
{
    struct doca_ctl_pipe_key key = {
        .group_id = group_id,
        .esw_mgr_port_id = netdev_dpdk_get_esw_mgr_port_id(netdev),
    };
    struct doca_ctl_pipe_arg arg = {
        .netdev = netdev,
    };
    char pipe_name[50];
    bool is_root;

    /* The pipe for recirc = 0 without any tunnel involved is
     * global and shared among devices on the esw. It is a root pipe.
     */
    is_root = (group_id == 0);
    snprintf(pipe_name, sizeof pipe_name, "OVS_CTL_PIPE_%" PRIu32, group_id);

    memset(&arg.cfg, 0, sizeof arg.cfg);
    arg.cfg.attr.name = pipe_name;
    arg.cfg.attr.type = DOCA_FLOW_PIPE_CONTROL;
    arg.cfg.attr.is_root = is_root;
    arg.cfg.port = doca_flow_port_switch_get();

    if (is_ct_zone_group_id(group_id)) {
        arg.cfg.attr.nb_flows = 2;
    } else if (group_id == MISS_TABLE_ID) {
        arg.cfg.attr.nb_flows = 1;
    } else if (group_id == CT_TABLE_ID || group_id == CTNAT_TABLE_ID) {
        arg.cfg.attr.nb_flows = DOCA_OFFLOAD_MAX_CT_CONNS;
    }

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
                       const struct rte_flow_action *actions,
                       struct doca_flow_actions *dacts,
                       struct doca_flow_action_descs *acts_descs OVS_UNUSED,
                       struct doca_flow_fwd *fwd,
                       struct doca_flow_monitor *monitor,
                       struct doca_flow_handle_resources *flow_res)
{
    struct doca_flow_header_format *outer = &dacts->outer;
    bool vlan_act_push = false;

    for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
        int act_type = actions->type;

        if (act_type == RTE_FLOW_ACTION_TYPE_DROP) {
            fwd->type = DOCA_FLOW_FWD_DROP;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_MAC_SRC) {
            memcpy(&outer->eth.src_mac, actions->conf, DOCA_ETHER_ADDR_LEN);
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_MAC_DST) {
            memcpy(&outer->eth.dst_mac, actions->conf, DOCA_ETHER_ADDR_LEN);
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
            }
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC) {
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            outer->ip4.src_ip = *(__be32 *) actions->conf;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_IPV4_DST) {
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            outer->ip4.dst_ip = *(__be32 *) actions->conf;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_IPV4_TTL) {
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            outer->ip4.ttl = *(__u8 *) actions->conf;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_IPV6_HOP) {
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP6;
            outer->ip6.hop_limit = *(__u8 *) actions->conf;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC) {
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP6;
            memcpy(&outer->ip6.src_ip, actions->conf, sizeof outer->ip6.src_ip);
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_IPV6_DST) {
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP6;
            memcpy(&outer->ip6.dst_ip, actions->conf, sizeof outer->ip6.dst_ip);
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_TP_SRC) {
            outer->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
            outer->tcp.l4_port.src_port = *(__u16 *) actions->conf;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_TP_DST) {
            outer->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
            outer->tcp.l4_port.dst_port = *(__u16 *) actions->conf;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_PORT_ID) {
            const struct rte_flow_action_port_id *port_id = actions->conf;

            fwd->type = DOCA_FLOW_FWD_PORT;
            fwd->port_id = port_id->id;
        } else if ((act_type == RTE_FLOW_ACTION_TYPE_NVGRE_DECAP) ||
                   (act_type == RTE_FLOW_ACTION_TYPE_VXLAN_DECAP)) {
            /* VXLAN and GRE supported natively */
            dacts->decap = true;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_COUNT) {
            monitor->flags |= DOCA_FLOW_MONITOR_COUNT;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_JUMP) {
            const struct rte_flow_action_jump *jump = actions->conf;
            struct doca_ctl_pipe_ctx *next_pipe;

            next_pipe = doca_ctl_pipe_ctx_ref(netdev, jump->group);
            if (!next_pipe) {
                return -1;
            }

            fwd->type = DOCA_FLOW_FWD_PIPE;
            fwd->next_pipe = next_pipe->pipe;
            flow_res->next_pipe = next_pipe;
            flow_res->next_group = jump->group;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP) {
            if (doca_translate_vxlan_encap(actions, dacts)) {
                return -1;
            }
        } else if (act_type == OVS_RTE_FLOW_ACTION_TYPE(FLOW_INFO)) {
            uint32_t reg_offset = reg_fields[REG_FIELD_FLOW_INFO].offset;
            const struct rte_flow_action_mark *mark = actions->conf;
            uint32_t reg_mask = reg_fields[REG_FIELD_FLOW_INFO].mask;

            dacts->meta.pkt_meta |= (mark->id & reg_mask) << reg_offset;
            acts_descs->meta.pkt_meta.mask.u32 |= reg_mask << reg_offset;
            acts_descs->meta.pkt_meta.type = DOCA_FLOW_ACTION_SET;
        } else if (act_type == OVS_RTE_FLOW_ACTION_TYPE_CT_INFO) {
            const struct rte_flow_action_set_meta *set_meta = actions->conf;
            uint32_t reg_offset = reg_fields[REG_FIELD_CT_CTX].offset;
            uint32_t reg_mask = reg_fields[REG_FIELD_CT_CTX].mask;

            dacts->meta.pkt_meta |= (set_meta->data & reg_mask) << reg_offset;
            acts_descs->meta.pkt_meta.mask.u32 |= (set_meta->mask & reg_mask) << reg_offset;
            acts_descs->meta.pkt_meta.type = DOCA_FLOW_ACTION_SET;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_SET_TAG) {
            const struct rte_flow_action_set_tag *set_tag = actions->conf;
            uint8_t index = set_tag->index;

            dacts->meta.u32[index] |= set_tag->data;
            acts_descs->meta.u32[index].mask.u32 |= set_tag->mask;
            acts_descs->meta.u32[index].type = DOCA_FLOW_ACTION_SET;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_OF_POP_VLAN) {
            /* Current support is for a single VLAN tag */
            if (dacts->pop) {
                return -1;
            }
            dacts->pop = true;
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

static struct doca_flow_pipe_entry *
create_doca_flow_entry(struct netdev *netdev,
                       struct doca_ctl_pipe_ctx *self_pipe,
                       uint32_t prio,
                       struct doca_flow_match *spec,
                       struct doca_flow_match *mask,
                       struct doca_flow_actions *actions,
                       struct doca_flow_action_descs *action_descs,
                       struct doca_flow_monitor *monitor,
                       struct doca_flow_fwd *fwd,
                       struct rte_flow_error *error)
{
    unsigned int tid = netdev_offload_thread_id();
    struct doca_flow_pipe *pipe = self_pipe->pipe;
    struct doca_flow_pipe_entry *entry;
    doca_error_t err;

    err = doca_flow_pipe_control_add_entry(tid, prio, pipe, spec, mask, actions,
                                           action_descs, monitor, fwd, &entry);
    if (err) {
        VLOG_WARN_RL(&rl, "%s: Failed to create ctl pipe entry. Error: %d (%s)",
                     netdev_get_name(netdev), err, doca_get_error_string(err));
        error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
        error->message = doca_get_error_string(err);
        return NULL;
    }

    return entry;
}
static struct doca_flow_handle *
create_doca_flow_handle(struct netdev *netdev,
                        uint32_t prio,
                        uint32_t group,
                        struct doca_flow_match *spec,
                        struct doca_flow_match *mask,
                        struct doca_flow_actions *actions,
                        struct doca_flow_action_descs *action_descs,
                        struct doca_flow_monitor *monitor,
                        struct doca_flow_fwd *fwd,
                        struct doca_flow_handle_resources *flow_res,
                        struct rte_flow_error *error)
{
    struct doca_ctl_pipe_ctx *pipe_ctx;
    struct doca_flow_handle *hndl;

    hndl = xzalloc(sizeof *hndl);
    if (!hndl) {
        error->type = RTE_FLOW_ERROR_TYPE_UNSPECIFIED;
        error->message = "Could not allocate doca flow handle";

        return NULL;
    }

    /* get self table pointer */
    pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, group);
    if (!pipe_ctx) {
        error->type = RTE_FLOW_ERROR_TYPE_UNSPECIFIED;
        error->message = "Could not create table";
        goto err_pipe;
    }

    /* insert rule */
    hndl->flow = create_doca_flow_entry(netdev, pipe_ctx, prio, spec, mask,
                                        actions, action_descs, monitor,
                                        fwd, error);
    if (!hndl->flow) {
        error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
        error->message = "Could not insert rule";
        goto err_insert;
    }

    memcpy(&hndl->flow_res, flow_res, sizeof *flow_res);
    hndl->flow_res.self_pipe = pipe_ctx;
    hndl->flow_res.group = group;

    return hndl;

err_insert:
    doca_ctl_pipe_ctx_unref(pipe_ctx);
err_pipe:
    free(hndl);

    return NULL;
}

static void *
dpdk_offload_doca_create(struct netdev *netdev,
                         const struct rte_flow_attr *attr,
                         struct rte_flow_item *items,
                         struct rte_flow_action *actions,
                         struct rte_flow_error *error)
{
    struct doca_flow_handle_resources flow_res;
    struct doca_flow_action_descs dacts_descs;
    struct doca_flow_monitor monitor;
    struct doca_flow_actions dacts;
    struct doca_flow_handle *hndl;
    struct doca_flow_match mask;
    struct doca_flow_match spec;
    struct doca_flow_fwd fwd;
    uint32_t prio;

    memset(&dacts_descs, 0x0, sizeof dacts_descs);
    memset(&flow_res, 0x0, sizeof flow_res);
    memset(&monitor, 0x0, sizeof monitor);
    memset(&dacts, 0x0, sizeof dacts);
    memset(&mask, 0x0, sizeof mask);
    memset(&spec, 0x0, sizeof spec);
    memset(&fwd, 0x0, sizeof fwd);

    if (doca_translate_items(netdev, attr, items, &spec, &mask)) {
        error->type = RTE_FLOW_ERROR_TYPE_ITEM;
        error->message = "Could not create items";
        return NULL;
    }

    /* parse actions */
    if (doca_translate_actions(netdev, actions, &dacts, &dacts_descs,
                               &fwd, &monitor, &flow_res)) {
        error->type = RTE_FLOW_ERROR_TYPE_ACTION;
        error->message = "Could not create actions";
        return NULL;
    }

    prio = (flow_res.next_group == MISS_TABLE_ID);
    hndl = create_doca_flow_handle(netdev, prio, attr->group, &spec, &mask,
                                   &dacts, &dacts_descs, &monitor, &fwd,
                                   &flow_res, error);
    if (!hndl) {
        /* change to free doca flow resources function */
        if (flow_res.next_pipe) {
            doca_ctl_pipe_ctx_unref(flow_res.next_pipe);
        }
    }

    return hndl;
}

static doca_error_t
destroy_doca_flow_entry(struct doca_flow_pipe_entry *flow)
{
    unsigned int tid = netdev_offload_thread_id();

    return doca_flow_pipe_rm_entry(tid, DOCA_FLOW_NO_WAIT, NULL, flow);
}

static int
dpdk_offload_doca_destroy(struct netdev *netdev OVS_UNUSED,
                          struct rte_flow *rte_flow,
                          struct rte_flow_error *error,
                          bool esw_port_id OVS_UNUSED)
{
    struct doca_flow_handle *hndl;
    doca_error_t err;

    hndl = (struct doca_flow_handle *) (void *) rte_flow;

    err = destroy_doca_flow_entry(hndl->flow);
    if (err) {
        error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
        error->message = doca_get_error_string(err);
        return -1;
    }

    if (hndl->flow_res.next_pipe) {
        doca_ctl_pipe_ctx_unref(hndl->flow_res.next_pipe);
    }

    doca_ctl_pipe_ctx_unref(hndl->flow_res.self_pipe);
    free(hndl);

    return 0;
}

static int
dpdk_offload_doca_query_count(struct netdev *netdev,
                              struct rte_flow *rte_flow,
                              struct rte_flow_query_count *query,
                              struct rte_flow_error *error)
{
    struct doca_flow_pipe_entry *doca_flow;
    struct doca_flow_handle *hndl;
    struct doca_flow_query stats;
    doca_error_t err;

    hndl = (struct doca_flow_handle *) (void *) rte_flow;
    doca_flow = hndl->flow;

    memset(query, 0, sizeof *query);
    memset(&stats, 0, sizeof stats);

    err = doca_flow_query_entry(doca_flow, &stats);
    if (err) {
        VLOG_DBG_RL(&rl, "%s: Failed to query doca_flow: %p. Error %d (%s)",
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
    if (!get_packet_reg_field(p, &reg_fields[REG_FIELD_FLOW_INFO],
                              &info->flow_miss_id)) {
            get_packet_reg_field(p, &reg_fields[REG_FIELD_CT_CTX],
                                 &info->ct_miss_id);
    }
}

static int
dpdk_offload_doca_netdev_data_destroy(void *data)
{
    return netdev_dpdk_doca_port_destroy((struct netdev *) data);
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
doca_fixed_rule_uninit(unsigned int tid,
                       struct fixed_rule *fr)
{
    if (fr->creation_tid != tid || !fr->flow) {
        return;
    }

    dpdk_offload_doca_destroy(NULL, fr->flow, NULL, true);
    fr->flow = NULL;
}

static void
doca_ct_nat_miss_uninit(unsigned int tid,
                        struct fixed_rule *fr)
{
    doca_fixed_rule_uninit(tid, fr);
}

static int
doca_ct_nat_miss_init(struct netdev *netdev, unsigned int tid,
                      struct fixed_rule *fr)
{
    struct doca_flow_handle_resources flow_res;
    struct doca_ctl_pipe_ctx *next_pipe_ctx;
    struct rte_flow_error error;
    struct doca_flow_fwd fwd;

    memset(&flow_res, 0x0, sizeof flow_res);
    memset(&fwd, 0x0, sizeof fwd);

    next_pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, CT_TABLE_ID);
    if (!next_pipe_ctx) {
        return -1;
    }

    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = next_pipe_ctx->pipe;
    flow_res.next_pipe = next_pipe_ctx;
    flow_res.next_group = CT_TABLE_ID;

    fr->flow = create_doca_flow_handle(netdev, 1, CTNAT_TABLE_ID,
                                       NULL, NULL, NULL, NULL, NULL,
                                       &fwd, &flow_res, &error);
    fr->creation_tid = tid;

    if (fr->flow == NULL) {
        return -1;
    }
    return 0;
}

static void
doca_ct_zones_uninit(unsigned int tid,
                     struct doca_eswitch_ctx *ctx)
{
    struct fixed_rule *fr;
    uint32_t zone_id;
    int nat, i;

    if (netdev_is_zone_tables_disabled()) {
        return;
    }

    for (nat = 0; nat < 2; nat++) {
        for (i = 0; i < 2; i++) {
            for (zone_id = MIN_ZONE_ID; zone_id <= MAX_ZONE_ID; zone_id++) {
                fr = &ctx->zone_flows[nat][i][zone_id];

                doca_fixed_rule_uninit(tid, fr);
            }
        }
    }
}

static void *
doca_create_ct_zone_revisit_rule(struct netdev *netdev, uint32_t group,
                                 uint32_t zone, int nat)
{
    struct doca_flow_handle_resources flow_res;
    struct doca_ctl_pipe_ctx *next_pipe_ctx;
    uint32_t ct_state_spec, ct_state_mask;
    uint32_t ct_zone_spec, ct_zone_mask;
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
        return NULL;
    }

    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = next_pipe_ctx->pipe;
    flow_res.next_pipe = next_pipe_ctx;
    flow_res.next_group = POSTCT_TABLE_ID;

    return create_doca_flow_handle(netdev, 0, group, &spec, &mask,
                                   NULL, NULL, NULL,
                                   &fwd, &flow_res, &error);
}

static void *
doca_create_ct_zone_uphold_rule(struct netdev *netdev, uint32_t group,
                                uint32_t zone, int nat)
{
    struct doca_flow_handle_resources flow_res;
    struct doca_flow_action_descs dacts_descs;
    struct doca_ctl_pipe_ctx *next_pipe_ctx;
    struct doca_flow_actions dacts;
    struct rte_flow_error error;
    struct reg_field *reg_field;
    struct doca_flow_fwd fwd;
    uint32_t next_group;

    memset(&dacts_descs, 0x0, sizeof dacts_descs);
    memset(&flow_res, 0x0, sizeof flow_res);
    memset(&dacts, 0x0, sizeof dacts);
    memset(&fwd, 0x0, sizeof fwd);

    reg_field = &reg_fields[REG_FIELD_CT_ZONE];
    dacts.meta.u32[reg_field->index] |= zone << reg_field->offset;
    dacts_descs.meta.u32[reg_field->index].mask.u32 |= reg_field->mask << reg_field->offset;
    dacts_descs.meta.u32[reg_field->index].type = DOCA_FLOW_ACTION_SET;

    next_group = nat ? CTNAT_TABLE_ID : CT_TABLE_ID;
    next_pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, next_group);
    if (!next_pipe_ctx) {
        return NULL;
    }

    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = next_pipe_ctx->pipe;
    flow_res.next_pipe = next_pipe_ctx;
    flow_res.next_group = next_group;

    return create_doca_flow_handle(netdev, 1, group, NULL, NULL,
                                   &dacts, &dacts_descs, NULL,
                                   &fwd, &flow_res, &error);
}

static int
doca_ct_zones_init(struct netdev *netdev, unsigned int tid,
                   struct doca_eswitch_ctx *ctx)
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
            fr = &ctx->zone_flows[nat][0][zone_id];
            fr->flow = doca_create_ct_zone_revisit_rule(netdev, base_group + zone_id,
                                                        zone_id, nat);
            fr->creation_tid = tid;
            if (fr->flow == NULL) {
                goto err;
            }

            fr = &ctx->zone_flows[nat][1][zone_id];
            /* Otherwise, set the zone and go to CT/CT-NAT. */
            fr->flow = doca_create_ct_zone_uphold_rule(netdev, base_group + zone_id,
                                                       zone_id, nat);
            fr->creation_tid = tid;
            if (fr->flow == NULL) {
                goto err;
            }
        }
    }

    return 0;

err:
    doca_ct_zones_uninit(tid, ctx);
    return -1;
}

static struct offload_metadata *doca_eswitch_md;

static void
doca_eswitch_ctx_uninit(void *ctx_)
{
    unsigned int tid = netdev_offload_thread_id();
    struct doca_eswitch_ctx *ctx = ctx_;

    doca_ct_nat_miss_uninit(tid, &ctx->ct_nat_miss);
    doca_ct_zones_uninit(tid, ctx);
    ctx->esw_port = NULL;
}

static int
doca_eswitch_ctx_init(void *ctx_, void *arg_, uint32_t id OVS_UNUSED)
{
    struct netdev *netdev = (struct netdev *) arg_;
    unsigned int tid = netdev_offload_thread_id();
    struct doca_eswitch_ctx *ctx = ctx_;
    int ret;

    ret = doca_ct_nat_miss_init(netdev, tid, &ctx->ct_nat_miss);
    if (!ret) {
        ret = doca_ct_zones_init(netdev, tid, ctx);
    }

    if (ret) {
        VLOG_WARN("Cannot apply init flows for netdev %s esw mgr id: %d",
                  netdev_get_name(netdev),
                  netdev_dpdk_get_esw_mgr_port_id(netdev));
        doca_eswitch_ctx_uninit(ctx);

        return ret;
    }

    ctx->esw_port = doca_flow_port_switch_get();

    return 0;
}

static struct ds *
dump_doca_eswitch(struct ds *s, void *key_, void *ctx_, void *arg_ OVS_UNUSED)
{
    struct doca_flow_port *esw_port = key_;
    struct doca_eswitch_ctx *ctx = ctx_;

    if (ctx) {
        ds_put_format(s, "ct_nat_miss_rule=%p, ct_zone_rules_array=%p",
                      &ctx->ct_nat_miss, ctx->zone_flows);
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
        unsigned int nb_thread = netdev_offload_thread_nb();

        doca_eswitch_md = offload_metadata_create(nb_thread, "doca_eswitch",
                                                  sizeof(struct doca_flow_port *),
                                                  dump_doca_eswitch, params);

        ovsthread_once_done(&init_once);
    }
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
