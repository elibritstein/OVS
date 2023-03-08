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
#include "util.h"

VLOG_DEFINE_THIS_MODULE(dpdk_offload_doca);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);

struct doca_flow_handle {
     struct doca_flow_pipe_entry *flow;
     uint32_t group;
     struct doca_ctl_pipe_ctx *self_pipe;
     uint32_t next_group;
     struct doca_ctl_pipe_ctx *next_pipe;
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
        .offset = 0,
        .mask = 0x00FFFFFF,
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
        doca_spec->tun.vxlan_tun_id = htonl(ntohll(spec_vni) << 8);
    }

    doca_mask->tun.type = DOCA_FLOW_TUN_VXLAN;
    if (item->mask) {
        mask_vni = get_unaligned_be32(ALIGNED_CAST(ovs_be32 *,
                    vxlan_mask->vni));
        doca_mask->tun.vxlan_tun_id = htonl(ntohll(mask_vni) << 8);
    }
}

static int
doca_translate_items(struct netdev *netdev OVS_UNUSED,
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
                       struct doca_flow_handle *hndl)
{
    struct doca_flow_header_format *outer = &dacts->outer;

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
            outer->eth_vlan[0].tci = rte_vlan_vid->vlan_vid;
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
            hndl->next_pipe = next_pipe;
            hndl->next_group = jump->group;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP) {
            if (doca_translate_vxlan_encap(actions, dacts)) {
                return -1;
            }
        } else if (act_type == OVS_RTE_FLOW_ACTION_TYPE_FLOW_INFO) {
            const struct rte_flow_action_mark *mark = actions->conf;

            dacts->meta.pkt_meta = mark->id;
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

static void *
dpdk_offload_doca_create(struct netdev *netdev,
                         const struct rte_flow_attr *attr,
                         struct rte_flow_item *items,
                         struct rte_flow_action *actions,
                         struct rte_flow_error *error)
{
    struct doca_flow_action_descs dacts_descs;
    struct doca_ctl_pipe_ctx *pipe_ctx;
    struct doca_flow_monitor monitor;
    struct doca_flow_actions dacts;
    struct doca_flow_handle *hndl;
    struct doca_flow_match mask;
    struct doca_flow_match spec;
    struct doca_flow_fwd fwd;
    uint32_t prio;

    memset(&dacts_descs, 0x0, sizeof dacts_descs);
    memset(&monitor, 0x0, sizeof monitor);
    memset(&dacts, 0x0, sizeof dacts);
    memset(&mask, 0x0, sizeof mask);
    memset(&spec, 0x0, sizeof spec);
    memset(&fwd, 0x0, sizeof fwd);

    if (doca_translate_items(netdev, items, &spec, &mask)) {
        return NULL;
    }

    hndl = xzalloc(sizeof *hndl);

    /* get self table pointer */
    pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, attr->group);
    if (!pipe_ctx) {
        error->type = RTE_FLOW_ERROR_TYPE_UNSPECIFIED;
        error->message = "Could not create table";
        goto err_pipe;
    }

    /* parse actions */
    if (doca_translate_actions(netdev, actions, &dacts, &dacts_descs,
                               &fwd, &monitor, hndl)) {
        error->type = RTE_FLOW_ERROR_TYPE_ACTION;
        error->message = "Could not create actions";
        goto err_actions;
    }

    /* insert rule */
    prio = (hndl->next_group == MISS_TABLE_ID);
    hndl->flow = create_doca_flow_entry(netdev, pipe_ctx, prio, &spec, &mask,
                                        &dacts, &dacts_descs, &monitor, &fwd, error);
    if (!hndl->flow) {
        error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
        error->message = "Could not insert rule";
        goto err_insert;
    }

    hndl->self_pipe = pipe_ctx;

    return hndl;

err_insert:
    /* change to free doca flow resources function */
    if (hndl->next_pipe) {
        doca_ctl_pipe_ctx_unref(hndl->next_pipe);
    }
err_actions:
    doca_ctl_pipe_ctx_unref(pipe_ctx);
err_pipe:
    free(hndl);

    return NULL;
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

    if (hndl->next_pipe) {
        doca_ctl_pipe_ctx_unref(hndl->next_pipe);
    }

    doca_ctl_pipe_ctx_unref(hndl->self_pipe);
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
    get_packet_reg_field(p, &reg_fields[REG_FIELD_FLOW_INFO],
                         &info->flow_miss_id);
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
    attrs->dp_layer = "doca";

    if (stats->n_packets != query->hits) {
        query->hits_set = 1;
        query->bytes_set = 1;
    }

    stats->n_packets = query->hits;
    stats->n_bytes = query->bytes;
}

struct dpdk_offload_api dpdk_offload_api_doca = {
    .create = dpdk_offload_doca_create,
    .destroy = dpdk_offload_doca_destroy,
    .query_count = dpdk_offload_doca_query_count,
    .get_packet_recover_info = dpdk_offload_doca_get_pkt_recover_info,
    .reg_fields = dpdk_offload_doca_get_reg_fields,
    .netdev_data_destroy = dpdk_offload_doca_netdev_data_destroy,
    .update_stats = dpdk_offload_doca_update_stats,
};
