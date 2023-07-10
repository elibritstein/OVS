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

#include "coverage.h"
#include "dp-packet.h"
#include "dpdk-offload-provider.h"
#include "id-fpool.h"
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
 * +---------------------------------------------------------------------------------------------------+
 * | Control pipes                                                                                     |
 * |                                                                                                   |
 * |                 ┌─[ CT Zone X ]─────┐                                                             |
 * |                 │  ┌─[ CT Zone Y ]─────┐                                                          |
 * |                 │  │  ┌─[ CT Zone Z ]─────┐                                                       |
 * |                 │  │  │                   │                                                       |
 * |                 │  │  │  ┌─────────┐      │                                                       |
 * |                 │  │  │  │ct_zone=Z├──────┼────────────────────────────────────────────┐          |
 * |                 │  │  │  └─────────┘hit   │                                            │          |
 * |                 │  │  │                   │    +----------------------------+          │          |
 * |                 │  │  │                   │    | Basic pipes                |          │          |
 * |                 │  │  │                   │    |                            |          │          |
 * |                 │  │  │                   │    |  ┌─[ CT IPv4 x UDP ]─┐     |          │          |
 * |                 │  │  │    ┌──────────┐   │    |  │                   │     |          │          |
 * |                 │  │  │    │IPv4 + UDP├───┼──────►│  ┌─[ CT IPv4 x TCP ]─┐  |          ▼          |
 * |  ┌─[ Pre-CT ]─┐ │  │  │    └──────────┘hit│    |  │  │                   │  |    ┌─[ Post-CT ]──┐ |
 * |  │            ├──────►│    ┌──────────┐   │    |  │  │ ┌─────────────┐   │──────►│              │ |
 * |  │            │ │  │  │    │IPv4 + TCP├───┼─────────►│ │ CT entries  ├───┼──────►│              │ |
 * |  └────────────┘ │  │  │    └──────────┘hit│    |  │  │ └─────────────┘hit│  |    └──────────────┘ |
 * |                 │  │  │       ┌─────────┐ │    |  │  │   ┌─────────┐     │  |                     |
 * |                 │  │  │       │Catch-all│ │    |  │  │   │Catch-all│     │  |                     |
 * |                 └──│  │       └────┬────┘ │    |  └──│   └────┬────┘     │  |                     |
 * |                    └──│            │      │    |     └────────┼──────────┘  |                     |
 * |                       └────────────┼──────┘    |           │  │             |                     |
 * |                                    │           +-----------│--│-------------+                     |
 * |                                    ▼                       │  │                                   |
 * |                             ┌─[ Miss pipe ]────────────────▼──▼───────┐                           |
 * |                             │         Go to software datapath         │                           |
 * |                             └─────────────────────────────────────────┘                           |
 * +---------------------------------------------------------------------------------------------------+
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
 * it is forwarded to the corresponding CT pipe. If no (network x protocol)
 * tuple matches, then CT is not supported for this flow and the packet
 * goes to software.
 *
 * The CT pipe is a basic pipe with a single action type, which writes to
 *
 *  * The packet registers used for CT metadata.
 *  * The packet 5-tuple.
 *
 * For plain CT, the 5-tuple is overwritten with its own values.
 * For NAT, the translations are written instead where relevant.
 *
 * In both cases, all fields are written anyway.
 * This way, the number of template used by the CT pipe is minimal.
 * During performance tests, no impact was measured due to the
 * superfluous writes.
 *
 * If a CT entry matches the packet, the CT pipe action is executed
 * and the packet is then forwarded to post-CT. Otherwise, the packet
 * goes to the miss pipe and is then handed over to the software
 * datapath.
 *
 * The diagram was drawn with https://asciiflow.com/ and edited in VIM.
 */

COVERAGE_DEFINE(doca_async_queue_full);
COVERAGE_DEFINE(doca_async_queue_blocked);
COVERAGE_DEFINE(doca_async_add_failed);

#define ENTRY_PROCESS_TIMEOUT_MS 1000
#define NUM_ZONE_FLOWS 4
/* TBD until doca can support insertion from more than one queue */
#define MAX_OFFLOAD_QUEUE_NB MAX_OFFLOAD_THREAD_NB
#define AUX_QUEUE 0

#define MAX_GENEVE_OPT 1

#define SHARED_CNT_N_IDS OVS_DOCA_MAX_CT_COUNTERS_PER_ESW

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

enum hash_pipe_type {
    HASH_TYPE_IPV4_UDP,
    HASH_TYPE_IPV4_TCP,
    HASH_TYPE_IPV4_L3,
    NUM_HASH_PIPE_TYPE,
};

struct doca_basic_pipe_ctx {
    struct doca_flow_pipe *pipe;
    struct doca_ctl_pipe_ctx *fwd_pipe_ctx;
    struct doca_ctl_pipe_ctx *miss_pipe_ctx;
};

/* ┌────────┐   ┌─────────────┐
 * │IPv4-UDP│──►│HASH-IPv4-UDP│
 * │        │   └─────────────┘
 * │        │   ┌─────────────┐
 * │IPv4-TCP│──►│HASH-IPv4-TCP│
 * └───┬────┘   └─────────────┘
 *     │ miss   ┌─────────────┐
 *     └───────►│HASH-IPv4-L3 │
 *              └─────────────┘
 * OVS always matches on ether type. Only 0x0800 (IPv4) is currently offloaded.
 * We only need to know TCP/UDP, or miss to simple L3.
 */
enum hash_tp_type {
    HASH_TP_UDP,
    HASH_TP_TCP,
    NUM_HASH_TP,
};

struct doca_hash_pipe_ctx {
    struct {
        struct doca_flow_pipe *pipe;
        struct doca_flow_pipe_entry *entry;
    } hashes[NUM_HASH_PIPE_TYPE];
    struct doca_flow_pipe *classifier;
    struct doca_flow_pipe_entry *tcpudp[NUM_HASH_TP];
    struct netdev *netdev;
};

struct doca_ctl_pipe_ctx {
    struct doca_flow_pipe *pipe;
    struct doca_hash_pipe_ctx *hash_pipe_ctx;
};

struct doca_async_entry {
    struct netdev *netdev; /* If set, port that posted this entry. */
    struct dpdk_offload_handle *doh; /* Corresponding handle for this entry. */
    unsigned int index; /* Index of this entry within the aync_state array. */
};

struct doca_async_state {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        unsigned int n_entries;
        struct doca_async_entry entries[OVS_DOCA_QUEUE_DEPTH];
    );
};

struct gnv_opt_parser {
    struct ovsthread_once once;
    struct doca_flow_parser *parser;
};

OVS_ASSERT_PACKED(struct doca_eswitch_ctx,
    struct doca_flow_port *esw_port;
    struct doca_ctl_pipe_ctx *root_pipe_ctx;
    struct gnv_opt_parser gnv_opt_parser;
    struct doca_async_state async_state[MAX_OFFLOAD_QUEUE_NB];
    struct doca_basic_pipe_ctx ct_pipes[NUM_CT_NW][NUM_CT_TP];
    struct fixed_rule zone_flows[2][NUM_ZONE_FLOWS][MAX_ZONE_ID + 1];
    struct id_fpool *shared_cnt_id_pool;
    uint32_t esw_id;
    char pad[4];
    struct doca_ctl_pipe_ctx *post_meter_pipe_ctx;
    struct fixed_rule post_meter_red_flow;
);

OVS_ASSERT_PACKED(struct doca_ctl_pipe_key,
    uint32_t group_id;
    uint32_t esw_mgr_port_id;
);

struct doca_ctl_pipe_arg {
    struct netdev *netdev;
    uint32_t group_id;
};

static struct id_fpool *esw_id_pool;

static struct doca_eswitch_ctx *
doca_eswitch_ctx_get(struct netdev *netdev);

/* From an async entry in the descriptor queue kept in an
 * eswitch context, find back through pointer arithmetic the
 * containing eswitch context. */
static inline struct doca_eswitch_ctx *
doca_eswitch_ctx_from_async_entry(struct doca_async_entry *dae,
                                  unsigned int qid)
{
    struct doca_async_state *das, *async_state;
    struct doca_async_entry *entries;

    entries = dae - dae->index;
    das = CONTAINER_OF(entries, struct doca_async_state, entries);
    async_state = das - qid;
    return CONTAINER_OF(async_state, struct doca_eswitch_ctx, async_state);
}

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

static bool
is_ct_zone_group_id(uint32_t group)
{
    return ((group >= CT_TABLE_ID + MIN_ZONE_ID &&
             group <= CT_TABLE_ID + MAX_ZONE_ID) ||
            (group >= CTNAT_TABLE_ID + MIN_ZONE_ID &&
             group <= CTNAT_TABLE_ID + MAX_ZONE_ID));
}

static int
doca_ctl_pipe_ctx_init(void *ctx_, void *arg_, uint32_t id OVS_UNUSED)
{
    struct doca_ctl_pipe_ctx *ctx = ctx_;
    struct doca_ctl_pipe_arg *arg = arg_;
    struct doca_flow_port *doca_port;
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
    doca_port = netdev_dpdk_doca_port_get(arg->netdev);

    memset(&cfg, 0, sizeof cfg);
    cfg.attr.name = pipe_name;
    cfg.attr.type = DOCA_FLOW_PIPE_CONTROL;
    cfg.attr.is_root = is_root;
    cfg.port = doca_flow_port_switch_get(doca_port);

    if (is_ct_zone_group_id(group_id)) {
        cfg.attr.nb_flows = NUM_ZONE_FLOWS;
    } else if (group_id == MISS_TABLE_ID) {
        cfg.attr.nb_flows = 1;
    } else {
        cfg.attr.nb_flows = ctl_pipe_size;
    }

    ret = doca_flow_pipe_create(&cfg, NULL, NULL, &ctx->pipe);
    if (ret) {
        VLOG_ERR("%s: Failed to create ctl pipe: %d (%s)",
                 netdev_get_name(arg->netdev), ret, doca_get_error_string(ret));
    }
    return ret;
}

static void
doca_hash_pipe_ctx_uninit(struct doca_hash_pipe_ctx *ctx)
{
    unsigned int queue_id = netdev_offload_thread_id();
    int i;

    if (ctx == NULL) {
        return;
    }

    for (i = 0; i < NUM_HASH_PIPE_TYPE; i++) {
        if (ctx->hashes[i].entry) {
            doca_flow_pipe_rm_entry(queue_id, DOCA_FLOW_NO_WAIT,
                                    ctx->hashes[i].entry);
            dpdk_offload_counter_dec(ctx->netdev);
        }
        if (ctx->hashes[i].pipe) {
            doca_flow_pipe_destroy(ctx->hashes[i].pipe);
        }
    }

    for (i = 0; i < NUM_HASH_TP; i++) {
        if (ctx->tcpudp[i]) {
            doca_flow_pipe_rm_entry(queue_id, DOCA_FLOW_NO_WAIT,
                                    ctx->tcpudp[i]);
            dpdk_offload_counter_dec(ctx->netdev);
        }
    }
    if (ctx->classifier) {
        doca_flow_pipe_destroy(ctx->classifier);
    }

    free(ctx);
}

static void
doca_ctl_pipe_ctx_uninit(void *ctx_)
{
    struct doca_ctl_pipe_ctx *ctx = ctx_;

    doca_hash_pipe_ctx_uninit(ctx->hash_pipe_ctx);
    doca_flow_pipe_destroy(ctx->pipe);
    ctx->pipe = NULL;
}

static struct ds *
dump_doca_ctl_pipe_ctx(struct ds *s, void *key_, void *ctx_, void *arg_ OVS_UNUSED)
{
    struct doca_ctl_pipe_key *key = key_;
    struct doca_ctl_pipe_ctx *ctx = ctx_;

    if (ctx) {
        ds_put_format(s, "hash_pipe_ctx=%p, ctl_pipe=%p, ", ctx->hash_pipe_ctx,
                      ctx->pipe);
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
    if (ctx == NULL) {
        return;
    }

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
        .mask = 0x00000FFF,
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
    [REG_FIELD_DP_HASH] = {
        .type = REG_TYPE_META,
        .index = 0,
        .offset = 12,
        .mask = 0x0000000F,
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

static int
doca_init_geneve_opt_parser(struct netdev *netdev,
                            const struct rte_flow_item *item)
{
    struct doca_flow_parser_geneve_opt_cfg opt_cfg[MAX_GENEVE_OPT];
    const struct rte_flow_item_geneve_opt *geneve_opt_spec;
    const struct rte_flow_item_geneve_opt *geneve_opt_mask;
    struct doca_eswitch_ctx *esw_ctx;
    int ret;

    esw_ctx = doca_eswitch_ctx_get(netdev);
    if (!esw_ctx) {
        VLOG_ERR("%s: Failed to create geneve_opt parser - esw_ctx is NULL",
                 netdev_get_name(netdev));
        return -1;
    }

    if (!ovsthread_once_start(&esw_ctx->gnv_opt_parser.once)) {
        return 0;
    }
    geneve_opt_spec = item->spec;
    geneve_opt_mask = item->mask;

    memset(&opt_cfg[0], 0, sizeof(opt_cfg[0]));
    opt_cfg[0].match_on_class_mode =
        DOCA_FLOW_PARSER_GENEVE_OPT_MODE_MATCHABLE;
    opt_cfg[0].option_len = geneve_opt_spec->option_len;
    opt_cfg[0].option_class = geneve_opt_spec->option_class;
    opt_cfg[0].option_type = geneve_opt_spec->option_type;
    BUILD_ASSERT_DECL(sizeof(opt_cfg[0].data_mask[0]) ==
                      sizeof(geneve_opt_mask->data[0]));
    memset(&opt_cfg[0].data_mask[0], UINT32_MAX,
           sizeof(opt_cfg[0].data_mask[0]) * geneve_opt_spec->option_len);

    ret = doca_flow_parser_geneve_opt_create(esw_ctx->esw_port, opt_cfg,
                                             MAX_GENEVE_OPT,
                                             &esw_ctx->gnv_opt_parser.parser);
    if (ret) {
        VLOG_DBG_RL(&rl, "%s: Create geneve_opt parser failed - doca call failure "
                         "rc %d, (%s)",netdev_get_name(netdev), ret,
                         doca_get_error_string(ret));
        ovsthread_once_reset(&esw_ctx->gnv_opt_parser.once);
        return -1;
    }
    ovsthread_once_done(&esw_ctx->gnv_opt_parser.once);
    return 0;
}

static void
doca_translate_geneve_opt_item(const struct rte_flow_item *item,
                               struct doca_flow_match *doca_spec,
                               struct doca_flow_match *doca_mask)
{
    union doca_flow_geneve_option *doca_opt_spec, *doca_opt_mask;
    const struct rte_flow_item_geneve_opt *geneve_opt_spec;
    const struct rte_flow_item_geneve_opt *geneve_opt_mask;

    geneve_opt_spec = item->spec;
    geneve_opt_mask = item->mask;
    doca_opt_spec = &doca_spec->tun.geneve_options[0];
    doca_opt_mask = &doca_mask->tun.geneve_options[0];

    doca_opt_spec->length = geneve_opt_spec->option_len;
    doca_opt_spec->class_id = geneve_opt_spec->option_class;
    doca_opt_spec->type = geneve_opt_spec->option_type;
    doca_opt_mask->length = geneve_opt_mask->option_len;
    doca_opt_mask->class_id = geneve_opt_mask->option_class;
    doca_opt_mask->type = geneve_opt_mask->option_type;

    /* doca_flow represents the geneve option header as an array of a union of
     * 32 bits, the array's first element is the type/class/len and this
     * option's data starts from the next element in the array up to option_len
     */
    doca_opt_spec++;
    doca_opt_mask++;
    BUILD_ASSERT_DECL(sizeof(doca_opt_spec->data) ==
                      sizeof(geneve_opt_spec->data[0]));
    memcpy(&doca_opt_spec->data, &geneve_opt_spec->data[0],
           sizeof(doca_opt_spec->data) * geneve_opt_spec->option_len);
    memcpy(&doca_opt_mask->data, &geneve_opt_mask->data[0],
           sizeof(doca_opt_mask->data) * geneve_opt_spec->option_len);
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
        } else if (item_type == RTE_FLOW_ITEM_TYPE_GENEVE_OPT) {
            if (doca_init_geneve_opt_parser(netdev, items)) {
                return -1;
            }
            doca_translate_geneve_opt_item(items, doca_spec, doca_mask);
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
        } else if (item_type == OVS_RTE_FLOW_ITEM_TYPE(HASH)) {
            uint32_t reg_offset = reg_fields[REG_FIELD_DP_HASH].offset;
            const struct rte_flow_item_mark *hash_spec = items->spec;
            const struct rte_flow_item_mark *hash_mask = items->mask;
            uint32_t reg_mask = reg_fields[REG_FIELD_DP_HASH].mask;

            /* In case of non-IPv4, the first flow with the hash function is
             * not offloaded, so there is no point to offload this flow as it
             * will never be hit.
             */
            if (doca_hdr_mask->l3_type != DOCA_FLOW_L3_TYPE_IP4) {
                return -1;
            }
            if (!hash_spec || !hash_mask || hash_mask->id & ~reg_mask) {
                /* Can't support larger mask. */
                return -1;
            }

            doca_spec->meta.pkt_meta |= (hash_spec->id & reg_mask) << reg_offset;
            doca_mask->meta.pkt_meta |= reg_mask << reg_offset;
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

    if (geneve->options[0].length) {
        encap->tun.geneve_options[0].class_id = geneve->options[0].opt_class;
        encap->tun.geneve_options[0].type = geneve->options[0].type;
        encap->tun.geneve_options[0].length = geneve->options[0].length;

        /* doca_flow represents the geneve option header as an array of a union
         * of 32 bits, the array's first element is the type/class/len and this
         * option's data starts from the next element in the array up to option_len
         */
        BUILD_ASSERT_DECL(sizeof(encap->tun.geneve_options[1].data) ==
                          sizeof(geneve->options[1]));
        memcpy(&encap->tun.geneve_options[1].data, &geneve->options[1],
               sizeof(encap->tun.geneve_options[1].data) * geneve->options[0].length);
    }

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
        outer->ip4.dscp_ecn = ip->ip_tos;
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
        outer->ip6.dscp_ecn = ntohl(get_16aligned_be32(&ip6->ip6_flow)) >> 20;
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
            outer->ip4.ttl = ip->ip_ttl;
            outer->ip4.dscp_ecn = ip->ip_tos;
        } else if (item_type == RTE_FLOW_ITEM_TYPE_IPV6) {
            const struct ovs_16aligned_ip6_hdr *ip6 = items->spec;

            outer->l3_type = DOCA_FLOW_L3_TYPE_IP6;
            memcpy(&outer->ip4.src_ip, &ip6->ip6_src, sizeof ip6->ip6_src);
            outer->l3_type = DOCA_FLOW_L3_TYPE_IP6;
            memcpy(&outer->ip4.dst_ip, &ip6->ip6_dst, sizeof ip6->ip6_dst);
            outer->ip6.hop_limit = ip6->ip6_hlim;
            outer->ip6.dscp_ecn =
                ntohl(get_16aligned_be32(&ip6->ip6_flow)) >> 20;
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
doca_hash_pipe_init(struct netdev *netdev,
                    unsigned int queue_id,
                    struct doca_hash_pipe_ctx *hash_pipe_ctx,
                    struct doca_flow_pipe *next_pipe,
                    enum hash_pipe_type type,
                    uint32_t group_id)
{
    uint32_t reg_offset = reg_fields[REG_FIELD_DP_HASH].offset;
    struct doca_flow_match hash_matches[NUM_HASH_PIPE_TYPE] = {
        [HASH_TYPE_IPV4_UDP] = {
            .outer.l3_type = DOCA_FLOW_L3_TYPE_IP4,
            .outer.ip4.src_ip = UINT32_MAX,
            .outer.ip4.dst_ip = UINT32_MAX,
            .outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP,
            .outer.udp.l4_port.src_port = UINT16_MAX,
            .outer.udp.l4_port.dst_port = UINT16_MAX,
        },
        [HASH_TYPE_IPV4_TCP] = {
            .outer.l3_type = DOCA_FLOW_L3_TYPE_IP4,
            .outer.ip4.src_ip = UINT32_MAX,
            .outer.ip4.dst_ip = UINT32_MAX,
            .outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP,
            .outer.tcp.l4_port.src_port = UINT16_MAX,
            .outer.tcp.l4_port.dst_port = UINT16_MAX,
        },
        [HASH_TYPE_IPV4_L3] = {
            .outer.l3_type = DOCA_FLOW_L3_TYPE_IP4,
            .outer.ip4.src_ip = UINT32_MAX,
            .outer.ip4.dst_ip = UINT32_MAX,
        },
    };
    uint32_t reg_mask = reg_fields[REG_FIELD_DP_HASH].mask;
    struct doca_flow_actions actions, *actions_arr[1];
    struct doca_flow_action_descs *descs_arr[1];
    struct doca_flow_pipe_entry **pentry;
    struct doca_flow_action_descs descs;
    struct doca_flow_action_desc desc;
    struct doca_eswitch_ctx *esw_ctx;
    struct doca_flow_fwd fwd, miss;
    struct doca_flow_pipe_cfg cfg;
    struct doca_flow_pipe **ppipe;
    char pipe_name[50];
    int ret;

    esw_ctx = doca_eswitch_ctx_get(netdev);

    ppipe = &hash_pipe_ctx->hashes[type].pipe;
    pentry = &hash_pipe_ctx->hashes[type].entry;

    snprintf(pipe_name, sizeof pipe_name, "OVS_HASH_PIPE_%"PRIu32"_type_%u",
             group_id, type);

    memset(&cfg, 0, sizeof cfg);
    memset(&fwd, 0, sizeof(fwd));
    memset(&miss, 0, sizeof(miss));
    memset(&descs, 0, sizeof(descs));
    memset(&actions, 0, sizeof(actions));
    memset(&desc, 0, sizeof desc);

    cfg.attr.name = pipe_name;
    cfg.attr.type = DOCA_FLOW_PIPE_HASH;
    cfg.port = esw_ctx->esw_port;
    cfg.match_mask = &hash_matches[type];
    cfg.attr.nb_flows = 1;
    descs_arr[0] = &descs;
    cfg.action_descs = descs_arr;
    descs.desc_array = &desc;
    descs.nb_action_desc = 1;
    cfg.actions = actions_arr;
    cfg.attr.nb_actions = 1;
    actions_arr[0] = &actions;

    desc.type = DOCA_FLOW_ACTION_COPY;
    desc.copy.src.field_string = "meta.hash";
    desc.copy.src.bit_offset = 0;
    desc.copy.dst.field_string = "meta.data";
    desc.copy.dst.bit_offset = reg_offset;
    desc.copy.width = ffs(~reg_mask) - 1;

    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = next_pipe;
    miss.type = DOCA_FLOW_FWD_DROP;

    ret = doca_flow_pipe_create(&cfg, &fwd, &miss, ppipe);
    if (ret) {
        VLOG_ERR("Failed to create hash pipe: %d (%s)", ret,
                 doca_get_error_string(ret));
        return ret;
    }

    ret = doca_flow_pipe_hash_add_entry(queue_id, *ppipe, 0, NULL, NULL, NULL,
                                        DOCA_FLOW_NO_WAIT, NULL, pentry);
    if (ret) {
        VLOG_ERR("Failed to create hash pipe entry. Error: %d (%s)", ret,
                 doca_get_error_string(ret));
        return ret;
    }
    dpdk_offload_counter_inc(netdev);

    ret = doca_flow_entries_process(cfg.port, queue_id,
                                    ENTRY_PROCESS_TIMEOUT_MS, 0);
    if (ret) {
        VLOG_ERR("Failed to process hash pipe entry. Error: %d (%s)", ret,
                 doca_get_error_string(ret));
        return ret;
    }

    return 0;
}

static struct doca_hash_pipe_ctx *
doca_hash_pipe_ctx_init(struct doca_flow_pipe *next_pipe,
                        struct netdev *netdev,
                        uint32_t group_id)
{
    unsigned int queue_id = netdev_offload_thread_id();
    struct doca_hash_pipe_ctx *hash_pipe_ctx;
    struct doca_flow_pipe_entry **pentry;
    struct doca_eswitch_ctx *esw_ctx;
    struct doca_flow_pipe_cfg cfg;
    struct doca_flow_match spec;
    struct doca_flow_match mask;
    struct doca_flow_fwd miss;
    struct doca_flow_fwd fwd;
    char pipe_name[50];
    doca_error_t err;
    int type;

    esw_ctx = doca_eswitch_ctx_get(netdev);
    if (esw_ctx == NULL) {
        return NULL;
    }

    hash_pipe_ctx = xzalloc(sizeof *hash_pipe_ctx);
    hash_pipe_ctx->netdev = netdev;
    for (type = 0; type < NUM_HASH_PIPE_TYPE; type++) {
        int ret;

        ret = doca_hash_pipe_init(netdev, queue_id, hash_pipe_ctx, next_pipe,
                                  type, group_id);
        if (ret) {
            VLOG_ERR("%s: Failed to create hash pipe ctx",
                     netdev_get_name(netdev));
            goto err;
        }
    }

    /* Classifier pipe. */
    snprintf(pipe_name, sizeof pipe_name, "OVS_HASH_CLASSIFIER_PIPE_%" PRIu32,
             group_id);

    memset(&cfg, 0, sizeof cfg);
    memset(&mask, 0, sizeof mask);
    memset(&fwd, 0, sizeof fwd);
    memset(&miss, 0, sizeof miss);

    cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
    cfg.port = esw_ctx->esw_port;
    cfg.attr.nb_flows = 2;
    cfg.match = &mask;
    cfg.match_mask = &mask;

    mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    mask.outer.ip4.next_proto = 0xFF;

    fwd.type = DOCA_FLOW_FWD_PIPE;
    miss.type = DOCA_FLOW_FWD_PIPE;
    miss.next_pipe = hash_pipe_ctx->hashes[HASH_TYPE_IPV4_L3].pipe;

    err = doca_flow_pipe_create(&cfg, &fwd, &miss, &hash_pipe_ctx->classifier);
    if (err) {
        VLOG_ERR("%s: Failed to create ctl pipe: %d (%s)",
                 netdev_get_name(netdev), err, doca_get_error_string(err));
        goto err;
    }

    /* TCP/UDP entries. */
    memset(&spec, 0, sizeof spec);
    spec.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;

    spec.outer.ip4.next_proto = IPPROTO_UDP;
    pentry = &hash_pipe_ctx->tcpudp[HASH_TP_UDP];
    fwd.next_pipe = hash_pipe_ctx->hashes[HASH_TYPE_IPV4_UDP].pipe;
    err = doca_flow_pipe_add_entry(queue_id, hash_pipe_ctx->classifier, &spec,
                                   NULL, NULL, &fwd, DOCA_FLOW_NO_WAIT, NULL,
                                   pentry);
    if (err) {
        VLOG_ERR("%s: Failed to create UDP classifier entry: %d (%s)",
                 netdev_get_name(netdev), err, doca_get_error_string(err));
        goto err;
    }
    dpdk_offload_counter_inc(netdev);

    spec.outer.ip4.next_proto = IPPROTO_TCP;
    pentry = &hash_pipe_ctx->tcpudp[HASH_TP_TCP];
    fwd.next_pipe = hash_pipe_ctx->hashes[HASH_TYPE_IPV4_TCP].pipe;
    err = doca_flow_pipe_add_entry(queue_id, hash_pipe_ctx->classifier, &spec,
                                   NULL, NULL, &fwd, DOCA_FLOW_NO_WAIT, NULL,
                                   pentry);
    if (err) {
        VLOG_ERR("%s: Failed to create TCP classifier entry: %d (%s)",
                 netdev_get_name(netdev), err, doca_get_error_string(err));
        goto err;
    }
    dpdk_offload_counter_inc(netdev);

    err = doca_flow_entries_process(esw_ctx->esw_port, queue_id,
                                    ENTRY_PROCESS_TIMEOUT_MS, 0);
    if (err) {
        VLOG_ERR("%s: Failed to poll classifier completion: queue %u. "
                 "Error: %d (%s)", netdev_get_name(netdev), queue_id, err,
                 doca_get_error_string(err));
        goto err;
    }

    return hash_pipe_ctx;
err:
    doca_hash_pipe_ctx_uninit(hash_pipe_ctx);
    return NULL;
}

static struct doca_flow_pipe *
get_ctl_pipe_root(struct doca_ctl_pipe_ctx *next_pipe_ctx,
                  struct doca_flow_match *spec,
                  struct doca_flow_actions *dacts,
                  bool has_dp_hash)
{
    if (!has_dp_hash) {
        return next_pipe_ctx->pipe;
    }

    if (dacts->has_encap) {
        if (dacts->encap.outer.l3_type != DOCA_FLOW_L3_TYPE_IP4) {
            return NULL;
        }
        if (dacts->encap.tun.type == DOCA_FLOW_TUN_VXLAN ||
            dacts->encap.tun.type == DOCA_FLOW_TUN_GENEVE) {
            return next_pipe_ctx->hash_pipe_ctx->hashes[HASH_TYPE_IPV4_UDP].pipe;
        }
        return next_pipe_ctx->hash_pipe_ctx->hashes[HASH_TYPE_IPV4_L3].pipe;
    }

    if (spec->outer.l3_type != DOCA_FLOW_L3_TYPE_IP4) {
        return NULL;
    }

    if (spec->outer.l4_type_ext == DOCA_FLOW_L4_TYPE_EXT_TCP) {
        return next_pipe_ctx->hash_pipe_ctx->hashes[HASH_TYPE_IPV4_TCP].pipe;
    } else if (spec->outer.l4_type_ext == DOCA_FLOW_L4_TYPE_EXT_UDP) {
        return next_pipe_ctx->hash_pipe_ctx->hashes[HASH_TYPE_IPV4_UDP].pipe;
    }
    return next_pipe_ctx->hash_pipe_ctx->classifier;
}

static int
doca_translate_actions(struct netdev *netdev,
                       struct doca_flow_match *spec,
                       const struct rte_flow_action *actions,
                       struct doca_flow_actions *dacts,
                       struct doca_flow_actions *dacts_masks,
                       struct doca_flow_fwd *fwd,
                       struct doca_flow_monitor *monitor,
                       struct doca_flow_handle_resources *flow_res,
                       uint32_t *flow_id)
{
    struct doca_flow_header_format *outer_masks = &dacts_masks->outer;
    struct doca_flow_header_format *outer = &dacts->outer;
    struct doca_eswitch_ctx *esw_ctx;
    bool vlan_act_push = false;
    bool has_dp_hash = false;

    esw_ctx = doca_eswitch_ctx_get(netdev);
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
            if (has_dp_hash) {
                next_pipe_ctx->hash_pipe_ctx =
                    doca_hash_pipe_ctx_init(next_pipe_ctx->pipe, netdev,
                                            jump->group);
                if (next_pipe_ctx->hash_pipe_ctx == NULL) {
                    return -1;
                }
            }

            fwd->type = DOCA_FLOW_FWD_PIPE;
            fwd->next_pipe = get_ctl_pipe_root(next_pipe_ctx, spec, dacts,
                                               has_dp_hash);
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
        } else if (act_type == OVS_RTE_FLOW_ACTION_TYPE(HASH)) {
            has_dp_hash = true;
        } else if (act_type == RTE_FLOW_ACTION_TYPE_METER) {
            uint32_t reg_offset = reg_fields[REG_FIELD_FLOW_INFO].offset;
            uint32_t reg_mask = reg_fields[REG_FIELD_FLOW_INFO].mask;
            const struct meter_data *mtr_data = actions->conf;

            dacts->meta.pkt_meta |= (mtr_data->flow_id & reg_mask) << reg_offset;
            dacts_masks->meta.pkt_meta |= reg_mask << reg_offset;

            /* id is determine by both the upper layer id, and the esw_id. */
            monitor->shared_meter_id =
                esw_ctx->esw_id * OVS_DOCA_MAX_METERS_PER_ESW +
                mtr_data->conf.mtr_id;
            *flow_id = mtr_data->flow_id;
        } else {
            return -1;
        }
    }

    return 0;
}

static void
dpdk_offload_doca_upkeep_queue(struct netdev *netdev, bool quiescing,
                               unsigned int qid)
{
    struct doca_eswitch_ctx *esw_ctx;
    unsigned int n_entries;
    doca_error_t err;

    if (netdev == NULL) {
        return;
    }

    esw_ctx = doca_eswitch_ctx_get(netdev);
    /* vports won't take an esw_ctx ref. */
    if (esw_ctx == NULL) {
        return;
    }

    n_entries = esw_ctx->async_state[qid].n_entries;
    if (n_entries == 0 || (!quiescing && n_entries < OVS_DOCA_QUEUE_DEPTH)) {
        /* Early bail-out if the queue has no entry or if
         * it is not full and we are not preparing for a long sleep. */
        return;
    }

    /* Use 'max_processed_entries' == 0 to always attempt processing
     * the full length of the queue. */
    err = doca_flow_entries_process(esw_ctx->esw_port, qid,
                                    ENTRY_PROCESS_TIMEOUT_MS, 0);
    if (err) {
        VLOG_WARN_RL(&rl, "%s: Failed to process entries in queue %u. "
                     "Error: %d (%s)", netdev_get_name(netdev), qid,
                     err, doca_get_error_string(err));
    }
}

static void
dpdk_offload_doca_upkeep(struct netdev *netdev, bool quiescing)
{
    dpdk_offload_doca_upkeep_queue(netdev, quiescing,
                                   netdev_offload_thread_id());
}

void
ovs_doca_entry_process_cb(struct doca_flow_pipe_entry *entry, uint16_t qid,
                          enum doca_flow_entry_status status,
                          enum doca_flow_entry_op op, void *aux)
{
    struct doca_eswitch_ctx *esw;
    struct doca_async_entry *dae;
    struct doca_flow_handle *dfh;
    struct netdev *netdev;

    if (aux == NULL) {
        /* 'aux' is NULL if the operation is synchronous. This is the
         * case for all control pipe changes, as well as CT if the user
         * requested it.
         * In this case, everything is handled in the calling function,
         * nothing to do. */
        return;
    }

    switch (op) {
    case DOCA_FLOW_ENTRY_OP_ADD:
        dae = aux;
        if (dae->doh == NULL) {
            /* Previous queue completion might have finished
             * before completing the whole queue due to timeout.
             * In that case, some 'dae' might have already been
             * processed and have their handle set to NULL.
             * Skip them. */
            return;
        }
        dfh = &dae->doh->dfh;
        netdev = dae->netdev;
        esw = doca_eswitch_ctx_from_async_entry(dae, qid);
        if (status == DOCA_FLOW_ENTRY_STATUS_SUCCESS) {
            dpdk_offload_counter_inc(netdev);
            dfh->flow = entry;
        } else if (status == DOCA_FLOW_ENTRY_STATUS_ERROR) {
            /* dfh->flow remains NULL. */
            COVERAGE_INC(doca_async_add_failed);
            VLOG_WARN_RL(&rl, "%s: Insertion failed for handle %p",
                         netdev_get_name(netdev), dfh);
        }
        dae->netdev = NULL;
        dae->doh = NULL;
        esw->async_state[qid].n_entries--;
        break;
    case DOCA_FLOW_ENTRY_OP_DEL:
        /* Deletion is always synchronous. */
        break;
    case DOCA_FLOW_ENTRY_OP_AGED:
    case DOCA_FLOW_ENTRY_OP_UPD:
        /* Not used by this implementation. */
        OVS_NOT_REACHED();
        break;
    }
}

static struct doca_async_entry *
doca_async_entry_find(struct netdev *netdev,
                      struct doca_eswitch_ctx *esw,
                      unsigned int qid)
{
    struct doca_async_entry *dae = NULL;
    unsigned int *n_entries;

    n_entries = &esw->async_state[qid].n_entries;

    /* If the queue is currently full, do not try to
     * take a pointer to an entry. Trigger the linear scan,
     * and if really full, process it before attempting again. */
    if ((*n_entries) != OVS_DOCA_QUEUE_DEPTH) {
        dae = &esw->async_state[qid].entries[(*n_entries)];
    }

    /* The queue is not completed in any guaranteed order, meaning
     * that n_entries might not always point to a 'free' entry.
     * When it happens, linearly scan for an available descriptor. */
    if (dae == NULL || dae->doh != NULL) {
        unsigned int retry_count = 0;

        dae = NULL;
        while (dae == NULL) {
            int i;

            if (retry_count++ > 10) {
                COVERAGE_INC(doca_async_queue_blocked);
                return NULL;
            }
            for (i = 0; i < OVS_DOCA_QUEUE_DEPTH; i++) {
                if (esw->async_state[qid].entries[i].doh == NULL) {
                    dae = &esw->async_state[qid].entries[i];
                    break;
                }
            }
            if (i == OVS_DOCA_QUEUE_DEPTH) {
                COVERAGE_INC(doca_async_queue_full);
                if (netdev == NULL) {
                    /* We cannot hope to flush that netdev queue
                     * if it's NULL, report that we didn't find an entry. */
                    return NULL;
                }
                dpdk_offload_doca_upkeep_queue(netdev, true, qid);
            }
        }
    }

    (*n_entries)++;
    return dae;
}

static int
create_doca_basic_flow_entry(struct netdev *netdev,
                             unsigned int queue_id,
                             struct doca_flow_pipe *pipe,
                             struct doca_flow_match *spec,
                             struct doca_flow_actions *actions,
                             struct doca_flow_monitor *monitor,
                             struct doca_flow_fwd *fwd,
                             struct dpdk_offload_handle *doh,
                             struct rte_flow_error *error)
{
    enum doca_flow_flags_type doca_flags;
    struct doca_flow_pipe_entry *entry;
    struct doca_eswitch_ctx *esw_ctx;
    struct doca_async_entry *dae;
    doca_error_t err;

    doca_flags = DOCA_FLOW_NO_WAIT;
    dae = NULL;

    esw_ctx = doca_eswitch_ctx_get(netdev);
    if (ovs_doca_async) {
        dae = doca_async_entry_find(netdev, esw_ctx, queue_id);
        if (dae != NULL) {
            unsigned int n_entries;

            /* No reference is taken on the netdev.
             * When a netdev is removed from the datapath, a blocking
             * 'flush' command is issued. This command should take care
             * of emptying the offload queue, leaving no dangling netdev
             * reference before removing that specific port.
             */
            dae->netdev = netdev;
            dae->doh = doh;
            n_entries = esw_ctx->async_state[queue_id].n_entries;
            if (n_entries < OVS_DOCA_QUEUE_DEPTH) {
                doca_flags = DOCA_FLOW_WAIT_FOR_BATCH;
            }
        }
    }

    err = doca_flow_pipe_add_entry(queue_id, pipe, spec, actions, monitor, fwd,
                                   doca_flags, dae, &entry);
    if (err) {
        VLOG_WARN_RL(&rl, "%s: Failed to create basic pipe entry. Error: %d (%s)",
                     netdev_get_name(netdev), err, doca_get_error_string(err));
        error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
        error->message = doca_get_error_string(err);
        return -1;
    }

    if (dae == NULL) {
        err = doca_flow_entries_process(esw_ctx->esw_port, queue_id,
                                        ENTRY_PROCESS_TIMEOUT_MS, 0);
        if (err) {
            VLOG_WARN_RL(&rl, "%s: Failed to poll completion of pipe queue %u."
                         " Error: %d (%s)", netdev_get_name(netdev), queue_id,
                         err, doca_get_error_string(err));
            error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
            error->message = doca_get_error_string(err);
            return -1;
        }
        dpdk_offload_counter_inc(netdev);
        doh->dfh.flow = entry;
    }

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

    dpdk_offload_counter_inc(netdev);

    return entry;
}

static struct doca_flow_pipe *
doca_get_ct_pipe(struct doca_eswitch_ctx *ctx,
                 struct doca_flow_match *spec)
{
    enum ct_nw_type nw_type;
    enum ct_tp_type tp_type;

    if (ctx == NULL) {
        return NULL;
    }

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

    return ctx->ct_pipes[nw_type][tp_type].pipe;
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

    memcpy(&hndl->flow_res, flow_res, sizeof *flow_res);
    hndl->flow_res.self_pipe_ctx = pipe_ctx;
    hndl->flow_res.group = group;

    return hndl;

err_insert:
    doca_ctl_pipe_ctx_unref(pipe_ctx);
err_pipe:
    return NULL;
}

static struct doca_flow_pipe_entry *
add_doca_post_meter_green_entry(struct netdev *netdev,
                                unsigned int queue_id,
                                uint32_t flow_id,
                                struct doca_flow_fwd *fwd,
                                struct rte_flow_error *error)
{
    uint32_t flow_info_reg_offset = reg_fields[REG_FIELD_FLOW_INFO].offset;
    uint32_t flow_info_reg_mask = reg_fields[REG_FIELD_FLOW_INFO].mask;

    struct doca_ctl_pipe_ctx *post_meter_pipe_ctx;
    struct doca_flow_pipe_entry *entry;
    struct doca_flow_match green_match;
    struct doca_flow_match green_mask;
    struct doca_eswitch_ctx *esw_ctx;

    esw_ctx = doca_eswitch_ctx_get(netdev);
    post_meter_pipe_ctx = esw_ctx->post_meter_pipe_ctx;

    memset(&green_match, 0, sizeof(green_match));
    memset(&green_mask, 0, sizeof(green_mask));

    /* Insert green rule with prio 1, which is lower than the fixed red rule
     * that is added at eswitch init stage with prio 0.
     */
    green_match.meta.pkt_meta |= (flow_id & flow_info_reg_mask) <<
                                 flow_info_reg_offset;
    green_mask.meta.pkt_meta |= flow_info_reg_mask << flow_info_reg_offset;
    entry = create_doca_ctl_flow_entry(netdev, queue_id, post_meter_pipe_ctx,
                                       1, &green_match, &green_mask, NULL,
                                       NULL, NULL, fwd, error);
    if (!entry) {
        VLOG_ERR_RL(&rl, "%s: Failed to create shared meter green rule for flow ID %u",
                    netdev_get_name(netdev), flow_id);
        return NULL;
    }

    /* replace original fwd with the internal meter pipe */
    memset(fwd, 0, sizeof *fwd);
    fwd->type = DOCA_FLOW_FWD_PIPE;
    fwd->next_pipe = post_meter_pipe_ctx->pipe;

    return entry;
}

static int
dpdk_offload_doca_create(struct netdev *netdev,
                         const struct rte_flow_attr *attr,
                         struct rte_flow_item *items,
                         struct rte_flow_action *actions,
                         struct dpdk_offload_handle *doh,
                         struct rte_flow_error *error)
{
    struct doca_eswitch_ctx *esw_ctx = doca_eswitch_ctx_get(netdev);
    unsigned int tid = netdev_offload_thread_id();
    struct doca_flow_actions dacts, dacts_masks;
    struct doca_flow_handle_resources flow_res;
    struct doca_flow_pipe_entry *meter_entry;
    struct doca_flow_monitor monitor;
    struct doca_flow_handle *hndl;
    struct doca_flow_match mask;
    struct doca_flow_match spec;
    unsigned int queue_id = tid;
    struct doca_flow_fwd fwd;
    uint32_t prio, flow_id;

    /* If it's a post ct rule, check for eswitch ct offload support */
    if (attr->group == POSTCT_TABLE_ID && !esw_ctx->shared_cnt_id_pool) {
        return -1;
    }

    memset(&dacts_masks, 0, sizeof dacts_masks);
    memset(&flow_res, 0, sizeof flow_res);
    memset(&monitor, 0, sizeof monitor);
    memset(&dacts, 0, sizeof dacts);
    memset(&mask, 0, sizeof mask);
    memset(&spec, 0, sizeof spec);
    memset(&fwd, 0, sizeof fwd);

    if (doca_translate_items(netdev, attr, items, &spec, &mask)) {
        error->type = RTE_FLOW_ERROR_TYPE_ITEM;
        error->message = "Could not create items";
        doh->rte_flow = NULL;
        return -1;
    }

    /* parse actions */
    if (doca_translate_actions(netdev, &spec, actions, &dacts, &dacts_masks,
                               &fwd, &monitor, &flow_res, &flow_id)) {
        error->type = RTE_FLOW_ERROR_TYPE_ACTION;
        error->message = "Could not create actions";
        doh->rte_flow = NULL;
        return -1;
    }

    if (monitor.shared_meter_id) {
        meter_entry = add_doca_post_meter_green_entry(netdev, queue_id,
                                                      flow_id, &fwd, error);
        if (!meter_entry) {
            if (error) {
                error->type = RTE_FLOW_ERROR_TYPE_ACTION;
                error->message = "Could not create post meter rule";
            }
            return -1;
        }
        flow_res.post_meter_entry = meter_entry;
    }

    prio = flow_res.next_group == MISS_TABLE_ID;
    hndl = create_doca_flow_handle(netdev, queue_id, prio, attr->group, &spec,
                                   &mask, &dacts, &dacts_masks, &monitor, &fwd,
                                   &flow_res, doh, error);
    if (!hndl) {
        /* change to free doca flow resources function */
        doca_ctl_pipe_ctx_unref(flow_res.next_pipe_ctx);
        if (monitor.shared_meter_id) {
            doca_flow_pipe_rm_entry(queue_id, DOCA_FLOW_NO_WAIT, meter_entry);
            dpdk_offload_counter_dec(netdev);
            flow_res.post_meter_entry = NULL;
        }
        return -1;
    }

    return 0;
}

static int
destroy_dpdk_offload_handle(struct netdev *netdev,
                            struct dpdk_offload_handle *doh,
                            unsigned int queue_id,
                            struct rte_flow_error *error)
{
    int upkeep_retries = 10;
    doca_error_t err;

    while (doh->dfh.flow == NULL && upkeep_retries-- > 0) {
        /* Force polling completions, this handle
         * was not yet completed. */
        dpdk_offload_doca_upkeep_queue(netdev, true, queue_id);
    }

    /* It should have been completed by now, or something is wrong. */
    if (doh->dfh.flow == NULL) {
        if (error) {
            error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
            error->message = "Failed to delete entry, "
                             "async insertion never completed";
        }
        return -1;
    }

    /* Deletion is always synchronous.
     *
     * If async deletion is implemented, aux-table uninit calls deleting
     * entries will use the offload queues in conflict with offload threads
     * polling them during upkeep. It should result in a crash or
     * in a lockup of the queues. */
    err = doca_flow_pipe_rm_entry(queue_id, DOCA_FLOW_NO_WAIT, doh->dfh.flow);
    if (err) {
        if (error) {
            error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
            error->message = doca_get_error_string(err);
        }
        return -1;
    }

    if (doh->dfh.flow_res.post_meter_entry) {
        err = doca_flow_pipe_rm_entry(queue_id, DOCA_FLOW_NO_WAIT,
                                      doh->dfh.flow_res.post_meter_entry);
        if (err) {
            if (error) {
                error->type = RTE_FLOW_ERROR_TYPE_HANDLE;
                error->message = doca_get_error_string(err);
            }
            return -1;
        }
        dpdk_offload_counter_dec(netdev);
        doh->dfh.flow_res.post_meter_entry = NULL;
    }

    /* Netdev can only be NULL during aux tables uninit. */
    if (netdev) {
        dpdk_offload_counter_dec(netdev);
    }

    doca_ctl_pipe_ctx_unref(doh->dfh.flow_res.next_pipe_ctx);
    doca_ctl_pipe_ctx_unref(doh->dfh.flow_res.self_pipe_ctx);

    return 0;
}

static int
dpdk_offload_doca_destroy(struct netdev *netdev,
                          struct dpdk_offload_handle *doh,
                          struct rte_flow_error *error,
                          bool esw_port_id OVS_UNUSED)
{
    unsigned int queue_id = netdev_offload_thread_id();

    return destroy_dpdk_offload_handle(netdev, doh, queue_id, error);
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

    if (doca_flow == NULL) {
        /* The async entry has not yet been completed,
         * it cannot have done anything yet. */
        return 0;
    }

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

static int
dpdk_offload_doca_shared_create(struct netdev *netdev,
                                struct indirect_ctx *ctx,
                                const struct rte_flow_action *action,
                                struct rte_flow_error *error)
{
    struct doca_eswitch_ctx *esw_ctx = doca_eswitch_ctx_get(netdev);
    unsigned int tid = netdev_offload_thread_id();
    uint32_t id;

    if (!esw_ctx->shared_cnt_id_pool) {
        return -1;
    }

    if (action->type != RTE_FLOW_ACTION_TYPE_COUNT) {
        return -1;
    }

    if (!id_fpool_new_id(esw_ctx->shared_cnt_id_pool, tid, &id)) {
        VLOG_ERR("Failed to alloc a new shared counter id");
        error->type = RTE_FLOW_ERROR_TYPE_UNSPECIFIED;
        error->message = "Failed to alloc a new shared counter id";
        return -1;
    }

    ctx->res_id = id;
    ctx->act_type = action->type;

    return 0;
}

static int
dpdk_offload_doca_shared_destroy(struct indirect_ctx *ctx,
                                 struct rte_flow_error *error OVS_UNUSED)
{
    struct doca_eswitch_ctx *esw_ctx = doca_eswitch_ctx_get(ctx->netdev);
    unsigned int tid = netdev_offload_thread_id();

    id_fpool_free_id(esw_ctx->shared_cnt_id_pool, tid, ctx->res_id);

    return 0;
}

static int
dpdk_offload_doca_shared_query(struct indirect_ctx *ctx,
                               void *data,
                               struct rte_flow_error *error)
{
    struct doca_flow_shared_resource_result query_results;
    struct rte_flow_query_count *query;
    struct doca_flow_query *stats;
    doca_error_t ret;
    uint32_t cnt_id;

    /* Only shared counter supported at the moment */
    if (ctx->act_type != RTE_FLOW_ACTION_TYPE_COUNT) {
        return -1;
    }

    query = (struct rte_flow_query_count *) data;
    memset(query, 0, sizeof *query);
    memset(&query_results, 0, sizeof query_results);

    cnt_id = ctx->res_id;
    ret = doca_flow_shared_resources_query(DOCA_FLOW_SHARED_RESOURCE_COUNT,
                                           &cnt_id, &query_results, 1);
    if (ret != DOCA_SUCCESS) {
        VLOG_ERR("Failed to query shared counter id 0x%.8x: %s",
                 ctx->res_id, doca_get_error_string(ret));
        error->type = RTE_FLOW_ERROR_TYPE_UNSPECIFIED;
        error->message = doca_get_error_string(ret);
        return -1;
    }

    stats = &query_results.counter;
    query->hits = stats->total_pkts;
    query->bytes = stats->total_bytes;

    return 0;
}

static void
dpdk_offload_doca_get_pkt_recover_info(struct dp_packet *p,
                                       struct dpdk_offload_recovery_info *info)
{
    memset(info, 0, sizeof *info);
    if (dpdk_offload_get_reg_field(p, REG_FIELD_FLOW_INFO,
                                   &info->flow_miss_id)) {
        dp_packet_set_flow_mark(p, info->flow_miss_id);
        dpdk_offload_get_reg_field(p, REG_FIELD_CT_CTX, &info->ct_miss_id);
        dpdk_offload_get_reg_field(p, REG_FIELD_DP_HASH, &info->dp_hash);
    }
}

static int
dpdk_offload_doca_netdev_data_destroy(void *data)
{
    struct netdev *netdev = data;

    if (!netdev_dpdk_is_ethdev(netdev)) {
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
doca_fixed_rule_uninit(struct netdev *netdev, struct fixed_rule *fr)
{
    if (!fr->doh.dfh.flow) {
        return;
    }

    destroy_dpdk_offload_handle(netdev, &fr->doh, AUX_QUEUE, NULL);
    fr->doh.dfh.flow = NULL;
}

static void
doca_ct_zones_uninit(struct netdev *netdev, struct doca_eswitch_ctx *ctx)
{
    struct fixed_rule *fr;
    uint32_t zone_id;
    int nat, i;

    if (netdev_is_zone_tables_disabled()) {
        VLOG_ERR("Disabling ct zones is not supported with doca");
        return;
    }

    for (nat = 0; nat < 2; nat++) {
        for (i = 0; i < NUM_ZONE_FLOWS; i++) {
            for (zone_id = MIN_ZONE_ID; zone_id <= MAX_ZONE_ID; zone_id++) {
                fr = &ctx->zone_flows[nat][i][zone_id];
                doca_fixed_rule_uninit(netdev, fr);
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

    memset(&flow_res, 0, sizeof flow_res);
    memset(&mask, 0, sizeof mask);
    memset(&spec, 0, sizeof spec);
    memset(&fwd, 0, sizeof fwd);

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

    memset(&dacts_masks, 0, sizeof dacts_masks);
    memset(&flow_res, 0, sizeof flow_res);
    memset(&dacts, 0, sizeof dacts);
    memset(&fwd, 0, sizeof fwd);
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
    fwd.next_pipe = doca_get_ct_pipe(ctx, &spec);
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
        VLOG_ERR("Disabling ct zones is not supported with doca");
        return -1;
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
    doca_ct_zones_uninit(netdev, ctx);
    return -1;
}

static void
doca_ct_pipe_destroy(struct doca_eswitch_ctx *ctx,
                     enum ct_nw_type nw_type, enum ct_tp_type tp_type)
{
    struct doca_basic_pipe_ctx *pipe_ctx;

    pipe_ctx = &ctx->ct_pipes[nw_type][tp_type];

    doca_ctl_pipe_ctx_unref(pipe_ctx->fwd_pipe_ctx);
    pipe_ctx->fwd_pipe_ctx = NULL;

    doca_ctl_pipe_ctx_unref(pipe_ctx->miss_pipe_ctx);
    pipe_ctx->miss_pipe_ctx = NULL;

    doca_flow_pipe_destroy(pipe_ctx->pipe);
    pipe_ctx->pipe = NULL;
}

static void
doca_ct_pipes_destroy(struct doca_eswitch_ctx *ctx)
{
    int i, j;

    for (i = 0; i < NUM_CT_NW; i++) {
        for (j = 0; j < NUM_CT_TP; j++) {
            doca_ct_pipe_destroy(ctx, i, j);
        }
    }
}

static void
doca_basic_pipe_name(struct ds *s, struct netdev *netdev,
                     enum ct_nw_type nw_type,
                     enum ct_tp_type tp_type)
{
    ds_put_format(s, "OVS_BASIC_CT_PIPE_%d",
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

static int
doca_ct_pipe_init(struct netdev *netdev, struct doca_eswitch_ctx *ctx,
                  enum ct_nw_type nw_type, enum ct_tp_type tp_type)
{
    struct doca_ctl_pipe_ctx *miss_pipe_ctx = NULL;
    struct doca_ctl_pipe_ctx *fwd_pipe_ctx = NULL;
    struct doca_flow_actions *actions_masks_list;
    struct doca_flow_header_format *outer_masks;
    struct doca_flow_actions actions_masks;
    struct doca_flow_header_format *outer;
    struct doca_flow_actions *actions_list;
    struct doca_basic_pipe_ctx *pipe_ctx;
    struct doca_flow_match match_mask;
    struct doca_flow_actions actions;
    struct doca_flow_pipe *miss_pipe;
    struct doca_flow_port *doca_port;
    struct doca_flow_monitor monitor;
    enum dpdk_reg_id set_tags[] = {
        REG_FIELD_CT_STATE,
        REG_FIELD_CT_MARK,
        REG_FIELD_CT_LABEL_ID,
    };
    struct doca_flow_pipe_cfg cfg;
    struct doca_flow_fwd miss;
    struct doca_flow_fwd fwd;
    struct reg_field *ct_reg;
    struct ds pipe_name;
    uint32_t reg_mask;
    int ret, i;

    pipe_ctx = &ctx->ct_pipes[nw_type][tp_type];

    /* Do not re-init a pipe if already done. */
    if (pipe_ctx->pipe != NULL) {
        return 0;
    }

    memset(&cfg, 0, sizeof cfg);
    memset(&fwd, 0, sizeof fwd);
    memset(&miss, 0, sizeof miss);
    memset(&actions, 0, sizeof actions);
    memset(&actions_masks, 0, sizeof actions_masks);
    memset(&monitor, 0, sizeof monitor);

    ds_init(&pipe_name);
    doca_basic_pipe_name(&pipe_name, netdev, nw_type, tp_type);

    actions_list = &actions;
    actions_masks_list = &actions_masks;

    outer = &actions.outer;
    outer_masks = &actions_masks.outer;

    /* Write the CT-NAT action template. */
    if (nw_type == CT_NW_IP4) {
        outer->l3_type = DOCA_FLOW_L3_TYPE_IP4;
        outer->ip4.src_ip = UINT32_MAX;
        outer->ip4.dst_ip = UINT32_MAX;
        if (tp_type == CT_TP_UDP) {
            outer->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
            outer->udp.l4_port.src_port = UINT16_MAX;
            outer->udp.l4_port.dst_port = UINT16_MAX;
        } else {
            outer->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
            outer->tcp.l4_port.src_port = UINT16_MAX;
            outer->tcp.l4_port.dst_port = UINT16_MAX;
        }
    } else {
        OVS_NOT_REACHED();
    }

    memcpy(outer_masks, outer, sizeof *outer_masks);

    ct_reg = &reg_fields[REG_FIELD_CT_CTX];
    reg_mask = ct_reg->mask << ct_reg->offset;
    /* Use 0xFFFs values to set pkt_meta in the action upon pipe create
     * and have the mask in the actions_mask
     */
    actions.meta.pkt_meta = UINT32_MAX;
    actions_masks.meta.pkt_meta = ct_reg->mask << ct_reg->offset;
    for (i = 0; i < ARRAY_SIZE(set_tags); i++) {
        ct_reg = &reg_fields[set_tags[i]];
        reg_mask = ct_reg->mask << ct_reg->offset;
        /* Use 0xFFFs values to set meta.u32 in the action upon pipe create
         * and have the mask in the actions_mask
         */
        actions.meta.u32[ct_reg->index] = UINT32_MAX;
        actions_masks.meta.u32[ct_reg->index] |= reg_mask;
    }

    /* Finalize the match templates. */
    ct_reg = &reg_fields[REG_FIELD_CT_ZONE];
    reg_mask = ct_reg->mask << ct_reg->offset;
    ct_matches[CT_NW_IP4][CT_TP_UDP].meta.u32[ct_reg->index] = reg_mask;
    ct_matches[CT_NW_IP4][CT_TP_TCP].meta.u32[ct_reg->index] = reg_mask;
    /* The mask is identical to the match itself. */
    match_mask = ct_matches[nw_type][tp_type];
    doca_port = netdev_dpdk_doca_port_get(netdev);

    monitor.shared_counter_id = UINT32_MAX;

    cfg.attr.name = ds_cstr(&pipe_name);
    cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
    cfg.attr.is_root = false;
    cfg.attr.nb_actions = 1,
    cfg.attr.nb_flows = OVS_DOCA_MAX_CT_RULES;
    cfg.port = doca_flow_port_switch_get(doca_port);
    cfg.match = &ct_matches[nw_type][tp_type];
    cfg.match_mask = &match_mask;
    cfg.actions = &actions_list;
    cfg.actions_masks = &actions_masks_list;
    cfg.monitor = &monitor;

    fwd_pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, POSTCT_TABLE_ID);
    if (fwd_pipe_ctx == NULL) {
        VLOG_ERR("%s: Failed to take a reference on post-ct table",
                 netdev_get_name(netdev));
        return -1;
    }
    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = fwd_pipe_ctx->pipe;

    miss_pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, MISS_TABLE_ID);
    if (miss_pipe_ctx == NULL) {
        VLOG_ERR("%s: Failed to take a reference on miss table",
                 netdev_get_name(netdev));
        return -1;
    }
    miss_pipe = miss_pipe_ctx->pipe;
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
    int i, j;

    for (i = 0; i < NUM_CT_NW; i++) {
        for (j = 0; j < NUM_CT_TP; j++) {
            if (doca_ct_pipe_init(netdev, ctx, i, j)) {
                goto error;
            }
        }
    }

    return 0;

error:
    /* Rollback any pipe creation. */
    doca_ct_pipes_destroy(ctx);
    return -1;
}

/* Init the shared counter id map for the first
 * eswitch context that requests it. This is the only
 * eswitch that will support CT offload for now.
 * After DOCA adds proper support this limitation should
 * be lifted and support shared counters for every eswitch
 * will be added.
 */
static void
shared_cnt_id_init(struct doca_eswitch_ctx *ctx)
{
    static struct ovsthread_once init_once = OVSTHREAD_ONCE_INITIALIZER;
    uint32_t base_id;

    if (ovsthread_once_start(&init_once)) {
        esw_id_pool = id_fpool_create(1, 0, OVS_DOCA_MAX_ESW);
        ovsthread_once_done(&init_once);
    }
    if (!esw_id_pool || !id_fpool_new_id(esw_id_pool, 0, &ctx->esw_id)) {
        VLOG_ERR("Failed to alloc a new esw id");
        return;
    }
    base_id = SHARED_CNT_N_IDS * ctx->esw_id;
    ctx->shared_cnt_id_pool = id_fpool_create(netdev_offload_thread_nb(),
                                              base_id, SHARED_CNT_N_IDS);
}

#define SHARED_CNT_IDS_ARR_SZ 5000
BUILD_ASSERT_DECL(OVS_DOCA_MAX_CT_COUNTERS_PER_ESW % SHARED_CNT_IDS_ARR_SZ == 0);

static int
doca_bind_shared_cntrs(struct doca_eswitch_ctx *ctx)
{
    struct doca_flow_shared_resource_cfg cfg =
        { .domain = DOCA_FLOW_PIPE_DOMAIN_DEFAULT };
    uint32_t ids[SHARED_CNT_IDS_ARR_SZ];
    int i, chunk, ret;
    uint32_t base_id;

    base_id = SHARED_CNT_N_IDS * ctx->esw_id;
    for (chunk = 0; chunk < SHARED_CNT_N_IDS;
         chunk += SHARED_CNT_IDS_ARR_SZ) {
        for (i = 0; i < SHARED_CNT_IDS_ARR_SZ; i++) {
            ids[i] = base_id + chunk + i;
            ret = doca_flow_shared_resource_cfg(DOCA_FLOW_SHARED_RESOURCE_COUNT,
                                                ids[i], &cfg);
            if (ret != DOCA_SUCCESS) {
                VLOG_ERR("Failed to config shared counter id %d, err %d - %s",
                         ids[i], ret, doca_get_error_string(ret));
                return -1;
            }
        }
        ret = doca_flow_shared_resources_bind(DOCA_FLOW_SHARED_RESOURCE_COUNT,
                                              ids, SHARED_CNT_IDS_ARR_SZ,
                                              ctx->esw_port);
        if (ret != DOCA_SUCCESS) {
            VLOG_ERR("Shared counters binding failed, ids %d-%d, err %d - %s",
                     ids[0], ids[SHARED_CNT_IDS_ARR_SZ - 1], ret,
                     doca_get_error_string(ret));
            return -1;
        }
    }

    return 0;
}

static int
doca_bind_shared_meters(struct doca_eswitch_ctx *ctx)
{
    struct doca_flow_shared_resource_cfg dummy_cfg = {
        .domain = DOCA_FLOW_PIPE_DOMAIN_DEFAULT,
        .meter_cfg.limit_type = DOCA_FLOW_METER_LIMIT_TYPE_BYTES,
        .meter_cfg.cir = 125000,
        .meter_cfg.cbs = 12500,
    };
    uint32_t ids[OVS_DOCA_MAX_METERS_PER_ESW];
    int i, id, ret;

    /* DOCA allows meter IDs to start from 0, but it's problematic to have a
     * meter with ID 0 because in such case it will be impossible to disable
     * shared meter in doca_flow_monitor struct later, so meter with ID 0 is
     * not configured and not bound to avoid this issue.
     *
     * Total number of shared meters is OVS_DOCA_MAX_METERS_PER_ESW-1 because
     * meter ID 0 is not used.
     */
    for (i = 0, id = 1; i < OVS_DOCA_MAX_METERS_PER_ESW - 1; i++, id++) {
        ids[i] = ctx->esw_id * OVS_DOCA_MAX_METERS_PER_ESW + id;
        /* DOCA will fail to bind a shared meter if it's unconfigured, which is
         * a bug, so a dummy configuration is used as a W/A; actual meter
         * configuration will be set by the user when OVS meter is added with
         * `ovs-ofctl add-meter` command.
         */
        ret = doca_flow_shared_resource_cfg(DOCA_FLOW_SHARED_RESOURCE_METER,
                                            ids[i], &dummy_cfg);
        if (ret != DOCA_SUCCESS) {
            VLOG_ERR("Failed to init shared meter (id %d), err %d - %s",
                    ids[i], ret, doca_get_error_string(ret));
            return -1;
        }
    }

    ret = doca_flow_shared_resources_bind(DOCA_FLOW_SHARED_RESOURCE_METER, ids,
                                          OVS_DOCA_MAX_METERS_PER_ESW - 1,
                                          ctx->esw_port);
    if (ret != DOCA_SUCCESS) {
        VLOG_ERR("Shared meters binding failed, ids %d-%d, err %d - %s",
                 ids[0], ids[OVS_DOCA_MAX_METERS_PER_ESW - 1], ret,
                 doca_get_error_string(ret));
        return -1;
    }

    return 0;
}

static int
doca_create_post_meter_red_rule(struct netdev *netdev, uint32_t group,
                                struct dpdk_offload_handle *doh)
{
    struct doca_flow_handle_resources flow_res;
    struct doca_flow_match red_match;
    struct doca_flow_handle *hndl;
    struct rte_flow_error error;
    struct doca_flow_fwd fwd;

    memset(&flow_res, 0, sizeof flow_res);
    memset(&red_match, 0, sizeof red_match);
    memset(&fwd, 0, sizeof fwd);

    fwd.type = DOCA_FLOW_FWD_DROP;
    red_match.meta.meter_color = DOCA_FLOW_METER_COLOR_RED;

    hndl = create_doca_flow_handle(netdev, AUX_QUEUE, 0, group, &red_match, NULL,
                                   NULL, NULL, NULL, &fwd, &flow_res, doh,
                                   &error);
    if (!hndl) {
        VLOG_ERR("%s: Failed to create post meter fixed red rule",
                 netdev_get_name(netdev));
        return -1;
    }

    return 0;
}

static void
doca_post_meter_pipe_uninit(struct netdev *netdev, struct doca_eswitch_ctx *ctx)
{
    doca_fixed_rule_uninit(netdev, &ctx->post_meter_red_flow);
    doca_ctl_pipe_ctx_unref(ctx->post_meter_pipe_ctx);
}

static int
doca_post_meter_pipe_init(struct netdev *netdev, struct doca_eswitch_ctx *ctx)
{
    struct doca_ctl_pipe_ctx *pipe_ctx;
    struct fixed_rule *fr;

    pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, POSTMETER_TABLE_ID);
    if (!pipe_ctx) {
        return -1;
    }
    ctx->post_meter_pipe_ctx = pipe_ctx;

    fr = &ctx->post_meter_red_flow;
    if (doca_create_post_meter_red_rule(netdev, POSTMETER_TABLE_ID,
                                        &fr->doh)) {
        goto err;
    }

    return 0;

err:
    doca_post_meter_pipe_uninit(netdev, ctx);
    return -1;
}

static struct offload_metadata *doca_eswitch_md;

static void
doca_eswitch_ctx_uninit(void *ctx_)
{
    struct doca_eswitch_ctx *ctx = ctx_;

    /* The fixed rule insertions were counted in the counters of
     * the netdev that issued the eswitch context init.
     *
     * Destroying the fixed rule is done only when the last netdev
     * using this eswitch context is being removed.
     *
     * We cannot keep track of the original init netdev without inducing
     * a circular dependency.
     *
     * So remove the fixed rules without counting the deletions
     * in the uninit netdev. As all netdevs related to this eswitch
     * are meant to be removed after this, the original counts will
     * have been removed once the uninit has finished.
     */
    if (ctx->shared_cnt_id_pool) {
        doca_post_meter_pipe_uninit(NULL, ctx);
        doca_ct_zones_uninit(NULL, ctx);
        doca_ct_pipes_destroy(ctx);
    }
    doca_ctl_pipe_ctx_unref(ctx->root_pipe_ctx);
    if (ctx->gnv_opt_parser.parser) {
        doca_flow_parser_geneve_opt_destroy(ctx->gnv_opt_parser.parser);
        ctx->gnv_opt_parser.parser = NULL;
        if (ovsthread_once_start(&ctx->gnv_opt_parser.once)) {
            ovsthread_once_reset(&ctx->gnv_opt_parser.once);
        }
        ovs_mutex_destroy(&ctx->gnv_opt_parser.once.mutex);
    }
    ctx->root_pipe_ctx = NULL;
    if (ctx->shared_cnt_id_pool) {
        /* DOCA doesn't provide an api to unbind shared counters
         * and they will remain bound until the port is destroyed.
         */
        id_fpool_destroy(ctx->shared_cnt_id_pool);
        ctx->shared_cnt_id_pool = NULL;
        id_fpool_free_id(esw_id_pool, 0, ctx->esw_id);
    }
    ctx->esw_port = NULL;
}

static int
doca_eswitch_ctx_init(void *ctx_, void *arg_, uint32_t id OVS_UNUSED)
{
    struct netdev *netdev = (struct netdev *) arg_;
    struct doca_eswitch_ctx *ctx = ctx_;
    struct doca_flow_port *doca_port;

    /* Write the constant offsets of each async entries of the eswitch,
     * used to back reference this context from any entry. */
    for (unsigned int qid = 0; qid < MAX_OFFLOAD_QUEUE_NB; qid++) {
        for (unsigned int idx = 0; idx < OVS_DOCA_QUEUE_DEPTH; idx++) {
            ctx->async_state[qid].entries[idx].index = idx;
        }
    }

    ctx->root_pipe_ctx = doca_ctl_pipe_ctx_ref(netdev, 0);
    if (ctx->root_pipe_ctx == NULL) {
        goto error;
    }

    shared_cnt_id_init(ctx);

    doca_port = netdev_dpdk_doca_port_get(netdev);
    ctx->esw_port = doca_flow_port_switch_get(doca_port);
    ctx->gnv_opt_parser.once =
        (struct ovsthread_once) OVSTHREAD_ONCE_INITIALIZER;

    if (ctx->shared_cnt_id_pool) {
        if (doca_ct_pipes_init(netdev, ctx)) {
            goto error;
        }

        if (doca_ct_zones_init(netdev, ctx)) {
            goto error;
        }

        if (doca_bind_shared_cntrs(ctx)) {
            goto error;
        }

        if (doca_bind_shared_meters(ctx)) {
            goto error;
        }

        if (doca_post_meter_pipe_init(netdev, ctx)) {
            goto error;
        }
    }

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
    struct doca_flow_port *doca_port = netdev_dpdk_doca_port_get(netdev);
    struct doca_flow_port *esw_port;

    esw_port = doca_flow_port_switch_get(doca_port);

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

    if (!netdev_dpdk_is_ethdev(netdev)) {
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

    if (!netdev_dpdk_is_ethdev(netdev)) {
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

static void
log_conn_rule(uint32_t group,
              enum ct_tp_type tp_type,
              struct doca_flow_match *dspec,
              struct doca_flow_actions *dacts)
{
    struct doca_flow_header_format *dhdr;
    struct reg_field *ct_reg;
    uint16_t sport, dport;
    struct ds s;

    if (VLOG_DROP_DBG(&rl)) {
        return;
    }

    ds_init(&s);

    dhdr = &dspec->outer;

    if (tp_type == CT_TP_TCP) {
        sport = dhdr->tcp.l4_port.src_port;
        dport = dhdr->tcp.l4_port.dst_port;
    } else {
        sport = dhdr->udp.l4_port.src_port;
        dport = dhdr->udp.l4_port.dst_port;
    }
    ds_put_format(&s, IP_FMT":%"PRIu16"->"IP_FMT":%"PRIu16,
                  IP_ARGS(dhdr->ip4.src_ip), ntohs(sport),
                  IP_ARGS(dhdr->ip4.dst_ip), ntohs(dport));

    ct_reg = &reg_fields[REG_FIELD_CT_ZONE];
    ds_put_format(&s, " zone_map=%d",
        (dspec->meta.u32[ct_reg->index] >> ct_reg->offset) & ct_reg->mask);

    /* CT MARK */
    ct_reg = &reg_fields[REG_FIELD_CT_MARK];
    ds_put_format(&s, " mark=0x%08x",
        (dacts->meta.u32[ct_reg->index] >> ct_reg->offset) & ct_reg->mask);

    /* CT LABEL */
    ct_reg = &reg_fields[REG_FIELD_CT_LABEL_ID];
    ds_put_format(&s, " label=0x%08x",
        (dacts->meta.u32[ct_reg->index] >> ct_reg->offset) & ct_reg->mask);

    /* CT STATE */
    ct_reg = &reg_fields[REG_FIELD_CT_STATE];
    ds_put_format(&s, " state=0x%02x",
        (dacts->meta.u32[ct_reg->index] >> ct_reg->offset) & ct_reg->mask);

    /* CT CTX */
    ct_reg = &reg_fields[REG_FIELD_CT_CTX];
    ds_put_format(&s, " ctx=0x%02x",
        (dacts->meta.pkt_meta >> ct_reg->offset) & ct_reg->mask);

    dhdr = &dacts->outer;

    if (group == CTNAT_TABLE_ID) {
        ds_put_format(&s, " NAT: ");
        if (tp_type == CT_TP_TCP) {
            sport = dhdr->tcp.l4_port.src_port;
            dport = dhdr->tcp.l4_port.dst_port;
        } else {
            sport = dhdr->udp.l4_port.src_port;
            dport = dhdr->udp.l4_port.dst_port;
        }
        ds_put_format(&s, IP_FMT":%"PRIu16"->"IP_FMT":%"PRIu16,
                      IP_ARGS(dhdr->ip4.src_ip), ntohs(sport),
                      IP_ARGS(dhdr->ip4.dst_ip), ntohs(dport));
    }

    VLOG_DBG("conn create: %s", ds_cstr(&s));

    ds_destroy(&s);
}

static int
dpdk_offload_doca_insert_conn(struct netdev *netdev,
                              struct ct_flow_offload_item ct_offload[1],
                              uint32_t ct_match_zone_id,
                              uint32_t ct_action_label_id,
                              struct indirect_ctx *shared_count_ctx,
                              uint32_t ct_miss_ctx_id,
                              struct flow_item *fi)
{
    struct doca_flow_header_format *dhdr;
    const struct ct_match *ct_match;
    struct doca_flow_actions dacts;
    struct doca_flow_monitor dmon;
    struct doca_flow_match dspec;
    struct doca_eswitch_ctx *ctx;
    struct doca_flow_pipe *pipe;
    struct rte_flow_error error;
    struct reg_field *ct_reg;
    enum ct_nw_type nw_type;
    enum ct_tp_type tp_type;
    unsigned int queue_id;
    bool is_ct;

    ct_match = &ct_offload->ct_match;

    tp_type = ct_match->key.nw_proto == IPPROTO_TCP ? CT_TP_TCP : CT_TP_UDP;
    if (ct_match->key.dl_type == htons(ETH_TYPE_IP)) {
        nw_type = CT_NW_IP4;
    } else {
        VLOG_DBG_RL(&rl, "Unsupported CT network type.");
        return -1;
    }

    dhdr = &dspec.outer;

    /* IPv4 */
    if (nw_type == CT_NW_IP4) {
        dhdr->ip4.src_ip = ct_match->key.src.addr.ipv4;
        dhdr->ip4.dst_ip = ct_match->key.dst.addr.ipv4;
        dhdr->ip4.next_proto = ct_match->key.nw_proto;
    }

    if (tp_type == CT_TP_TCP) {
        dhdr->tcp.l4_port.src_port = ct_match->key.src.port;
        dhdr->tcp.l4_port.dst_port = ct_match->key.dst.port;
    } else {
        dhdr->udp.l4_port.src_port = ct_match->key.src.port;
        dhdr->udp.l4_port.dst_port = ct_match->key.dst.port;
    }

    ct_reg = &reg_fields[REG_FIELD_CT_ZONE];
    dspec.meta.u32[ct_reg->index] = ct_match_zone_id << ct_reg->offset;

    dhdr = &dacts.outer;

    /* Common part for all CT, plain and NAT. */

    dhdr->l3_type = DOCA_FLOW_L3_TYPE_IP4;
    dhdr->ip4.src_ip = ct_match->key.src.addr.ipv4;
    dhdr->ip4.dst_ip = ct_match->key.dst.addr.ipv4;

    if (tp_type == CT_TP_TCP) {
        dhdr->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
        dhdr->tcp.l4_port.src_port = ct_match->key.src.port;
        dhdr->tcp.l4_port.dst_port = ct_match->key.dst.port;
    } else {
        dhdr->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
        dhdr->udp.l4_port.src_port = ct_match->key.src.port;
        dhdr->udp.l4_port.dst_port = ct_match->key.dst.port;
    }

    /* For NAT translate the relevant fields. */
    if (ct_offload->nat.mod_flags) {
        is_ct = false;
        if (nw_type == CT_NW_IP4) {
            if (ct_offload->nat.mod_flags & NAT_ACTION_SRC) {
                dhdr->ip4.src_ip = ct_offload->nat.key.src.addr.ipv4;
            } else if (ct_offload->nat.mod_flags & NAT_ACTION_DST) {
                dhdr->ip4.dst_ip = ct_offload->nat.key.dst.addr.ipv4;
            }
        }
        if (ct_offload->nat.mod_flags & NAT_ACTION_SRC_PORT) {
            if (tp_type == CT_TP_TCP) {
                dhdr->tcp.l4_port.src_port = ct_offload->nat.key.src.port;
            } else {
                dhdr->udp.l4_port.src_port = ct_offload->nat.key.src.port;
            }
        } else if (ct_offload->nat.mod_flags & NAT_ACTION_DST_PORT) {
            if (tp_type == CT_TP_TCP) {
                dhdr->tcp.l4_port.dst_port = ct_offload->nat.key.dst.port;
            } else {
                dhdr->udp.l4_port.dst_port = ct_offload->nat.key.dst.port;
            }
        }
    } else {
        is_ct = true;
    }

    memset(&dmon, 0, sizeof dmon);
    dmon.shared_counter_id = shared_count_ctx->res_id;

    memset(dacts.meta.u32, 0, sizeof dacts.meta.u32);

    /* CT MARK */
    ct_reg = &reg_fields[REG_FIELD_CT_MARK];
    dacts.meta.u32[ct_reg->index] |= ct_offload->mark_key << ct_reg->offset;

    /* CT LABEL */
    ct_reg = &reg_fields[REG_FIELD_CT_LABEL_ID];
    dacts.meta.u32[ct_reg->index] |= ct_action_label_id << ct_reg->offset;

    /* CT STATE */
    ct_reg = &reg_fields[REG_FIELD_CT_STATE];
    dacts.meta.u32[ct_reg->index] |= ct_offload->ct_state << ct_reg->offset;

    /* CT CTX */
    ct_reg = &reg_fields[REG_FIELD_CT_CTX];
    dacts.meta.pkt_meta = ct_miss_ctx_id << ct_reg->offset;

    ctx = doca_eswitch_ctx_get(netdev);
    queue_id = netdev_offload_thread_id();
    memset(fi, 0, sizeof *fi);

    log_conn_rule(is_ct ? CT_TABLE_ID : CTNAT_TABLE_ID, tp_type, &dspec,
                  &dacts);

    dacts.action_idx = 0;
    pipe = ctx->ct_pipes[nw_type][tp_type].pipe;
    if (create_doca_basic_flow_entry(netdev, queue_id, pipe, &dspec,
                                     &dacts, &dmon, NULL, &fi->doh[0],
                                     &error)) {
        VLOG_WARN_RL(&rl, "%s: Failed to create ct entry: Error %d (%s)",
                     netdev_get_name(netdev), error.type, error.message);
        return -1;
    }
    fi->doh[0].valid = true;

    return 0;
}

struct dpdk_offload_api dpdk_offload_api_doca = {
    .upkeep = dpdk_offload_doca_upkeep,
    .create = dpdk_offload_doca_create,
    .destroy = dpdk_offload_doca_destroy,
    .query_count = dpdk_offload_doca_query_count,
    .get_packet_recover_info = dpdk_offload_doca_get_pkt_recover_info,
    .insert_conn = dpdk_offload_doca_insert_conn,
    .reg_fields = dpdk_offload_doca_get_reg_fields,
    .netdev_data_destroy = dpdk_offload_doca_netdev_data_destroy,
    .update_stats = dpdk_offload_doca_update_stats,
    .aux_tables_init = dpdk_offload_doca_aux_tables_init,
    .aux_tables_uninit = dpdk_offload_doca_aux_tables_uninit,
    .shared_create = dpdk_offload_doca_shared_create,
    .shared_destroy = dpdk_offload_doca_shared_destroy,
    .shared_query = dpdk_offload_doca_shared_query,
};
