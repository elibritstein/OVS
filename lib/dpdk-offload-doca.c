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
#include "util.h"

VLOG_DEFINE_THIS_MODULE(dpdk_offload_doca);

OVS_ASSERT_PACKED(struct doca_ctl_pipe_key,
    uint32_t group_id;
    uint32_t esw_mgr_port_id;
);

struct doca_ctl_pipe_ctx {
    struct netdev *netdev;
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

OVS_UNUSED
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

OVS_UNUSED
static void
doca_ctl_pipe_ctx_unref(struct doca_ctl_pipe_ctx *ctx)
{
    doca_ctl_pipe_md_init();
    offload_metadata_priv_unref(doca_ctl_pipe_md,
                                netdev_offload_thread_id(),
                                ctx);
}


static struct reg_field *
dpdk_offload_doca_get_reg_fields(void)
{
    return NULL;
}

static struct rte_flow *
dpdk_offload_doca_create(struct netdev *netdev OVS_UNUSED,
                         const struct rte_flow_attr *attr OVS_UNUSED,
                         const struct rte_flow_item *items OVS_UNUSED,
                         const struct rte_flow_action *actions OVS_UNUSED,
                         struct rte_flow_error *error OVS_UNUSED)
{
    return NULL;
}

static int
dpdk_offload_doca_destroy(struct netdev *netdev OVS_UNUSED,
                          struct rte_flow *rte_flow OVS_UNUSED,
                          struct rte_flow_error *error OVS_UNUSED,
                          bool esw_port_id OVS_UNUSED)
{
    return -1;
}

static int
dpdk_offload_doca_query_count(struct netdev *netdev OVS_UNUSED,
                              struct rte_flow *rte_flow OVS_UNUSED,
                              struct rte_flow_query_count *query OVS_UNUSED,
                              struct rte_flow_error *error OVS_UNUSED)
{
    return -1;
}

static struct rte_flow_action_handle *
dpdk_offload_doca_shared_create(struct netdev *netdev OVS_UNUSED,
                                const struct rte_flow_action *action OVS_UNUSED,
                                struct rte_flow_error *error OVS_UNUSED)
{
    return NULL;
}

static int
dpdk_offload_doca_shared_destroy(int port_id OVS_UNUSED,
                                 struct rte_flow_action_handle *act_hdl OVS_UNUSED,
                                 struct rte_flow_error *error OVS_UNUSED)
{
    return -1;
}

static int
dpdk_offload_doca_shared_query(int port_id OVS_UNUSED,
                               struct rte_flow_action_handle *act_hdl OVS_UNUSED,
                               void *data OVS_UNUSED,
                               struct rte_flow_error *error OVS_UNUSED)
{
    return -1;
}

static void
dpdk_offload_doca_get_pkt_recover_info(struct dp_packet *p OVS_UNUSED,
                                       struct dpdk_offload_recovery_info *info)
{
    memset(info, 0, sizeof *info);
    return;
}

static int
dpdk_offload_doca_netdev_data_destroy(void *data OVS_UNUSED)
{
    return -1;
}

static void
dpdk_offload_doca_update_stats(struct dpif_flow_stats *stats OVS_UNUSED,
                               struct dpif_flow_attrs *attrs,
                               struct rte_flow_query_count *query OVS_UNUSED)
{
    attrs->dp_layer = "doca";
    return;
}

struct dpdk_offload_api dpdk_offload_api_doca = {
    .create = dpdk_offload_doca_create,
    .destroy = dpdk_offload_doca_destroy,
    .query_count = dpdk_offload_doca_query_count,
    .shared_create = dpdk_offload_doca_shared_create,
    .shared_destroy = dpdk_offload_doca_shared_destroy,
    .shared_query = dpdk_offload_doca_shared_query,
    .get_packet_recover_info = dpdk_offload_doca_get_pkt_recover_info,
    .reg_fields = dpdk_offload_doca_get_reg_fields,
    .netdev_data_destroy = dpdk_offload_doca_netdev_data_destroy,
    .update_stats = dpdk_offload_doca_update_stats,
};
