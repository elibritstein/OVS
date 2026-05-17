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

#include "ovs-doca.h"

#include "compiler.h"
#include "vswitch-idl.h"

#ifdef DOCA_NETDEV

#include <errno.h>
#include <infiniband/verbs.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_flow.h>
#include <rte_pci.h>
#include <rte_pmd_mlx5.h>

#include <doca_flow.h>
#include <doca_flow_definitions.h>
#include <doca_log.h>
#include <doca_version.h>

#include "coverage.h"
#include "dpdk.h"
#include "netdev.h"
#include "netdev-doca.h"
#include "smap.h"
#include "unixctl.h"
#include "util.h"

#include "openvswitch/list.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovs_doca);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

COVERAGE_DEFINE(ovs_doca_queue_block);
COVERAGE_DEFINE(ovs_doca_queue_empty);
COVERAGE_DEFINE(ovs_doca_queue_none_processed);

#define OVS_DOCA_SLOWPATH_COUNTERS \
    ((NETDEV_DOCA_RSS_NUM_ENTRIES + 1) * RTE_MAX_ETHPORTS)

/* DOCA installs a higher-priority constructor that disables DPDK steering.
 * This lower-priority constructor re-enables it. */
RTE_INIT(dpdk_steering_enable)
{
    rte_pmd_mlx5_enable_steering();
}

static atomic_bool doca_initialized = false;

static unsigned int ovs_doca_max_megaflows_counters;

static struct doca_log_backend *ovs_doca_log = NULL;
static FILE *log_stream = NULL;       /* Stream for DOCA log redirection */

static const char * const levels[] = {
    [DOCA_LOG_LEVEL_CRIT]    = "CRT",
    [DOCA_LOG_LEVEL_ERROR]   = "ERR",
    [DOCA_LOG_LEVEL_WARNING] = "WRN",
    [DOCA_LOG_LEVEL_INFO]    = "INF",
    [DOCA_LOG_LEVEL_DEBUG]   = "DBG",
    [DOCA_LOG_LEVEL_TRACE]   = "TRC",
};

static int
ovs_doca_parse_log_level(const char *s)
{
    for (int i = 0; i < ARRAY_SIZE(levels); ++i) {
        if (levels[i] && !strncmp(s, levels[i], strlen(levels[i]))) {
            return i;
        }
    }

    return -EINVAL;
}

static const char *
ovs_doca_log_level_to_str(uint32_t log_level)
{
    for (int i = 0; i < ARRAY_SIZE(levels); ++i) {
        if (i == log_level && levels[i]) {
            return levels[i];
        }
    }

    OVS_NOT_REACHED();
    return "UNKNOWN";
}

static enum doca_log_level
get_buf_log_level(const char **pbuf, size_t *psize)
{
    const char *buf = *pbuf;
    size_t size = *psize;
    const char *p = buf;
    int level;

    /* Skip [timestamp][thread_id][DOCA], then parse [LEVEL] (INF/WRN/etc.). */
    for (int i = 0; i < 4; i++) {
        while (size && *p && *p != '[') {
            size--;
            p++;
        }

        if (!size || !*p) {
            return DOCA_LOG_LEVEL_DISABLE;
        }

        size--;
        p++;
    }

    level = ovs_doca_parse_log_level(p);
    if (level < 0) {
        return DOCA_LOG_LEVEL_DISABLE;
    }

    /* 'p' points to the level start which is 3 chars and another ']'
     * after it.  For example "INF]".  Skip it. */
    *pbuf = p + 4;
    *psize -= *pbuf - buf;

    return level;
}

static ssize_t
ovs_doca_log_write(void *c OVS_UNUSED, const char *buf, size_t size)
{
    static struct vlog_rate_limit dbg_rl = VLOG_RATE_LIMIT_INIT(600, 600);
    enum doca_log_level level = get_buf_log_level(&buf, &size);

    switch (level) {
        case DOCA_LOG_LEVEL_DISABLE:
            VLOG_EMER("(Failed to parse level): %.*s", (int) size, buf);
            break;
        case DOCA_LOG_LEVEL_TRACE:
        case DOCA_LOG_LEVEL_DEBUG:
            VLOG_DBG_RL(&dbg_rl, "%.*s", (int) size, buf);
            break;
        case DOCA_LOG_LEVEL_INFO:
            VLOG_INFO_RL(&dbg_rl, "%.*s", (int) size, buf);
            break;
        case DOCA_LOG_LEVEL_WARNING:
            VLOG_WARN_RL(&dbg_rl, "%.*s", (int) size, buf);
            break;
        case DOCA_LOG_LEVEL_ERROR:
            VLOG_ERR_RL(&dbg_rl, "%.*s", (int) size, buf);
            break;
        case DOCA_LOG_LEVEL_CRIT:
            VLOG_EMER("%.*s", (int) size, buf);
            break;
        default:
            OVS_NOT_REACHED();
    }

    return size;
}

static cookie_io_functions_t ovs_doca_log_func = {
    .write = ovs_doca_log_write,
};

static void
ovs_doca_unixctl_log_set(struct unixctl_conn *conn, int argc,
                         const char *argv[], void *aux OVS_UNUSED)
{
    int level = DOCA_LOG_LEVEL_DEBUG;

    /* With no argument, level is set to 'debug'. */
    if (argc == 2) {
        const char *level_string = argv[1];

        level = ovs_doca_parse_log_level(level_string);
        if (level < 0) {
            char *err_msg = xasprintf("invalid log level: '%s'", level_string);

            unixctl_command_reply_error(conn, err_msg);
            free(err_msg);
            return;
        }
    }

    doca_log_level_set_global_sdk_limit(level);
    unixctl_command_reply(conn, NULL);
}

static void
ovs_doca_log_get(FILE *stream)
{
    uint32_t log_level;

    log_level = doca_log_level_get_global_sdk_limit();
    fprintf(stream, "DOCA log level is %s",
            ovs_doca_log_level_to_str(log_level));
}

static void
ovs_doca_destroy_defs(struct doca_flow_definitions *defs,
                      struct doca_flow_definitions_cfg *defs_cfg)
{
    if (defs) {
        doca_flow_definitions_destroy(defs);
    }

    if (defs_cfg) {
        doca_flow_definitions_cfg_destroy(defs_cfg);
    }
}

static doca_error_t
ovs_doca_init_defs(struct doca_flow_cfg *cfg,
                   struct doca_flow_definitions **defs,
                   struct doca_flow_definitions_cfg **defs_cfg)
{
#define DEF_FIELD(str_val, struct_name, field_name) {     \
    .str = str_val,                                       \
    .offset = offsetof(struct struct_name, field_name),   \
    .size = MEMBER_SIZEOF(struct struct_name, field_name) \
}
    struct def_field {
        const char *str;
        size_t offset;
        size_t size;
    } def_fields[] = {
        DEF_FIELD("actions.packet.meta.mark", ovs_doca_flow_actions, mark),
    };
    doca_error_t result;

    result = doca_flow_definitions_cfg_create(defs_cfg);
    if (result != DOCA_SUCCESS) {
        VLOG_ERR("Failed to create defs cfg. Error: %d (%s)", result,
                 doca_error_get_descr(result));
        return result;
    }

    result = doca_flow_definitions_create(*defs_cfg, defs);
    if (result != DOCA_SUCCESS) {
        VLOG_ERR("Failed to create definitions. Error: %d (%s)", result,
                 doca_error_get_descr(result));
        goto out;
    }

    for (int i = 0; i < ARRAY_SIZE(def_fields); i++) {
        result = doca_flow_definitions_add_field(*defs, def_fields[i].str,
                                                 def_fields[i].offset,
                                                 def_fields[i].size);
        if (result != DOCA_SUCCESS) {
            VLOG_ERR("Failed to add definition field '%s'. Error: %d (%s)",
                     def_fields[i].str, result, doca_error_get_descr(result));
            goto out;
        }
    }

    result = doca_flow_cfg_set_definitions(cfg, *defs);
    if (result != DOCA_SUCCESS) {
        VLOG_ERR("Failed to set doca_flow_cfg defs. Error: %d (%s)", result,
                 doca_error_get_descr(result));
        goto out;
    }

out:
    if (result != DOCA_SUCCESS) {
        ovs_doca_destroy_defs(*defs, *defs_cfg);
    }

    return result;
}

/* Every doca-entry operation is asynchronous.  It must be processed using
 * doca_flow_entries_process() API.  For each processed entry, this callback
 * is called.  The 'qid' argument is the queue-id for which the entry was
 * processed on (which is the same as the one of the initial operation).
 * 'queues' is an array of queues.  Each entry is accessed only the its own
 * queue (which is assigned to a thread), no locks are required here. */
static void
ovs_doca_offload_entry_process(struct doca_flow_pipe_entry *entry,
                               uint16_t qid,
                               enum doca_flow_entry_status status,
                               enum doca_flow_entry_op op,
                               void *aux)
{
    static const char *status_desc[] = {
        [DOCA_FLOW_ENTRY_STATUS_IN_PROCESS] = "in-process",
        [DOCA_FLOW_ENTRY_STATUS_SUCCESS] = "success",
        [DOCA_FLOW_ENTRY_STATUS_ERROR] = "failure",
    };
    static const char *op_desc[] = {
        [DOCA_FLOW_ENTRY_OP_ADD] = "add",
        [DOCA_FLOW_ENTRY_OP_DEL] = "del",
        [DOCA_FLOW_ENTRY_OP_UPD] = "mod",
        [DOCA_FLOW_ENTRY_OP_AGED] = "age",
    };
    bool error = status == DOCA_FLOW_ENTRY_STATUS_ERROR;
    struct ovs_doca_offload_queue *queues = aux;

    ovs_assert(status < ARRAY_SIZE(status_desc));
    ovs_assert(op < ARRAY_SIZE(op_desc));

    VLOG_RL(&rl, error ? VLL_ERR : VLL_DBG,
            "%s: [qid:%" PRIu16 "] %s aux=%p entry %p %s",
            __func__, qid, op_desc[op], aux, entry, status_desc[status]);

    if (queues && status != DOCA_FLOW_ENTRY_STATUS_IN_PROCESS) {
        queues[qid].n_waiting_entries--;
    }
}

static int
ovs_doca_init__(const struct smap *ovs_other_config)
{
    struct doca_flow_definitions_cfg *defs_cfg = NULL;
    struct doca_flow_definitions *defs = NULL;
    struct doca_flow_cfg *cfg;
    doca_error_t err;

    if (!dpdk_available()) {
        VLOG_ERR("DOCA requires DPDK. Set other_config:dpdk-init=true.");
        return ENODEV;
    }

    if (rte_flow_dynf_metadata_register() < 0) {
        VLOG_ERR("Failed to register dynamic metadata, Error: %d (%s)",
                 rte_errno, rte_strerror(rte_errno));
        return ENOTSUP;
    }

    log_stream = fopencookie(NULL, "w+", ovs_doca_log_func);
    if (!log_stream) {
        VLOG_ERR("Can't redirect DOCA log: %s.", ovs_strerror(errno));
    } else {
        /* Create a logger back-end that prints to the redirected log. */
        doca_log_backend_create_with_file_sdk(log_stream, &ovs_doca_log);
        doca_log_level_set_global_sdk_limit(DOCA_LOG_LEVEL_WARNING);
    }

    unixctl_command_register("doca/log-set", "{level}. "
                             "level=CRT/ERR/WRN/INF/DBG/TRC", 0, 1,
                             ovs_doca_unixctl_log_set, NULL);
    unixctl_command_register("doca/log-get", "", 0, 0,
                             unixctl_mem_stream, ovs_doca_log_get);

    /* DOCA configuration happens earlier than dpif-netdev's.
     * To avoid reorganizing them, read the relevant item directly. */
    ovs_doca_max_megaflows_counters =
        smap_get_uint(ovs_other_config, "flow-limit",
                      OVS_DOCA_MAX_MEGAFLOWS_COUNTERS);

#define RV_TEST(call)                                                    \
    do {                                                                 \
        err = (call);                                                    \
        if (err != DOCA_SUCCESS) {                                       \
            VLOG_ERR("DOCA initialization failed, %s(). Error: %d (%s)", \
                     #call, err, doca_error_get_descr(err));             \
            return ENODEV;                                               \
        }                                                                \
    } while (0)

    RV_TEST(doca_flow_cfg_create(&cfg));
    RV_TEST(doca_flow_cfg_set_pipe_queues(cfg, OVS_DOCA_MAX_OFFLOAD_QUEUES));
    RV_TEST(doca_flow_cfg_set_resource_mode(cfg,
                                            DOCA_FLOW_RESOURCE_MODE_PORT));
    RV_TEST(doca_flow_cfg_set_mode_args(cfg, "switch,hws,isolated,expert"));
    RV_TEST(doca_flow_cfg_set_queue_depth(cfg, OVS_DOCA_QUEUE_DEPTH));
    RV_TEST(doca_flow_cfg_set_cb_entry_process(
                cfg, ovs_doca_offload_entry_process));
    RV_TEST(ovs_doca_init_defs(cfg, &defs, &defs_cfg));

    VLOG_INFO("DOCA Enabled - initializing...");
    RV_TEST(doca_flow_init(cfg));
    ovs_doca_destroy_defs(defs, defs_cfg);
    RV_TEST(doca_flow_cfg_destroy(cfg));

#undef RV_TEST

    netdev_doca_register();
    return 0;
}

static bool
ovs_doca_available(void)
{
    bool available;

    atomic_read_relaxed(&doca_initialized, &available);
    return available;
}

/* Complete the queue 'qid' on the netdev's ESW until OVS_DOCA_QUEUE_DEPTH
 * entries are available. */
static doca_error_t
ovs_doca_complete_queue_esw(struct netdev_doca_esw_ctx *esw,
                            unsigned int qid)
{
    struct ovs_doca_offload_queue *queue;
    long long int timeout_ms;
    unsigned int n_waiting;
    doca_error_t err;
    uint32_t room;
    int retries;

    queue = &esw->offload_queues[qid];
    n_waiting = queue->n_waiting_entries;

    if (n_waiting == 0) {
        COVERAGE_INC(ovs_doca_queue_empty);
        return DOCA_SUCCESS;
    }

    /* 1 second timeout. */
    timeout_ms = time_msec() + 1 * 1000;
    retries = 100;
    do {
        unsigned int n_processed;

        /* Use 'max_processed_entries' == 0 to always attempt processing
         * the full length of the queue. */
        err = doca_flow_entries_process(esw->esw_port, qid,
                                        OVS_DOCA_ENTRY_PROCESS_TIMEOUT_US, 0);
        if (err != DOCA_SUCCESS) {
            VLOG_WARN_RL(&rl, "%s: Failed to process entries in queue "
                         "%u. Error: %d (%s)",
                         netdev_get_name(esw->esw_netdev), qid,
                         err, doca_error_get_descr(err));
            return err;
        }

        n_processed = n_waiting - queue->n_waiting_entries;
        if (n_processed == 0) {
            COVERAGE_INC(ovs_doca_queue_none_processed);
        }
        n_waiting = queue->n_waiting_entries;

        room = OVS_DOCA_QUEUE_DEPTH - n_waiting;
        if (n_processed == 0 && retries-- <= 0) {
            COVERAGE_INC(ovs_doca_queue_block);
            break;
        }

        if (timeout_ms && time_msec() > timeout_ms) {
            VLOG_EMER("Timeout reached trying to complete queue %u: "
                      "%u remaining entries", qid, n_waiting);
        }
    } while (err == DOCA_SUCCESS && room < OVS_DOCA_QUEUE_DEPTH);

    return err;
}

static doca_error_t
ovs_doca_add_generic(unsigned int qid,
                     struct doca_flow_pipe *pipe,
                     enum doca_flow_pipe_type pipe_type,
                     uint32_t hash_index,
                     const struct ovs_doca_flow_match *ovs_match,
                     const struct ovs_doca_flow_actions *ovs_actions,
                     const struct doca_flow_monitor *monitor,
                     const struct doca_flow_fwd *fwd,
                     uint32_t flags,
                     struct netdev_doca_esw_ctx *esw,
                     struct doca_flow_pipe_entry **pentry)
{
    const struct doca_flow_actions *actions;
    struct ovs_doca_offload_queue *queues;
    const struct doca_flow_match *match;
    doca_error_t err;

    ovs_assert(esw && qid < OVS_DOCA_MAX_OFFLOAD_QUEUES);

    queues = esw->offload_queues;
    match = ovs_match ? &ovs_match->d : NULL;
    actions = ovs_actions ? &ovs_actions->d : NULL;

    switch (pipe_type) {
    case DOCA_FLOW_PIPE_BASIC:
        err = doca_flow_pipe_basic_add_entry(qid, pipe, match, 0, actions,
                                             monitor, fwd, flags, queues,
                                             pentry);
        break;
    case DOCA_FLOW_PIPE_HASH:
        err = doca_flow_pipe_hash_add_entry(qid, pipe, hash_index, 0, actions,
                                            monitor, fwd, flags, queues,
                                            pentry);
        break;
    case DOCA_FLOW_PIPE_CONTROL:
    case DOCA_FLOW_PIPE_LPM:
    case DOCA_FLOW_PIPE_CT:
    case DOCA_FLOW_PIPE_ACL:
    case DOCA_FLOW_PIPE_ORDERED_LIST:
        OVS_NOT_REACHED();
    }

    if (err == DOCA_SUCCESS) {
        queues[qid].n_waiting_entries++;
    }

    return err;
}

doca_error_t
ovs_doca_add_entry(struct netdev *netdev,
                   unsigned int qid,
                   struct doca_flow_pipe *pipe,
                   const struct ovs_doca_flow_match *match,
                   const struct ovs_doca_flow_actions *actions,
                   const struct doca_flow_monitor *monitor,
                   const struct doca_flow_fwd *fwd,
                   uint32_t flags,
                   struct doca_flow_pipe_entry **pentry)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;
    doca_error_t err;

    err = ovs_doca_add_generic(qid, pipe, DOCA_FLOW_PIPE_BASIC, 0, match,
                               actions, monitor, fwd, flags, esw, pentry);
    if (err != DOCA_SUCCESS) {
        VLOG_WARN_RL(&rl, "%s: Failed to create basic pipe entry. "
                     "Error: %d (%s)", netdev_get_name(netdev), err,
                     doca_error_get_descr(err));
        return err;
    }

    /* DOCA API is asynchronous.
     *
     * "wait" means the request is not sent to the HW yet (to enable bursts),
     * so we can't "complete" in this case.
     *
     * "no-wait" means it is sent immediately to the HW, then we want to
     * complete to return to the caller as if the call was "sync". */
    if (DOCA_FLOW_FLAGS_IS_SET(flags, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT)) {
        err = ovs_doca_complete_queue_esw(esw, qid);
    }

    return err;
}

doca_error_t
ovs_doca_remove_entry(struct netdev_doca_esw_ctx *esw,
                      unsigned int qid, uint32_t flags,
                      struct doca_flow_pipe_entry **entry)
{
    doca_error_t err;

    if (!*entry) {
        return DOCA_SUCCESS;
    }

    ovs_assert(qid < OVS_DOCA_MAX_OFFLOAD_QUEUES);

    err = doca_flow_pipe_remove_entry(qid, flags, *entry);
    if (err == DOCA_SUCCESS) {
        esw->offload_queues[qid].n_waiting_entries++;
        /* DOCA API is asynchronous.
         *
         * "wait" means the request is not sent to the HW yet (to enable
         * bursts), so we can't "complete" in this case.
         *
         * "no-wait" means it is sent immediately to the HW, then we want to
         * complete to return to the caller as if the call was "sync". */
        if (DOCA_FLOW_FLAGS_IS_SET(flags, DOCA_FLOW_ENTRY_FLAGS_NO_WAIT)) {
            /* Ignore potential errors here, as even if the queue completion
             * failed, the entry removal would still be issued.  The caller
             * requires knowing so. */
            ovs_doca_complete_queue_esw(esw, qid);
        }
        *entry = NULL;
    } else {
        VLOG_ERR("%s: Failed to remove entry %p qid=%d. Error: %d (%s)",
                 netdev_get_name(esw->esw_netdev), *entry, qid, err,
                 doca_error_get_descr(err));
    }

    return err;
}

doca_error_t
ovs_doca_pipe_cfg_allow_queues(struct doca_flow_pipe_cfg *cfg,
                               uint64_t queues_bitmap)
{
    ovs_assert(cfg);

    for (unsigned int qid = 0; qid < OVS_DOCA_MAX_OFFLOAD_QUEUES; qid++) {
        doca_error_t err;

        if ((UINT64_C(1) << qid) & queues_bitmap) {
            continue;
        }

        err = doca_flow_pipe_cfg_set_excluded_queue(cfg, qid);
        if (err != DOCA_SUCCESS) {
            return err;
        }
    }

    return DOCA_SUCCESS;
}

void
ovs_doca_destroy_pipe(struct doca_flow_pipe **ppipe)
{
    if (!ppipe || !*ppipe) {
        return;
    }

    doca_flow_pipe_destroy(*ppipe);
    *ppipe = NULL;
}

doca_error_t
ovs_doca_pipe_create(struct netdev *netdev,
                     struct ovs_doca_flow_match *match,
                     struct ovs_doca_flow_match *match_mask,
                     struct doca_flow_monitor *monitor,
                     struct ovs_doca_flow_actions *actions,
                     struct ovs_doca_flow_actions *actions_mask,
                     struct doca_flow_action_desc *desc,
                     struct doca_flow_fwd *fwd,
                     struct doca_flow_fwd *fwd_miss,
                     uint32_t nr_entries,
                     bool is_egress, bool is_root,
                     uint64_t queues_bitmap,
                     const char *pipe_str,
                     struct doca_flow_pipe **pipe)
{
    struct doca_flow_actions *actions_arr[1], *actions_masks_arr[1];
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct doca_flow_action_descs descs, *descs_arr[1];
    char pipe_name[OVS_DOCA_MAX_PIPE_NAME_LEN];
    struct doca_flow_port *doca_port;
    struct doca_flow_pipe_cfg *cfg;
    int ret;

    ovs_assert(!*pipe);

    doca_port = doca_flow_port_switch_get(dev->port);
    ovs_assert(doca_port);

    if (snprintf(pipe_name, sizeof pipe_name, "%s: %s",
                 netdev_get_name(netdev), pipe_str) >= sizeof pipe_name) {
        VLOG_WARN("%s: pipe name truncated", netdev_get_name(netdev));
    }

    ret = doca_flow_pipe_cfg_create(&cfg, doca_port);
    if (ret != DOCA_SUCCESS) {
        VLOG_ERR("%s: Could not create doca_flow_pipe_cfg for %s."
                 " Error: %d (%s)", netdev_get_name(netdev), pipe_name,
                 ret, doca_error_get_descr(ret));
        return ret;
    }

    actions_arr[0] = actions ? &actions->d : NULL;
    actions_masks_arr[0] = actions_mask ? &actions_mask->d : NULL;
    descs.desc_array = desc;
    descs.nb_action_desc = desc ? 1 : 0;
    descs_arr[0] = &descs;

#define PIPE_CFG_SET(call)                                                 \
    do {                                                                   \
        ret = (call);                                                      \
        if (ret != DOCA_SUCCESS) {                                         \
            VLOG_ERR("%s: Pipe '%s' configuration failed, %s(). "          \
                     "Error: %d (%s)", netdev_get_name(netdev), pipe_name, \
                     #call, ret, doca_error_get_descr(ret));               \
            goto error;                                                    \
        }                                                                  \
    } while (0)

    PIPE_CFG_SET(doca_flow_pipe_cfg_set_name(cfg, pipe_name));
    PIPE_CFG_SET(doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_BASIC));
    PIPE_CFG_SET(doca_flow_pipe_cfg_set_nr_entries(cfg, nr_entries));
    PIPE_CFG_SET(ovs_doca_pipe_cfg_allow_queues(cfg, queues_bitmap));
    if (is_egress) {
        PIPE_CFG_SET(doca_flow_pipe_cfg_set_domain(
            cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS));
    }

    PIPE_CFG_SET(doca_flow_pipe_cfg_set_is_root(cfg, is_root));
    if (match) {
        PIPE_CFG_SET(doca_flow_pipe_cfg_set_match(cfg, &match->d,
                                                  match_mask
                                                  ? &match_mask->d
                                                  : &match->d));
    }

    if (monitor) {
        PIPE_CFG_SET(doca_flow_pipe_cfg_set_monitor(cfg, monitor));
    }

    if (actions) {
        PIPE_CFG_SET(doca_flow_pipe_cfg_set_actions(cfg, actions_arr,
                                                    actions_mask
                                                    ? actions_masks_arr
                                                    : actions_arr,
                                                    desc
                                                    ? descs_arr
                                                    : NULL, 1));
    }

#undef PIPE_CFG_SET

    ret = doca_flow_pipe_create(cfg, fwd, fwd_miss, pipe);
    if (ret != DOCA_SUCCESS) {
        VLOG_ERR("%s: Failed to create basic pipe '%s'. Error: %d (%s)",
                 netdev_get_name(netdev), pipe_name, ret,
                 doca_error_get_descr(ret));
    }

error:
    doca_flow_pipe_cfg_destroy(cfg);
    return ret;
}

unsigned int
ovs_doca_max_counters(void)
{
    return ovs_doca_max_megaflows_counters + OVS_DOCA_SLOWPATH_COUNTERS;
}

/* Called from bridge_reconfigure() when other_config may have changed (same
 * moment as ofproto_set_flow_limit). No work on the main loop hot path. */
void
ovs_doca_flow_limit_config_changed(unsigned int cfg_flow_limit)
{
    bool available;

    atomic_read_relaxed(&doca_initialized, &available);
    if (!available) {
        return;
    }

    if (cfg_flow_limit != ovs_doca_max_megaflows_counters) {
        VLOG_WARN_RL(&rl,
                     "other_config:flow-limit is now %u but DOCA was already "
                     "initialized with %u; the limit is fixed until "
                     "ovs-vswitchd is restarted.",
                     cfg_flow_limit, ovs_doca_max_megaflows_counters);
    }
}

void
ovs_doca_init(const struct smap *ovs_other_config)
{
    static bool enabled = false;
    int rv;

    if (enabled || !ovs_other_config) {
        return;
    }

    if (smap_get_bool(ovs_other_config, "doca-init", false)) {
        static struct ovsthread_once once_enable = OVSTHREAD_ONCE_INITIALIZER;

        if (!ovsthread_once_start(&once_enable)) {
            return;
        }

        VLOG_INFO("Using DOCA %s", doca_version_runtime());
        VLOG_INFO("DOCA Enabled - initializing...");
        rv = ovs_doca_init__(ovs_other_config);
        if (!rv) {
            VLOG_INFO("DOCA Enabled - initialized");
            enabled = true;
        } else {
            ovs_abort(rv, "DOCA Initialization Failed.");
        }

        ovsthread_once_done(&once_enable);
    } else {
        VLOG_INFO_ONCE("DOCA Disabled - Use other_config:doca-init to enable");
    }

    atomic_store_relaxed(&doca_initialized, enabled);
}

void
print_doca_version(void)
{
    printf("DOCA %s\n", doca_version_runtime());
}

void
ovs_doca_status(const struct ovsrec_open_vswitch *cfg)
{
    if (!cfg) {
        return;
    }

    ovsrec_open_vswitch_set_doca_initialized(cfg, ovs_doca_available());
    ovsrec_open_vswitch_set_doca_version(cfg, doca_version_runtime());
}

#else /* DOCA_NETDEV */

void
ovs_doca_init(const struct smap *ovs_other_config OVS_UNUSED)
{
}

void
print_doca_version(void)
{
}

void
ovs_doca_status(const struct ovsrec_open_vswitch *cfg)
{
    if (!cfg) {
        return;
    }

    ovsrec_open_vswitch_set_doca_initialized(cfg, false);
    ovsrec_open_vswitch_set_doca_version(cfg, "none");
}

#endif /* DOCA_NETDEV */
