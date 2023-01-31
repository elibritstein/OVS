/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <config.h>

#include <doca_version.h>
#include <doca_flow.h>

#include "dpdk.h"
#include "netdev-offload.h"
#include "netdev-offload-provider.h"
#include "openvswitch/vlog.h"
#include "ovs-doca.h"

VLOG_DEFINE_THIS_MODULE(ovs_doca);

/* Indicates successful initialization of DOCA. */
static atomic_bool doca_initialized = ATOMIC_VAR_INIT(false);

/* Maximum number of megaflows */
#define OVS_DOCA_MAX_COUNTERS (1 << 16)

#define MAX_PORT_STR_LEN 128

bool
ovs_doca_enabled(void)
{
    bool initialized;

    atomic_read_relaxed(&doca_initialized, &initialized);
    return initialized;
}

int
ovs_doca_init(const struct smap *ovs_other_config)
{
    static struct ovsthread_once once_enable = OVSTHREAD_ONCE_INITIALIZER;
    unsigned int nb_threads = DEFAULT_OFFLOAD_THREAD_NB;
    struct doca_flow_cfg cfg = {};
    static bool enabled = false;
    doca_error_t err;

    if (!ovsthread_once_start(&once_enable)) {
        return 0;
    }

    if (!enabled && ovs_other_config &&
        smap_get_bool(ovs_other_config, "doca-init", false)) {
        /* Set dpdk-init to be true if not already set */
        smap_replace(CONST_CAST(struct smap *, ovs_other_config),
                     "dpdk-init", "true");
        dpdk_init(ovs_other_config);

        /* Due to limitation in doca, only one offload thread is currently
         * supported.
         * */
        if (smap_get_uint(ovs_other_config,"n-offload-threads", 1) !=
            nb_threads) {
            smap_replace(CONST_CAST(struct smap *, ovs_other_config),
                         "n-offload-threads", "1");
            VLOG_WARN_ONCE("Only %u offload thread is currently supported with"
                           "doca, ignoring n-offload-threads configuration",
                           nb_threads);
        }
        cfg.queues = smap_get_uint(ovs_other_config, "n-offload-threads", 1);
        cfg.resource.nb_counters = OVS_DOCA_MAX_COUNTERS;
        cfg.mode_args = "switch,hws";
        cfg.queue_depth = 32;

        VLOG_INFO("DOCA Enabled - initializing...");
        err = doca_flow_init(&cfg);
        if (err) {
            VLOG_ERR("Error initializing doca flow offload. Error %d (%s)\n",
                    err, doca_get_error_string(err));

            ovs_abort(err, "Cannot init DOCA");
            return err;
        }

        enabled = true;
        VLOG_INFO("DOCA Enabled - initialized");
    }

    ovsthread_once_done(&once_enable);
    atomic_store_relaxed(&doca_initialized, enabled);

    return 0;
}

void *
ovs_doca_port_create(uint16_t port_id)
{
    struct doca_flow_port_cfg port_cfg;
    char port_id_str[MAX_PORT_STR_LEN];
    struct doca_flow_port *port;
    doca_error_t err;

    memset(&port_cfg, 0, sizeof(port_cfg));

    port_cfg.port_id = port_id;
    port_cfg.type = DOCA_FLOW_PORT_DPDK_BY_ID;
    snprintf(port_id_str, MAX_PORT_STR_LEN, "%d", port_cfg.port_id);
    port_cfg.devargs = port_id_str;

    err = doca_flow_port_start(&port_cfg, &port);
    if (err) {
        VLOG_ERR("Failed to start doca flow port_id %"PRIu16". Error: %d (%s)",
                 port_id, err, doca_get_error_string(err));

        return NULL;
    }

    return (void *)port;
}

int
ovs_doca_port_destroy(void *port)
{
    struct doca_flow_port *doca_port = port;

    return doca_flow_port_stop(doca_port);
}

void
ovs_doca_status(const struct ovsrec_open_vswitch *cfg)
{
    if (!cfg) {
        return;
    }
    ovsrec_open_vswitch_set_doca_initialized(cfg, ovs_doca_enabled());
    ovsrec_open_vswitch_set_doca_version(cfg, doca_version_runtime());
}

void
ovs_doca_destroy(void)
{
    doca_flow_destroy();
}
