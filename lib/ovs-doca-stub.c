/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#include "ovs-doca.h"
#include "ovs-thread.h"
#include "openvswitch/vlog.h"
#include "smap.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(doca);

int
ovs_doca_init(const struct smap *ovs_other_config OVS_UNUSED)
{
    return 0;
}

void *
ovs_doca_port_create(uint16_t port_id OVS_UNUSED)
{
    return NULL;
}

int
ovs_doca_port_destroy(void *port OVS_UNUSED)
{
    return 0;
}

void
ovs_doca_status(const struct ovsrec_open_vswitch *cfg)
{
    if (cfg) {
        ovsrec_open_vswitch_set_doca_initialized(cfg, false);
        ovsrec_open_vswitch_set_doca_version(cfg, "none");
    }
}

bool
ovs_doca_enabled(void)
{
    return false;
}

void
ovs_doca_destroy(void)
{
}
