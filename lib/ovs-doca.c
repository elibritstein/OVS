/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "compiler.h"
#include "ovs-doca.h"
#include "vswitch-idl.h"

#ifdef DOCA_NETDEV

#include <rte_common.h>
#include <rte_pmd_mlx5.h>

#include <doca_version.h>

/* DOCA disables dpdk steering as a constructor in higher priority.
 * Set a lower priority one to enable it back. Disable it only upon using
 * doca ports.
 */
RTE_INIT(dpdk_steering_enable)
{
    rte_pmd_mlx5_enable_steering();
}

void
ovs_doca_init(const struct smap *ovs_other_config OVS_UNUSED)
{
}

void
print_doca_version(void)
{
    puts(doca_version_runtime());
}

void
ovs_doca_status(const struct ovsrec_open_vswitch *cfg)
{
    if (!cfg) {
        return;
    }

    ovsrec_open_vswitch_set_doca_initialized(cfg, false);
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
