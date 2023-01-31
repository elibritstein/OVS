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

#ifndef OVS_DOCA_H_
#define OVS_DOCA_H_

#include <config.h>

#include "smap.h"
#include "vswitch-idl.h"

bool
ovs_doca_enabled(void);

int
ovs_doca_init(const struct smap *ovs_other_config);

void *
ovs_doca_port_create(uint16_t port_id);

int
ovs_doca_port_destroy(void *port);

void
ovs_doca_status(const struct ovsrec_open_vswitch *cfg);

void
ovs_doca_destroy(void);
#endif
