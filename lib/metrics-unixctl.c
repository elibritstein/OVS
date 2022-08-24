/*
 * Copyright (c) 2022 NVIDIA Corporation.
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

#include "metrics.h"
#include "metrics-private.h"
#include "openvswitch/dynamic-string.h"
#include "unixctl.h"

static void
metrics_show(struct unixctl_conn *conn,
             int argc OVS_UNUSED,
             const char *argv[] OVS_UNUSED,
             void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;

    metrics_values_format(&reply);

    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

void
metrics_unixctl_register(const char *metrics_root_name)
{
    metrics_init();
    metrics_tree_check();

    if (metrics_root_name != NULL) {
        metrics_root_set_name(metrics_root_name);
    }

    unixctl_command_register("metrics/show",
                             "", 0, 1,
                             metrics_show, NULL);
}
