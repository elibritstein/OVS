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

#include <stdbool.h>

#include "metrics.h"
#include "metrics-private.h"
#include "openvswitch/dynamic-string.h"
#include "unixctl.h"

bool metrics_show_extended;
bool metrics_show_debug;

struct metrics_show_params {
    bool usage;
    bool extended;
    bool debug;
    const char *error;
};

static void
metrics_show_format_usage(struct ds *s,
                          struct metrics_show_params *p)
{
    if (p->error) {
        ds_put_format(s, "invalid option -- '%s'\n", p->error);
    }
    ds_put_format(s, "Usage: metrics/show [-d] [-h] [-x]\n");
    ds_put_format(s, "\n");
    ds_put_format(s, "Show the system metrics.\n");
    ds_put_format(s, "\n");
    ds_put_format(s, "-d: Show debug metrics as well.\n");
    ds_put_format(s, "-h: Show this help.\n");
    ds_put_format(s, "-x: Show extended metrics as well.\n");
}

static void
metrics_show_parse_params(int argc, const char *argv[],
                          struct metrics_show_params *p)
{
    memset(p, 0, sizeof *p);

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-d")) {
            p->debug = true;
        } else if (!strcmp(argv[i], "-h")) {
            p->usage = true;
        } else if (!strcmp(argv[i], "-x")) {
            p->extended = true;
        } else {
            p->usage = true;
            p->error = argv[i];
        }
    }
}

static void
metrics_show(struct unixctl_conn *conn,
             int argc, const char *argv[],
             void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct metrics_show_params p;

    metrics_show_parse_params(argc, argv, &p);
    if (p.usage) {
        metrics_show_format_usage(&reply, &p);
    } else {
        metrics_show_extended = p.extended;
        metrics_show_debug = p.debug;
        metrics_values_format(&reply);
    }

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

    unixctl_command_register("metrics/show", "[-d] [-h] [-x]",
                             0, 3, metrics_show, NULL);
}
