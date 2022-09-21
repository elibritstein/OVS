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
#include "dpif.h"
#include "sset.h"

METRICS_SUBSYSTEM(dpif);

static void
do_foreach_dpif(metrics_visitor_fn visitor,
                struct metrics_visitor_context *ctx,
                struct metrics_node *node,
                struct metrics_label *labels,
                size_t n OVS_UNUSED)
{
    struct sset types;
    const char *type;

    sset_init(&types);
    dp_enumerate_types(&types);
    SSET_FOR_EACH (type, &types) {
        struct dpif *dpif;
        struct sset names;
        const char *name;

        sset_init(&names);
        dp_enumerate_names(type, &names);
        SSET_FOR_EACH (name, &names) {
            if (!dpif_open(name, type, &dpif)) {
                ctx->it = dpif;
                if (labels[0].key) {
                    labels[0].value = name;
                }
                visitor(ctx, node);
                dpif_close(dpif);
            }
        }
        sset_destroy(&names);
    }
    sset_destroy(&types);
}

METRICS_COLLECTION(dpif, foreach_dpif, do_foreach_dpif, "datapath");
METRICS_COLLECTION(dpif, foreach_dpif_nolabel, do_foreach_dpif, NULL);
