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
#include "netdev.h"
#include "ofproto-private.h"
#include "ofproto-provider.h"

METRICS_SUBSYSTEM(ofproto);

static void
do_foreach_ofproto(metrics_visitor_fn visitor,
                   struct metrics_visitor_context *ctx,
                   struct metrics_node *node,
                   struct metrics_label *labels,
                   size_t n OVS_UNUSED)
{
    struct ofproto *ofproto;

    HMAP_FOR_EACH (ofproto, hmap_node, &all_ofprotos) {
        ctx->it = ofproto;
        labels[0].value = ofproto->name;
        labels[1].value = ofproto->type;
        visitor(ctx, node);
    }
}

METRICS_COLLECTION(ofproto, foreach_ofproto,
                   do_foreach_ofproto, "name", "type");

static void
bridge_n_read_value(double *values, void *it OVS_UNUSED)
{
    values[0] = hmap_count(&all_ofprotos);
}
METRICS_ENTRIES(ofproto, n_bridges, "bridge", bridge_n_read_value,
    METRICS_GAUGE(n_bridges,
        "Number of bridges present in the instance."),
);

enum {
    OF_BRIDGE_NAME,
    OF_BRIDGE_N_PORTS,
    OF_BRIDGE_N_FLOWS,
};

static void
bridge_read_value(double *values, void *it)
{
    struct ofproto *ofproto = it;
    struct oftable *table;
    unsigned int n_flows;

    n_flows = 0;
    OFPROTO_FOR_EACH_TABLE (table, ofproto) {
        n_flows += table->n_flows;
    }

    values[OF_BRIDGE_NAME] = 1.0;
    values[OF_BRIDGE_N_PORTS] = hmap_count(&ofproto->ports);
    values[OF_BRIDGE_N_FLOWS] = n_flows;
}

METRICS_ENTRIES(foreach_ofproto, bridge_entries, "bridge", bridge_read_value,
    [OF_BRIDGE_NAME] = METRICS_GAUGE(,
        "A metric with a constant value '1' labeled by bridge name and type "
        "present on the instance."),
    [OF_BRIDGE_N_PORTS] = METRICS_GAUGE(n_ports,
        "Number of ports present on the bridge."),
    [OF_BRIDGE_N_FLOWS] = METRICS_GAUGE(n_flows,
        "Number of flows present on the bridge."),
);

void
ofproto_metrics_register(void)
{
    static bool registered;
    if (registered) {
        return;
    }
    registered = true;

    METRICS_REGISTER(n_bridges);
    METRICS_REGISTER(bridge_entries);
}
