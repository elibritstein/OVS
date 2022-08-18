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

#include <math.h>
#include <stdint.h>

#include "metrics.h"
#include "metrics-private.h"
#include "openvswitch/util.h"
#include "util.h"

static size_t
metrics_set_size(struct metrics_node *node)
{
    struct metrics_set *set = metrics_node_cast(node);

    return sizeof(struct metrics_set) +
           set->n_entries * sizeof(struct metrics_entry);
}

static size_t
metrics_set_n_values(struct metrics_node *node)
{
    struct metrics_set *set = metrics_node_cast(node);

    return set->n_entries;
}

static void
metrics_set_check_entry(struct metrics_entry *entry)
{
    /* The entry has associated description. */
    ovs_assert(entry->help != NULL);
    /* The entry has a 'public' stable name. */
    ovs_assert(entry->name != NULL);
}

static void
metrics_set_check(struct metrics_node *node)
{
    struct metrics_set *set = metrics_node_cast(node);
    size_t i;

    ovs_assert(set->read != NULL);
    for (i = 0; i < set->n_entries; i++) {
        metrics_set_check_entry(&set->entries[i]);
    }
}

void
metrics_set_read_one(double *values OVS_UNUSED,
                     void *it OVS_UNUSED)
{
    /* This is a dummy function serving as a placeholder. */
}

static void
metrics_set_read_values(struct metrics_node *node,
                        struct metrics_visitor_context *ctx OVS_UNUSED,
                        double *values)
{
    struct metrics_set *set = metrics_node_cast(node);
    size_t i;

    if (set->read == metrics_set_read_one) {
        for (i = 0; i < set->n_entries; i++) {
            values[i] = 1.;
        }
    } else {
        set->read(values, ctx->it);
    }
}

static void
metrics_set_format_values(struct metrics_node *node,
                          struct metrics_visitor_context *ctx,
                          double *values)
{
    struct metrics_set *set = metrics_node_cast(node);
    struct format_aux *aux = ctx->ops_aux;
    struct metrics_header *hdr;
    size_t i;

    for (i = 0; i < set->n_entries; i++) {
        hdr = metrics_header_find(aux, node, &set->entries[i]);
        metrics_header_add_line(hdr, NULL, ctx, values[i]);
    }
}

struct metrics_class metrics_class_set = {
    .init = NULL,
    .size = metrics_set_size,
    .n_values = metrics_set_n_values,
    .check = metrics_set_check,
    .read_values = metrics_set_read_values,
    .format_values = metrics_set_format_values,
};
