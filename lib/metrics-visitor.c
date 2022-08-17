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
#include "openvswitch/dynamic-string.h"
#include "openvswitch/util.h"
#include "util.h"

/* Depth-First Search on the tree. */
void
metrics_visitor_dfs(struct metrics_visitor_context *ctx,
                    struct metrics_node *node)
{
    struct metrics_node *child;

    ctx->ops(node, ctx);

    LIST_FOR_EACH (child, siblings, &node->children) {
        metrics_visitor_dfs(ctx, child);
    }
}

static size_t
metrics_node_generic_size(struct metrics_node *node)
{
    switch (node->type) {
    case METRICS_NODE_TYPE_SUBSYSTEM:
        return sizeof(struct metrics_subsystem);
    case METRICS_NODE_TYPE_SET:
        return sizeof(struct metrics_set);
    case METRICS_N_NODE_TYPE:
        OVS_NOT_REACHED();
    }
    OVS_NOT_REACHED();
    return 0;
}

void
metrics_node_size(struct metrics_node *node,
                  struct metrics_visitor_context *ctx)
{
    size_t *total_size = ctx->ops_aux;

    *total_size += metrics_ops(node)->size
                    ? metrics_ops(node)->size(node)
                    : metrics_node_generic_size(node);
}

void
metrics_node_n_values(struct metrics_node *node,
                      struct metrics_visitor_context *ctx)
{
    uint64_t *count = ctx->ops_aux;

    *count += metrics_ops(node)->n_values
                    ? metrics_ops(node)->n_values(node)
                    : 0;
}

static void
metrics_node_generic_check(struct metrics_node *node)
{
    if (node == METRICS_ROOT) {
        return;
    }
    /* No node should be isolated / orphan. */
    ovs_assert(node->up != NULL);
    /* All nodes should have an internal name. */
    ovs_assert(node->name != NULL);
}

void
metrics_node_check(struct metrics_node *node,
                   struct metrics_visitor_context *ctx OVS_UNUSED)
{
    metrics_node_generic_check(node);
    if (metrics_ops(node)->check) {
        metrics_ops(node)->check(node);
    }
}
