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

#include <stdio.h>
#include <stdint.h>

#include "metrics.h"
#include "metrics-private.h"
#include "openvswitch/util.h"
#include "ovs-thread.h"
#include "util.h"

static char metrics_root_name[64] = { "ovs" };
struct metrics_subsystem METRICS(root) = {
    .node = {
        .name = "[root]",
        .display_name = metrics_root_name,
    },
};
METRICS_DEFINE(root);

void
metrics_root_set_name(const char *name)
{
    snprintf(metrics_root_name, sizeof metrics_root_name,
             "%s", name);
}

static void
metrics_node_init(struct metrics_node *node)
{
    struct metrics_node *up = node->up;

    if (node->init_done) {
        return;
    }

    ovs_list_init(&node->siblings);
    ovs_list_init(&node->children);

    if (up != NULL) {
        ovs_list_push_back(&up->children, &node->siblings);
    }

    if (metrics_ops(node)->init) {
        metrics_ops(node)->init(node);
    }

    node->init_done = true;
}

void
metrics_init(void)
{
    struct metrics_node *root = METRICS_ROOT;

    if (!root->init_done) {
        metrics_node_init(root);
    }
}

void
metrics_register(struct metrics_node *node)
{
    struct metrics_node *stack[METRICS_MAX_DEPTH];
    struct metrics_node *n;
    int head = -1;

    ovs_assert("Only register 'METRICS_ENTRIES' using 'METRICS_REGISTER'." &&
               node->type == METRICS_NODE_TYPE_SET);

    /* The 'up' pointer must be set before executing
     * the node initialization. */
    if (node->set_up != NULL) {
        node->set_up();
    }

    /* Only register non-orphaned node:
     * they must all be reachable from the unique root. */
    ovs_assert(node->up != NULL);

    /* Initialize the dependency chain in proper order. */
    for (n = node->up; n != NULL; n = n->up) {
        ovs_assert(head < METRICS_MAX_DEPTH);
        if (n->set_up != NULL) {
            n->set_up();
        }
        if (!n->init_done) {
            stack[++head] = n;
        } else {
            break;
        }
    }

    while (head >= 0) {
        n = stack[head--];
        metrics_node_init(n);
    }

    metrics_node_init(node);
}

size_t
metrics_tree_size(void)
{
    size_t total_size = 0;
    struct metrics_visitor_context ctx = {
        .ops = metrics_node_size,
        .ops_aux = &total_size,
    };

    metrics_visitor_dfs(&ctx, METRICS_ROOT);
    return total_size;
}

unsigned int
metrics_values_count(void)
{
    unsigned int n_values = 0;
    struct metrics_visitor_context ctx = {
        .ops = metrics_node_n_values,
        .ops_aux = &n_values,
    };

    metrics_visitor_dfs(&ctx, METRICS_ROOT);
    return n_values;
}

void
metrics_tree_check(void)
{
    struct metrics_visitor_context ctx = {
        .ops = metrics_node_check,
    };

    /* Sanity checks. */
    metrics_visitor_dfs(&ctx, METRICS_ROOT);
}

struct metrics_class metrics_class_default = METRICS_CLASS_DEFAULT_INITIALIZER;
struct metrics_class *metrics_classes[METRICS_N_NODE_TYPE] = {
    [METRICS_NODE_TYPE_SUBSYSTEM] = &metrics_class_default,
    [METRICS_NODE_TYPE_SET] = &metrics_class_set,
};
