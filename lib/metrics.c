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
#include "timeval.h"
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

static void
metrics_register_metrics(void);
void
metrics_init(void)
{
    static bool registered = false;
    struct metrics_node *root = METRICS_ROOT;

    if (registered) {
        return;
    }
    registered = true;

    if (!root->init_done) {
        metrics_node_init(root);
    }
    metrics_register_metrics();
}

void
metrics_register(struct metrics_node *node)
{
    struct metrics_node *stack[METRICS_MAX_DEPTH];
    struct metrics_node *n;
    int head = -1;

    ovs_assert("Only register 'METRICS_ENTRIES' or 'METRICS_HISTOGRAM' "
               "using 'METRICS_REGISTER'." &&
               (node->type == METRICS_NODE_TYPE_SET ||
                node->type == METRICS_NODE_TYPE_HISTOGRAM));

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
        .inspect = true,
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
        .inspect = false,
    };

    metrics_visitor_dfs(&ctx, METRICS_ROOT);
    return n_values;
}

void
metrics_tree_check(void)
{
    struct metrics_visitor_context ctx = {
        .ops = metrics_node_check,
        .inspect = true,
    };

    /* Sanity checks. */
    metrics_visitor_dfs(&ctx, METRICS_ROOT);
}

static const char *metrics_type2txt[] = {
    [METRICS_ENTRY_TYPE_COUNTER] = "counter",
    [METRICS_ENTRY_TYPE_GAUGE] = "gauge",
    [METRICS_ENTRY_TYPE_HISTOGRAM] = "histogram",
};

static void
metrics_values_add_entry(struct format_aux *aux,
                         struct metrics_visitor_context *ctx,
                         struct metrics_entry *entry,
                         double value)
{
    struct ds full_name = DS_EMPTY_INITIALIZER;
    struct metrics_header *hdr;

    ds_put_format(&full_name, "%s_%s",
                  METRICS_ROOT->display_name, entry->name);
    hdr = metrics_header_create(aux, ds_cstr(&full_name),
                                entry);
    metrics_header_add_line(hdr, NULL, ctx, value);
    ds_destroy(&full_name);
}

void
metrics_values_format(struct ds *s)
{
    struct format_aux aux;
    struct metrics_visitor_context ctx = {
        .ops = metrics_node_format,
        .ops_aux = &aux,
    };
    struct metrics_entry latency =
        METRICS_GAUGE(metrics_query_latency,
                "Time elapsed to process this query in milliseconds.");
    long long int start;
    size_t i;

    start = time_msec();

    memset(&aux, 0, sizeof aux);
    metrics_visitor_dfs(&ctx, METRICS_ROOT);

    metrics_values_add_entry(&aux, &ctx, &latency,
                             time_msec() - start);

    for (i = 0; i < aux.hdrs.n; i++) {
        struct metrics_header *hdr = aux.hdrs.buf[i];
        struct metrics_entry *entry = hdr->entry;
        struct metrics_line *line;

        ds_put_format(s, "# HELP %s %s\n# TYPE %s %s\n",
                      ds_cstr(&hdr->full_name), entry->help,
                      ds_cstr(&hdr->full_name),
                      metrics_type2txt[entry->type]);

        LIST_FOR_EACH_SAFE (line, next, &hdr->lines) {
            ds_put_format(s, "%s%s",
                          ds_cstr(&hdr->full_name),
                          ds_cstr(&line->s));
            ds_destroy(&line->s);
            free(line);
        }

        ds_destroy(&hdr->full_name);
        free(hdr);
    }

    free(aux.hdrs.buf);
}

static void
metrics_add_label_init(struct metrics_node *node)
{
    struct metrics_add_label *add_label = metrics_node_cast(node);
    size_t i;

    for (i = 0; i < add_label->array.n_labels; i++) {
        add_label->array.labels[i].key = add_label->keys[i];
    }
}

bool
metrics_ext_enabled(void *it OVS_UNUSED)
{
    return metrics_show_extended;
}

bool
metrics_dbg_enabled(void *it OVS_UNUSED)
{
    return metrics_show_debug;
}

struct metrics_class metrics_class_add_label = {
    .init = metrics_add_label_init,
};

struct metrics_class metrics_class_default = METRICS_CLASS_DEFAULT_INITIALIZER;
struct metrics_class *metrics_classes[METRICS_N_NODE_TYPE] = {
    [METRICS_NODE_TYPE_SUBSYSTEM] = &metrics_class_default,
    [METRICS_NODE_TYPE_COND] = &metrics_class_default,
    [METRICS_NODE_TYPE_LABEL] = &metrics_class_add_label,
    [METRICS_NODE_TYPE_COLLECTION] = &metrics_class_default,
    [METRICS_NODE_TYPE_SET] = &metrics_class_set,
    [METRICS_NODE_TYPE_HISTOGRAM] = &metrics_class_histogram,
};

METRICS_SUBSYSTEM(metrics);

enum {
    METRICS_HIST_N_READ_ERRORS,
};

static void
metrics_entries_read_value(double *values, void *it OVS_UNUSED)
{
    values[METRICS_HIST_N_READ_ERRORS] = n_failed_histogram_reads;
}

METRICS_ENTRIES(metrics, metrics_entries,
    "metrics", metrics_entries_read_value,
    [METRICS_HIST_N_READ_ERRORS] = METRICS_COUNTER(histogram_n_read_errors,
        "Number of histogram reads that could not resolve without "
        "inconsistencies."),
);

static void
metrics_register_metrics(void)
{
    METRICS_REGISTER(metrics_entries);
}
