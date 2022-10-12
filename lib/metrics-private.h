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

#ifndef METRICS_PRIVATE_H
#define METRICS_PRIVATE_H

#include <stdbool.h>

#include "metrics.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/util.h"
#include "util.h"

#define METRICS_ROOT METRICS_PTR(root)

#define METRICS_MAX_DEPTH 20

extern unsigned int n_failed_histogram_reads;
extern bool metrics_show_extended;
extern bool metrics_show_debug;

static inline void *
metrics_node_cast(struct metrics_node *node)
{
    switch (node->type) {
    case METRICS_NODE_TYPE_SUBSYSTEM:
        return CONTAINER_OF(node, struct metrics_subsystem, node);
    case METRICS_NODE_TYPE_COND:
        return CONTAINER_OF(node, struct metrics_cond, node);
    case METRICS_NODE_TYPE_LABEL:
        return CONTAINER_OF(node, struct metrics_add_label, node);
    case METRICS_NODE_TYPE_COLLECTION:
        return CONTAINER_OF(node, struct metrics_collection, node);
    case METRICS_NODE_TYPE_SET:
        return CONTAINER_OF(node, struct metrics_set, node);
    case METRICS_NODE_TYPE_HISTOGRAM:
        return CONTAINER_OF(node, struct metrics_histogram, node);
    case METRICS_N_NODE_TYPE:
        OVS_NOT_REACHED();
    }
    OVS_NOT_REACHED();
    return NULL;
}

void metrics_root_set_name(const char *name);
void metrics_node_leaf_init(struct metrics_node *node);

struct metrics_class {
    void (*init)(struct metrics_node *node);
    size_t (*size)(struct metrics_node *node);
    size_t (*n_values)(struct metrics_node *node);
    void (*check)(struct metrics_node *node);
    void (*read_values)(struct metrics_node *node,
                        struct metrics_visitor_context *ctx,
                        double *values);
    void (*format_values)(struct metrics_node *node,
                          struct metrics_visitor_context *ctx,
                          double *values);
};
#define METRICS_CLASS_DEFAULT_INITIALIZER { \
    .init = NULL, .size = NULL, .n_values = NULL, .check = NULL, \
    .read_values = NULL, .format_values = NULL, \
}

extern struct metrics_class metrics_class_set;
extern struct metrics_class metrics_class_histogram;
extern struct metrics_class metrics_class_add_label;
extern struct metrics_class *metrics_classes[METRICS_N_NODE_TYPE];

static inline struct metrics_class *
metrics_ops(struct metrics_node *node)
{
    return metrics_classes[node->type];
}

unsigned int metrics_values_count(void);
size_t metrics_tree_size(void);
void metrics_tree_check(void);
void metrics_values_format(struct ds *s);

void metrics_visitor_dfs(struct metrics_visitor_context *ctx,
                         struct metrics_node *node);
void metrics_visitor_labels_push(struct metrics_visitor_context *ctx,
                                 struct metrics_label *labels,
                                 size_t n_labels);
void metrics_visitor_labels_pop(struct metrics_visitor_context *ctx);
void metrics_node_n_values(struct metrics_node *node,
                           struct metrics_visitor_context *ctx);
void metrics_node_size(struct metrics_node *node,
                       struct metrics_visitor_context *ctx);
void metrics_node_check(struct metrics_node *node,
                        struct metrics_visitor_context *ctx);

struct metrics_line {
    struct ovs_list next; /* next in 'lines'. */
    struct ds s; /* formatted value. */
};

/* Structure allowing access to
 *  - help string
 *  - entry type
 *  - entry full name
 * Several value may follow, linked
 * by the 'lines' head of list.
 */
struct metrics_header {
    struct metrics_entry *entry;
    struct ds full_name;
    struct ovs_list lines;
};

struct format_aux {
    struct {
        struct metrics_header **buf;
        size_t capacity;
        size_t n;
    } hdrs;
};

struct metrics_header *
metrics_header_create(struct format_aux *aux,
                      const char *full_name,
                      struct metrics_entry *entry);
struct metrics_header *
metrics_header_find(struct format_aux *aux,
                    struct metrics_node *node,
                    struct metrics_entry *entry);
void metrics_header_add_line(struct metrics_header *hdr,
                             const char *prefix,
                             struct metrics_visitor_context *ctx,
                             double value);
void metrics_node_format(struct metrics_node *node,
                         struct metrics_visitor_context *ctx);

#endif /* METRICS_PRIVATE_H */
