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

static const struct metrics_label *
metrics_visitor_last_label(struct metrics_visitor_context *ctx)
{
    size_t n = ctx->labels.n_arrays;

    return n > 0 ? ctx->labels.stack[n - 1].labels : NULL;
}

static struct metrics_add_label *
find_child_label(struct metrics_collection *coll)
{
    struct metrics_node *child;

    /* the 'add-label' node of a 'collection' node is its immediate
     * first child. */
    LIST_FOR_EACH (child, siblings, &coll->node.children) {
        ovs_assert(child->type == METRICS_NODE_TYPE_LABEL);
        return metrics_node_cast(child);
    }
    OVS_NOT_REACHED();
    return NULL;
}

static struct metrics_node *
metrics_iterator_last_it(struct metrics_visitor_context *ctx)
{
    size_t n = ctx->iterators.n_its;

    return n > 0 ? ctx->iterators.stack[n - 1].handle : NULL;
}

static struct metrics_node *
metrics_iterator_last_node(struct metrics_visitor_context *ctx)
{
    size_t n = ctx->iterators.n_its;

    return n > 0 ? ctx->iterators.stack[n - 1].node : NULL;
}

static void
metrics_iterator_push(struct metrics_visitor_context *ctx,
                      struct metrics_node *src,
                      void *it)
{
    size_t n = ctx->iterators.n_its;

    /* Need to update current stored top 'it' to latest value. */
    if (metrics_iterator_last_node(ctx) == src &&
        metrics_iterator_last_it(ctx) != it) {
        ctx->iterators.stack[n - 1].handle = it;
        return;
    }

    /* The top 'it' already has the correct info, nothing to do. */
    if (metrics_iterator_last_it(ctx) == it) {
        return;
    }

    /* Allocate a new frame with its own (node,it) tuple. */

    if (n == ctx->iterators.capacity) {
        ctx->iterators.stack = x2nrealloc(ctx->iterators.stack,
                                          &ctx->iterators.capacity,
                                          sizeof(ctx->iterators.stack[0]));
    }
    ctx->iterators.stack[n].handle = it;
    ctx->iterators.stack[n].node = src;
    ctx->iterators.n_its++;
}

static void
metrics_iterator_pop(struct metrics_visitor_context *ctx)
{
    if (ctx->iterators.n_its == 0) {
        return;
    }
    ctx->iterators.n_its--;
    if (ctx->iterators.n_its == 0) {
        free(ctx->iterators.stack);
        ctx->iterators.stack = NULL;
        ctx->iterators.capacity = 0;
    }
    ctx->it = metrics_iterator_last_it(ctx);
}

/* Depth-First Search on the tree. */
void
metrics_visitor_dfs(struct metrics_visitor_context *ctx,
                    struct metrics_node *node)
{
    const struct metrics_label *last_labels = metrics_visitor_last_label(ctx);

    if (!ctx->inspect) {
        metrics_iterator_push(ctx, node, ctx->it);
    }

    if (node->type != METRICS_NODE_TYPE_COLLECTION ||
        metrics_iterator_last_node(ctx) != node) {
        ctx->ops(node, ctx);
    }

    if (!ctx->inspect &&
        node->type == METRICS_NODE_TYPE_COND) {
        struct metrics_cond *cond = metrics_node_cast(node);

        if (!cond->enabled(ctx->it)) {
            return;
        }
    }

    if (!ctx->inspect &&
        node->type == METRICS_NODE_TYPE_LABEL) {
        struct metrics_add_label *add_label = metrics_node_cast(node);
        struct metrics_label_array *array = &add_label->array;

        metrics_visitor_labels_push(ctx, array->labels, array->n_labels);
        if (add_label->set_value) {
            add_label->set_value(array->labels, array->n_labels, ctx->it);
        }
    }

    if (!ctx->inspect &&
        node->type == METRICS_NODE_TYPE_COLLECTION &&
        metrics_iterator_last_node(ctx) != node) {
        struct metrics_collection *coll = metrics_node_cast(node);
        struct metrics_add_label *add_label = find_child_label(coll);

        coll->iterate(metrics_visitor_dfs, ctx, node,
                      add_label->array.labels, add_label->array.n_labels);
        metrics_iterator_pop(ctx);
    } else {
        struct metrics_node *child;

        LIST_FOR_EACH (child, siblings, &node->children) {
            metrics_visitor_dfs(ctx, child);
        }
    }

    if (!ctx->inspect &&
        node->type == METRICS_NODE_TYPE_LABEL) {
        metrics_visitor_labels_pop(ctx);
    }

    ovs_assert("A callback did not properly clean the labels it pushed"
               && metrics_visitor_last_label(ctx) == last_labels);
}

void
metrics_visitor_labels_push(struct metrics_visitor_context *ctx,
                            struct metrics_label *labels,
                            size_t n_labels)
{
    size_t n = ctx->labels.n_arrays;

    if (n == ctx->labels.capacity) {
        ctx->labels.stack = x2nrealloc(ctx->labels.stack,
                                       &ctx->labels.capacity,
                                       sizeof(ctx->labels.stack[0]));
    }
    ctx->labels.stack[n].labels = labels;
    ctx->labels.stack[n].n_labels = n_labels;
    ctx->labels.n_arrays++;
}

void
metrics_visitor_labels_pop(struct metrics_visitor_context *ctx)
{
    if (ctx->labels.n_arrays == 0) {
        return;
    }
    ctx->labels.n_arrays--;
    if (ctx->labels.n_arrays == 0) {
        free(ctx->labels.stack);
        ctx->labels.stack = NULL;
        ctx->labels.capacity = 0;
    }
}

static bool
ds_contains_label(struct ds *s, const char *key)
{
    struct ds pattern = DS_EMPTY_INITIALIZER;
    bool found;

    ds_put_format(&pattern, "%s=", key);
    found = (strstr(ds_cstr(s), ds_cstr(&pattern)) != NULL);
    ds_destroy(&pattern);
    return found;
}

static void
metrics_visitor_labels_format(struct metrics_visitor_context *ctx,
                              struct ds *s)
{
    struct ds l = DS_EMPTY_INITIALIZER;
    size_t i;

    /* If there are any labels set,
     * start from the last and write each k:v pairs if the key is not already
     * present (the last label takes precedence). */

    for (i = ctx->labels.n_arrays; i > 0; i--) {
        struct metrics_label_array *array = &ctx->labels.stack[i - 1];
        size_t j;

        /* Assume no-one submitted labels where a key would be repeated.
         * If it happens, the first of the values only will be written. */
        for (j = 0; j < array->n_labels; j++) {
            const struct metrics_label *label = &array->labels[j];

            if (label->value == NULL ||
                label->value[0] == '\0') {
                continue;
            }
            if (ds_contains_label(&l, label->key)) {
                continue;
            }
            if (l.length > 0) {
                ds_put_cstr(&l, ",");
            }
            ds_put_format(&l, "%s=\"%s\"", label->key, label->value);
        }
    }

    if (l.length > 0) {
        ds_put_format(s, "{%s}", ds_cstr(&l));
    }

    ds_destroy(&l);
}

static size_t
metrics_node_generic_size(struct metrics_node *node)
{
    switch (node->type) {
    case METRICS_NODE_TYPE_SUBSYSTEM:
        return sizeof(struct metrics_subsystem);
    case METRICS_NODE_TYPE_COND:
        return sizeof(struct metrics_cond);
    case METRICS_NODE_TYPE_LABEL:
        return sizeof(struct metrics_add_label);
    case METRICS_NODE_TYPE_COLLECTION:
        return sizeof(struct metrics_collection);
    case METRICS_NODE_TYPE_SET:
        return sizeof(struct metrics_set);
    case METRICS_NODE_TYPE_HISTOGRAM:
        return sizeof(struct metrics_histogram);
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

static void
metrics_entry_name(struct metrics_node *node,
                   struct metrics_entry *entry,
                   struct ds *s)
{
    struct metrics_node *stack[METRICS_MAX_DEPTH];
    struct metrics_node *n;
    int head = -1;

    for (n = node; n != NULL; n = n->up) {
        if (n->display_name != NULL &&
            n->display_name[0] != '\0') {
            ovs_assert(head < METRICS_MAX_DEPTH);
            stack[++head] = n;
        }
    }

    while (head >= 0) {
        if (s->length > 0) {
            ds_put_char(s, '_');
        }
        ds_put_cstr(s, stack[head--]->display_name);
    }
    if (strlen(entry->name) > 0) {
        if (s->length > 0) {
            ds_put_char(s, '_');
        }
        ds_put_cstr(s, entry->name);
    }
}

static int
metrics_header_cmp(const void *a, const void *b)
{
    struct metrics_header **hdr1 = (void *) a;
    struct metrics_header **hdr2 = (void *) b;

    return strcmp(ds_cstr(&hdr1[0]->full_name),
                  ds_cstr(&hdr2[0]->full_name));
}

struct metrics_header *
metrics_header_create(struct format_aux *aux,
                      const char *full_name,
                      struct metrics_entry *entry)
{
    struct metrics_header *hdr;

    hdr = xcalloc(1, sizeof *hdr);
    ds_init(&hdr->full_name);
    ds_put_cstr(&hdr->full_name, full_name);
    hdr->entry = entry;
    ovs_list_init(&hdr->lines);

    if (aux->hdrs.n == aux->hdrs.capacity) {
        aux->hdrs.buf = x2nrealloc(aux->hdrs.buf,
                                   &aux->hdrs.capacity,
                                   sizeof(aux->hdrs.buf[0]));
    }
    aux->hdrs.buf[aux->hdrs.n++] = hdr;

    qsort(aux->hdrs.buf, aux->hdrs.n,
          sizeof aux->hdrs.buf[0],
          metrics_header_cmp);

    return hdr;
}

struct metrics_header *
metrics_header_find(struct format_aux *aux,
                    struct metrics_node *node,
                    struct metrics_entry *entry)
{
    struct metrics_header hdr_s = {
        .full_name = DS_EMPTY_INITIALIZER,
        .entry = entry,
    }, *hdr = &hdr_s, **lookup;

    metrics_entry_name(node, entry, &hdr_s.full_name);
    lookup = bsearch(&hdr, aux->hdrs.buf, aux->hdrs.n,
                     sizeof aux->hdrs.buf[0],
                     metrics_header_cmp);

    if (lookup == NULL) {
        hdr = metrics_header_create(aux,
                                    ds_cstr(&hdr_s.full_name),
                                    entry);
    } else {
        hdr = *lookup;
    }
    ds_destroy(&hdr_s.full_name);

    return hdr;
}

void
metrics_header_add_line(struct metrics_header *hdr,
                        const char *prefix,
                        struct metrics_visitor_context *ctx,
                        double value)
{
    /* If possible, do not format the values using the exponent
     * form, as it will lose information.
     * The full mantissa is at most 53 bits,
     *   log(2**53) ~= 16
     */
    struct metrics_line *line;

    line = xcalloc(1, sizeof *line);

    ds_init(&line->s);
    if (prefix) {
        ds_put_cstr(&line->s, prefix);
    }
    metrics_visitor_labels_format(ctx, &line->s);
    /* Request FP-formatting as integer up to 16 digits. */
    ds_put_format(&line->s, " %.16g\n", value);

    ovs_list_init(&line->next);
    ovs_list_push_back(&hdr->lines, &line->next);
}

void
metrics_node_format(struct metrics_node *node,
                    struct metrics_visitor_context *ctx)
{
    struct metrics_class *cls = metrics_ops(node);
    size_t n_values;
    double *values;

    if (cls->n_values == NULL ||
        cls->read_values == NULL ||
        cls->format_values == NULL) {
        /* Require all these ops available to proceed. */
        return;
    }

    n_values = cls->n_values(node);
    values = xmalloc(n_values * sizeof(values[0]));

    cls->read_values(node, ctx, values);
    cls->format_values(node, ctx, values);

    free(values);
}
