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
                        struct metrics_visitor_context *ctx OVS_UNUSED,
                        double value)
{
    struct metrics_line *line;

    line = xcalloc(1, sizeof *line);

    ds_init(&line->s);
    if (prefix) {
        ds_put_cstr(&line->s, prefix);
    }
    ds_put_format(&line->s, " %.10g\n", value);

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
