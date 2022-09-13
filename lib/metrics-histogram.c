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

#include <stdint.h>

#include "histogram.h"
#include "metrics.h"
#include "metrics-private.h"
#include "openvswitch/util.h"
#include "util.h"

unsigned int n_failed_histogram_reads;

static size_t
metrics_histogram_size(struct metrics_node *node OVS_UNUSED)
{
    return sizeof(struct metrics_histogram);
}

static size_t
metrics_histogram_n_values(struct metrics_node *node OVS_UNUSED)
{
    /* Each histogram buckets, plus the sum and count. */
    return HISTOGRAM_N_BINS + 2;
}

static void
metrics_histogram_check(struct metrics_node *node)
{
    struct metrics_histogram *hist = metrics_node_cast(node);

    ovs_assert(hist->get != NULL);
}

static void
metrics_histogram_read_values(struct metrics_node *node,
                              struct metrics_visitor_context *ctx OVS_UNUSED,
                              double *values)
{
    struct metrics_histogram *hist = metrics_node_cast(node);
    uint64_t buckets[HISTOGRAM_N_BINS] = {0};
    struct histogram *histogram;
    unsigned int n_read_retries = 10;
    uint64_t count = 0, sum = 0;
    size_t i;

    histogram = hist->get();
    /* Make sure we read a 'count' consistent with the buckets:
     * first load the buckets locally, then count them independently from
     * potential subsystem changes.
     */
    while (n_read_retries-- && sum != histogram->sum) {
        sum = histogram->sum;
        memcpy(buckets, histogram->bin, sizeof buckets);
    }
    if (sum != histogram->sum) {
        n_failed_histogram_reads++;
    }

    for (i = 0; i < HISTOGRAM_N_BINS; i++) {
        values[i] = count += buckets[i];
    }
    values[i++] = sum;
    values[i] = count;
}

static void
metrics_histogram_format_values(struct metrics_node *node,
                                struct metrics_visitor_context *ctx,
                                double *values)
{
    struct metrics_histogram *hist = metrics_node_cast(node);
    struct format_aux *aux = ctx->ops_aux;
    struct metrics_header *hdr;
    size_t i;

    hdr = metrics_header_find(aux, node, &hist->entry);

    for (i = 0; i < HISTOGRAM_N_BINS - 1; i++) {
        metrics_header_add_line(hdr, "_buckets", ctx, values[i]);
    }
    /* +Inf bucket */
    metrics_header_add_line(hdr, "_buckets", ctx, values[i++]);

    /* Sum field */
    metrics_header_add_line(hdr, "_sum", ctx, values[i++]);

    /* Count field */
    metrics_header_add_line(hdr, "_count", ctx, values[i++]);
}

struct metrics_class metrics_class_histogram = {
    .init = NULL,
    .size = metrics_histogram_size,
    .n_values = metrics_histogram_n_values,
    .check = metrics_histogram_check,
    .read_values = metrics_histogram_read_values,
    .format_values = metrics_histogram_format_values,
};
