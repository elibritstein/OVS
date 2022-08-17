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

struct metrics_class metrics_class_histogram = {
    .init = NULL,
    .size = metrics_histogram_size,
    .n_values = metrics_histogram_n_values,
    .check = metrics_histogram_check,
};
