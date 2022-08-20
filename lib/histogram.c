/*
 * Copyright (c) 2022 NVIDIA Corporation.
 * Copyright (c) 2017 Ericsson AB.
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
#include <math.h>

#include "histogram.h"
#include "openvswitch/util.h"
#include "util.h"

void
histogram_walls_set_lin(struct histogram *hist, uint32_t min, uint32_t max)
{
    uint32_t i, inc;

    ovs_assert(min < max);
    inc = (max - min) / (HISTOGRAM_N_BINS - 2);
    for (i = 0; i < HISTOGRAM_N_BINS - 1; i++) {
        hist->wall[i] = min + (i * inc);
    }
    if (max != UINT32_MAX) {
        hist->wall[HISTOGRAM_N_BINS - 2] = max;
    }
    hist->wall[HISTOGRAM_N_BINS - 1] = UINT32_MAX;
}

void
histogram_walls_set_log(struct histogram *hist, uint32_t min, uint32_t max)
{
    uint32_t i, start, bins, wall;
    double log_min, log_max;

    ovs_assert(min < max);
    if (min > 0) {
        log_min = log(min);
        log_max = log(max);
        start = 0;
        bins = HISTOGRAM_N_BINS - 1;
    } else {
        hist->wall[0] = 0;
        log_min = log(1);
        log_max = log(max);
        start = 1;
        bins = HISTOGRAM_N_BINS - 2;
    }
    wall = start;
    for (i = 0; i < bins; i++) {
        /* Make sure each wall is monotonically increasing. */
        wall = MAX(wall,
                   exp(log_min + (i * (log_max - log_min)) / (bins - 1)));
        hist->wall[start + i] = wall++;
    }
    if (hist->wall[HISTOGRAM_N_BINS - 2] < max && max != UINT32_MAX) {
        hist->wall[HISTOGRAM_N_BINS - 2] = max;
    }
    hist->wall[HISTOGRAM_N_BINS - 1] = UINT32_MAX;
}

uint64_t
histogram_samples(const struct histogram *hist)
{
    uint64_t samples = 0;

    for (int i = 0; i < HISTOGRAM_N_BINS; i++) {
        samples += hist->bin[i];
    }
    return samples;
}

void
histogram_clear(struct histogram *hist)
{
    int i;

    for (i = 0; i < HISTOGRAM_N_BINS; i++) {
        hist->bin[i] = 0;
    }
    hist->sum = 0;
}
