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

#ifndef HISTOGRAM_H
#define HISTOGRAM_H 1

#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Data structure to collect statistical distribution of an integer measurement
 * type in form of a histogram. The wall[] array contains the inclusive
 * upper boundaries of the bins, while the bin[] array contains the actual
 * counters per bin. The histogram walls are typically set automatically
 * using the functions provided below.*/

#define HISTOGRAM_N_BINS 32 /* Number of histogram bins. */

struct histogram {
    uint32_t wall[HISTOGRAM_N_BINS];
    uint64_t bin[HISTOGRAM_N_BINS];
    uint64_t sum;
};

static inline void
histogram_add_sample(struct histogram *hist, uint32_t val)
{
    hist->sum += val;
    /* TODO: Can do better with binary search? */
    for (int i = 0; i < HISTOGRAM_N_BINS - 1; i++) {
        if (val <= hist->wall[i]) {
            hist->bin[i]++;
            return;
        }
    }
    hist->bin[HISTOGRAM_N_BINS - 1]++;
}

void histogram_walls_set_lin(struct histogram *hist,
                             uint32_t min, uint32_t max);
void histogram_walls_set_log(struct histogram *hist,
                             uint32_t min, uint32_t max);
uint64_t histogram_samples(const struct histogram *hist);
void histogram_clear(struct histogram *hist);

#ifdef  __cplusplus
}
#endif

#endif /* HISTOGRAM_H */
