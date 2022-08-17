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
#include "openvswitch/util.h"
#include "ovstest.h"
#include "random.h"
#include "util.h"

#define FUZZ(v) { v == 0 ? 0 : v - 1, v, v == UINT32_MAX ? v : v + 1 }

static inline bool
fuzzy_eq(uint32_t v, uint32_t target)
{
    uint32_t bounds[3] = FUZZ(target);

    return (v == bounds[0]
         || v == bounds[1]
         || v == bounds[2]);
}

static inline bool eq(uint32_t v, uint32_t target){ return v == target; }

static inline bool
fuzzy_lt(uint32_t v, uint32_t target)
{
    uint32_t bounds[3] = FUZZ(target);
    return (v < bounds[0]);
}

static inline bool lt(uint32_t v, uint32_t target){ return v < target; }

static void
test_histogram_check(struct histogram *hist,
                     uint32_t min, uint32_t max,
                     bool fuzzy)
{
    enum { EQ, LT };
    bool (*ops[])(uint32_t, uint32_t) = {
        [EQ] = fuzzy ? fuzzy_eq : eq,
        [LT] = fuzzy ? fuzzy_lt : lt,
    };
    bool min_found = false, max_found = false;

    for (size_t i = 0; i < HISTOGRAM_N_BINS; i++) {
        if (ops[EQ](hist->wall[i], min)) {
            min_found = true;
        }
        if (hist->wall[i] == max) {
            max_found = true;
        }
    }
    ovs_assert(min_found);
    ovs_assert(max_found);
    for (size_t i = 0; i < HISTOGRAM_N_BINS - 1; i++) {
        if (ops[LT](hist->wall[i], min)) {
            ovs_abort(0, "A bucket is under the requested minimum. "
                    "For [%"PRIu32",%"PRIu32"]: "
                    "wall[%"PRIuSIZE"](%"PRIu32") < min(%"PRIu32")",
                    min, max, i, hist->wall[i], min);
        }
        if (hist->wall[i] > max) {
            ovs_abort(0, "A bucket is over the requested maximum. "
                    "For [%"PRIu32",%"PRIu32"]: "
                    "wall[%"PRIuSIZE"](%"PRIu32") > max(%"PRIu32")",
                    min, max, i, hist->wall[i], max);
        }
        if (hist->wall[i] >= hist->wall[i + 1]) {
            char res = hist->wall[i] > hist->wall[i + 1] ? '>' : '=';
            ovs_abort(0, "The histogram buckets are not strictly increasing.\n"
                    "For [%"PRIu32",%"PRIu32"]: "
                    "wall[%"PRIuSIZE"](%"PRIu32") %c "
                    "wall[%"PRIuSIZE"](%"PRIu32")",
                    min, max, i, hist->wall[i], res, i + 1, hist->wall[i + 1]);
        }
    }
}

static void
test_histogram_linear(uint32_t min, uint32_t max)
{
    struct histogram hist;

    memset(&hist, 0, sizeof hist);
    histogram_walls_set_lin(&hist, min, max);
    test_histogram_check(&hist, min, max, false);
}

static void
test_histogram_logarithmic(uint32_t min, uint32_t max)
{
    struct histogram hist;

    memset(&hist, 0, sizeof hist);
    histogram_walls_set_log(&hist, min, max);
    test_histogram_check(&hist, min, max, true);
}

static void
test_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum { LIN = 1, LOG = 2 };
    struct {
        uint32_t type;
        uint32_t min, max;
    } tcases[] = {
        /* Edge cases. */
        { LIN | LOG, 0, UINT32_MAX },
        { LIN | LOG, 1, UINT32_MAX },
        { LIN | LOG, 0, UINT32_MAX - 1 },
        { LIN | LOG, 1, UINT32_MAX - 1 },
        { LIN      , UINT32_MAX - (HISTOGRAM_N_BINS - 1), UINT32_MAX },
        { LIN      , UINT32_MAX - (HISTOGRAM_N_BINS - 1), UINT32_MAX - 1 },
        /* Congruent case with inc=1. */
        { LIN      , 5, 5 +  HISTOGRAM_N_BINS },
        /* Non-congruent case with inc<1. */
        { LIN      , 5, 5 + (HISTOGRAM_N_BINS - 1) },
        /* Non-congruent case with inc<1. */
        { LIN      , 5, 5 + (HISTOGRAM_N_BINS - 2) },
        { LIN | LOG, 0x88888888, 0x99999999 },
        { LIN | LOG, 2203470768, 2441348688 },
        { LIN | LOG, 1732474832, 2432533624 },
    };

    for (size_t i = 0; i < ARRAY_SIZE(tcases); i++) {
        if (tcases[i].type & LIN) {
            test_histogram_linear(tcases[i].min, tcases[i].max);
        }
    }

    for (size_t i = 0; i < ARRAY_SIZE(tcases); i++) {
        if (tcases[i].type & LOG) {
            test_histogram_logarithmic(tcases[i].min, tcases[i].max);
        }
    }
}

OVSTEST_REGISTER("test-histogram", test_main);
