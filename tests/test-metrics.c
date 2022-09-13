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

#undef NDEBUG
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <math.h>

#include <config.h>

#include "command-line.h"
#include "metrics.h"
#include "metrics-private.h"
#include "openvswitch/vlog.h"
#include "openvswitch/util.h"
#include "ovs-thread.h"
#include "ovs-rcu.h"
#include "ovstest.h"
#include "random.h"
#include "timeval.h"
#include "util.h"

METRICS_SUBSYSTEM(test);

enum TEST_METRICS_NAMES {
    M, N, O, P, NAME,
};

static void
flat_entries_read_value(double *values)
{
    values[M] = 42;
    values[N] = 24.48;
    values[O] = 0xbaadfeed;
    values[P] = 3.14;
    values[NAME] = 1.0;
}

METRICS_ENTRIES(test, flat_entries,
    "flat", flat_entries_read_value,
    [M] = METRICS_COUNTER(m, "Count the number of m"),
    [N] = METRICS_COUNTER(n, "Count the number of n"),
    [O] = METRICS_GAUGE(o, "Gauge the number of o"),
    [P] = METRICS_GAUGE(p, "Gauge the number of p"),
    [NAME] = METRICS_GAUGE(, "A 'header' entry with the set name."),
);

static struct histogram *
linear_histogram_get(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static struct histogram hist;
    size_t i;

    if (ovsthread_once_start(&once)) {
        histogram_walls_set_lin(&hist, UINT32_MAX / 32, UINT32_MAX / 8);
        for (i = 0; i < 1ULL << 20; i++) {
            histogram_add_sample(&hist, random_uint32());
        }
        ovsthread_once_done(&once);
    }
    return &hist;
}

METRICS_HISTOGRAM(test, linear_histogram,
    "A basic linear histogram", linear_histogram_get);

static void
metrics_test_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    uint64_t n_values;
    size_t size;

    metrics_init();

    METRICS_REGISTER(flat_entries);
    METRICS_REGISTER(linear_histogram);

    /* Sanity checks. */
    metrics_tree_check();

    /* Read and output the test metrics. */
    metrics_values_format(&s);
    printf("%s", ds_cstr(&s));
    ds_destroy(&s);

    n_values = metrics_values_count();
    size = metrics_tree_size();

    printf("Got %ld metrics values to read\n", n_values);
    printf("Got %"PRIuSIZE" bytes of payload described in %" PRIuSIZE
           " bytes of framework.\n",
           n_values * sizeof(uint64_t), size);
    printf("Efficiency: %.2lf%%\n",
           (double) (n_values * sizeof(uint64_t)) /
           (double) (size) * 100.0);
}

OVSTEST_REGISTER("test-metrics", metrics_test_main);
