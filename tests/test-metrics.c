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
flat_entries_read_value(double *values,
                        void *it OVS_UNUSED)
{
    /* Test formatting of values up to 2**53: */
    /* This one should be written as integer. */
    values[M] = 9007199254740992.0;
    /* This one should be written in exponent form. */
    values[N] = 9007199254740992.0 * 2.0;
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
linear_histogram_get(void *it OVS_UNUSED)
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

static struct {
    uint64_t m, o;
    double n, p;
} objects[] = {
    [0] = {
        .m = 0xCAFED00D,
        .n = 2.17,
        .o = 0xBAADF00D,
        .p = 4.135667696,
    },
    [1] = {
        .m = 0xCAFED00D + 1,
        .n = 2.17 + 1,
        .o = 0xBAADF00D + 1,
        .p = 4.135667696 + 1,
    },
    [2] = {
        .m = 0xCAFED00D + 2,
        .n = 2.17 + 2,
        .o = 0xBAADF00D + 2,
        .p = 4.135667696 + 2,
    },
};

static void
do_foreach_objects(metrics_visitor_fn visitor,
                   struct metrics_visitor_context *ctx,
                   struct metrics_node *node,
                   struct metrics_label *labels,
                   size_t n OVS_UNUSED)
{
    char obj[64];
    size_t i;

    labels[0].value = obj;
    for (i = 0; i < ARRAY_SIZE(objects); i++) {
        snprintf(obj, sizeof obj, "%" PRIuSIZE, i);
        ctx->it = &i;
        visitor(ctx, node);
    }
}

static void
objects_read_value(double *values,
                   void *it)
{
    static unsigned int nb_obj_read = 0;
    size_t *iptr = it, i = *iptr;

    values[M] = objects[i].m;
    values[N] = objects[i].n;
    values[O] = objects[i].o;
    values[P] = objects[i].p;

    /* Number of time the objects were read. Should
     * be exactly the number of object iterations. */
    nb_obj_read++;
    ovs_assert(nb_obj_read <= ARRAY_SIZE(objects));
}

METRICS_COLLECTION(test, foreach_objects, do_foreach_objects, "obj");

METRICS_ENTRIES(foreach_objects, objects_entries,
    "objects", objects_read_value,
    [M] = METRICS_COUNTER(m, "Count the number of m in range of objects"),
    [N] = METRICS_COUNTER(n, "Count the number of n in range of objects"),
    [O] = METRICS_GAUGE(o, "Gauge the number of o in range of objects"),
    [P] = METRICS_GAUGE(p, "Gauge the number of p in range of objects"),
);

static bool enabled_cond_metrics_seen = false;
static bool
test_cond_metrics_true(void *it OVS_UNUSED)
{
    return true;
}
METRICS_COND(test, enabled_cond, test_cond_metrics_true);
static void
test_enabled_cond_read_value(double *values OVS_UNUSED,
                             void *it OVS_UNUSED)
{
    /* Verify we visit this node when the conditional is enabled. */
    enabled_cond_metrics_seen = true;
}
METRICS_ENTRIES(enabled_cond, trigger_enabled_cond_read, "",
    test_enabled_cond_read_value,
);

static bool
test_cond_metrics_false(void *it OVS_UNUSED)
{
    return false;
}
METRICS_COND(test, disabled_cond, test_cond_metrics_false);
static void
test_disabled_cond_read_value(double *values OVS_UNUSED,
                              void *it OVS_UNUSED)
{
    /* Verify we do not visit this node when the conditional is disabled. */
    OVS_NOT_REACHED();
}
METRICS_ENTRIES(disabled_cond, check_disabled_cond_read, "",
    test_disabled_cond_read_value,
);

static void
do_foreach_iface(metrics_visitor_fn visitor,
                 struct metrics_visitor_context *ctx,
                 struct metrics_node *node,
                 struct metrics_label *labels,
                 size_t n OVS_UNUSED)
{
    struct {
        const char *bridge;
        const char *interface;
        const char *port;
    } tuples[] = {
        {   .bridge = "br-int",
            .interface = "8bdd8bce8c7b306",
            .port = "default_ubuntu-bf2-veth-7b6456456c-4ldhw",
        },
        {   .bridge = "br-int",
            .interface = "br-int",
            .port = "br-int",
        },
        {   .bridge = "br-int",
            .interface = "ovn-k8s-mp0",
            .port = "k8s-k8s-worker1-bf",
        },
        {   .bridge = "br-int",
            .interface = "patch-br-int-to-brp0_k8s-worker1",
            .port = "patch-br-int-to-brp0_k8s-worker1",
        },
        {   .bridge = "br-int",
            .interface = "patch-br-int-to-brp0_k8s-worker1-bf",
            .port = "patch-br-int-to-brp0_k8s-worker1-bf",
        },
        {   .bridge = "brp0",
            .interface = "brp0",
            .port = "brp0",
        },
        {   .bridge = "brp0",
            .interface = "patch-brp0_k8s-worker1-bf-to-br-int",
            .port = "patch-brp0_k8s-worker1-bf-to-br-int",
        },
        {   .bridge = "brp0",
            .interface = "patch-brp0_k8s-worker1-to-br-int",
            .port = "patch-brp0_k8s-worker1-to-br-int",
        },
        {   .bridge = "brp0",
            .interface = "vtep0",
            .port = "vtep0",
        },
    };
    size_t i;

    for (i = 0; i < ARRAY_SIZE(tuples); i++) {
        labels[0].value = tuples[i].bridge;
        labels[1].value = tuples[i].interface;
        labels[2].value = tuples[i].port;
        ctx->it = &tuples[i];
        visitor(ctx, node);
    }
}

METRICS_COLLECTION(test, foreach_iface, do_foreach_iface,
                   "bridge", "interface", "port");
METRICS_ENTRIES(foreach_iface, iface_entries,
    "iface", metrics_set_read_one,
    METRICS_GAUGE(rx_errors, "Gauge reading a constant 1"),
);

static void
iface_set_label(struct metrics_label *labels,
                size_t n OVS_UNUSED,
                void *it OVS_UNUSED)
{
    static char name_value[64];

    labels[0].value = name_value;
    snprintf(name_value, sizeof name_value, "veth");
}

METRICS_LABEL(foreach_iface, iface_labels, iface_set_label, "name");
METRICS_ENTRIES(iface_labels, iface_driver_name,
    "iface", metrics_set_read_one,
    METRICS_GAUGE(driver_name,
        "A metric with a constant '1' value labeled by driver name "
        "that specifies the name of the device driver controlling the "
        "network interface"),
);

static void
do_foreach_nested_it_x(metrics_visitor_fn visitor,
                       struct metrics_visitor_context *ctx,
                       struct metrics_node *node,
                       struct metrics_label *labels,
                       size_t n OVS_UNUSED)
{
    static char x[64];
    int i;

    labels[0].value = x;
    ctx->it = &i;
    for (i = 0; i < 3; i++) {
        snprintf(x, sizeof x, "%d", i);
        ovs_assert(ctx->it == &i);
        visitor(ctx, node);
        ovs_assert(ctx->it == &i);
    }
}

METRICS_COLLECTION(test, foreach_nested_it_x,
    do_foreach_nested_it_x, "x");

static void
do_foreach_nested_it_y(metrics_visitor_fn visitor,
                       struct metrics_visitor_context *ctx,
                       struct metrics_node *node,
                       struct metrics_label *labels,
                       size_t n OVS_UNUSED)
{
    static char y[64];
    int i;

    labels[0].value = y;
    ctx->it = &i;
    for (i = 0; i < 3; i++) {
        snprintf(y, sizeof y, "%d", i);
        ovs_assert(ctx->it == &i);
        visitor(ctx, node);
        ovs_assert(ctx->it == &i);
    }
}

METRICS_COLLECTION(foreach_nested_it_x, foreach_nested_it_y,
    do_foreach_nested_it_y, "y");

METRICS_ENTRIES(foreach_nested_it_y, xy_entries, "nested_it",
    metrics_set_read_one,
    METRICS_GAUGE(, "Verify nested iteration correctness."),
);

static void
do_foreach_nested_it_z(metrics_visitor_fn visitor,
                       struct metrics_visitor_context *ctx,
                       struct metrics_node *node,
                       struct metrics_label *labels,
                       size_t n OVS_UNUSED)
{
    static char z[64];
    int i;

    labels[0].value = z;
    /* Verify nested iterations, this time with
     * the context iterator being set to NULL. */
    ctx->it = NULL;
    for (i = 0; i < 2; i++) {
        snprintf(z, sizeof z, "%d", i);
        ovs_assert(ctx->it == NULL);
        visitor(ctx, node);
        ovs_assert(ctx->it == NULL);
    }
}

METRICS_COLLECTION(foreach_nested_it_y, foreach_nested_it_z,
    do_foreach_nested_it_z, "z");

METRICS_ENTRIES(foreach_nested_it_z, xyz_entries, "nulled_nested_it",
    metrics_set_read_one,
    METRICS_GAUGE(, "Verify nested iteration correctness."),
);

static void
metrics_test_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    uint64_t n_values;
    size_t size;

    metrics_init();

    METRICS_REGISTER(flat_entries);
    METRICS_REGISTER(linear_histogram);
    METRICS_REGISTER(trigger_enabled_cond_read);
    METRICS_REGISTER(check_disabled_cond_read);
    METRICS_REGISTER(objects_entries);
    METRICS_REGISTER(iface_entries);
    METRICS_REGISTER(iface_driver_name);
    METRICS_REGISTER(xy_entries);
    METRICS_REGISTER(xyz_entries);

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
