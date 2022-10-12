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

#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>

#include "compiler.h"
#include "histogram.h"
#include "openvswitch/list.h"

enum metrics_node_type {
    METRICS_NODE_TYPE_SUBSYSTEM,
    METRICS_NODE_TYPE_COND,
    METRICS_NODE_TYPE_LABEL,
    METRICS_NODE_TYPE_COLLECTION,
    METRICS_NODE_TYPE_SET,
    METRICS_NODE_TYPE_HISTOGRAM,
    METRICS_N_NODE_TYPE,
};

struct metrics_node {
    enum metrics_node_type type;
    const char *const name;
    const char *const display_name;
    struct metrics_node *up;
    struct ovs_list siblings;
    struct ovs_list children;
    void (*set_up)(void);
    bool init_done;
};

struct metrics_subsystem {
    struct metrics_node node;
};

typedef bool (*metrics_cond_enabled)(void *it);

struct metrics_cond {
    struct metrics_node node;
    metrics_cond_enabled enabled;
};

struct metrics_visitor_context;
typedef void (*metrics_node_fn)(struct metrics_node *node,
                                struct metrics_visitor_context *ctx);

struct metrics_label {
    const char *key;
    const char *value;
};

typedef void (*metrics_label_set_value)(struct metrics_label *labels,
                                        size_t n, void *it);

struct metrics_label_array {
    struct metrics_label *labels;
    size_t n_labels;
};

struct metrics_add_label {
    struct metrics_node node;
    metrics_label_set_value set_value;
    struct metrics_label_array array;
    const char **keys;
};

struct metrics_iterator_frame {
    void *handle; /* The iterator handle. */
    struct metrics_node *node; /* The metrics node that set the handle. */
};

struct metrics_visitor_context {
    metrics_node_fn ops;
    void *ops_aux;
    void *it; /* Current 'active' iterator. */
    bool inspect; /* Run the visitor to 'inspect' the tree:
                   * callbacks are not executed, the tree is fully visited. */
    struct {
        struct metrics_iterator_frame *stack;
        size_t capacity;
        size_t n_its;
    } iterators;
    struct {
        struct metrics_label_array *stack;
        size_t capacity;
        size_t n_arrays;
    } labels;
};

typedef void (*metrics_visitor_fn)(struct metrics_visitor_context *ctx,
                                   struct metrics_node *node);

typedef void (*metrics_collection_iterate)(metrics_visitor_fn visitor,
                                           struct metrics_visitor_context *ctx,
                                           struct metrics_node *node,
                                           struct metrics_label *labels,
                                           size_t n_labels);

struct metrics_collection {
    struct metrics_node node;
    metrics_collection_iterate iterate;
};

enum metrics_entry_type {
    METRICS_ENTRY_TYPE_GAUGE,
    METRICS_ENTRY_TYPE_COUNTER,
    METRICS_ENTRY_TYPE_HISTOGRAM,
};

struct metrics_entry {
    const char *const name;
    const char *const help;
    enum metrics_entry_type type;
};

typedef void (*metrics_set_read)(double *values, void *it);

struct metrics_set {
    struct metrics_node node;
    metrics_set_read read;
    size_t n_entries;
    struct metrics_entry *entries;
};

typedef struct histogram *(*metrics_histogram_get_fn)(void *it);

struct metrics_histogram {
    struct metrics_node node;
    struct metrics_entry entry;
    metrics_histogram_get_fn get;
};

#define METRICS(NAME) metrics_node_##NAME
#define METRICS_REF(NAME) (&METRICS(NAME).node)
#define METRICS_PTR(NAME) METRICS(NAME##_ptr)
#define METRICS_DEFINE(NAME) \
    struct metrics_node *METRICS_PTR(NAME) = METRICS_REF(NAME)

/* Expose a metrics node to other translation units.
 * TYPE (C tag):
 *      C type of the exposed metrics struct.
 * NAME (C identifier):
 *      Exposed metrics node name to be referenced
 *      as 'UP' by linked metrics.
 */
#define METRICS_DECLARE(NAME) \
    extern struct metrics_node *METRICS_PTR(NAME)

#define METRICS_INIT(NAME) METRICS(NAME##_init)
#define METRICS_DECLARE_INIT(NAME) \
    void METRICS_INIT(NAME)(void);
#define METRICS_DEFINE_INIT(UP, NAME) \
    METRICS_DEFINE(NAME); \
    void METRICS_INIT(NAME)(void) { \
        METRICS_REF(NAME)->set_up = NULL; \
        METRICS_REF(NAME)->up = METRICS_PTR(UP); \
    }

#define METRICS_NODE_(NAME, DISPLAY_NAME, TYPE) \
    { \
        .name = #NAME, \
        .display_name = DISPLAY_NAME, \
        .type = METRICS_NODE_TYPE_##TYPE, \
        .set_up = METRICS_INIT(NAME), \
    }

#define METRICS_ENTRY_(NAME, HELP, TYPE) \
    { \
        .name = #NAME, \
        .help = HELP, \
        .type = METRICS_ENTRY_TYPE_##TYPE, \
    }

/**************************************
 *           User interface           *
 **************************************/

/* Subsystem:
 * This node is the root of the metrics in a system or module.
 * It is the entry-point used by the metrics framework to visit
 * that system metrics node.
 *
 * NAME (C identifier):
 *      The name of the subsystem. Will be displayed in telemetry.
 */
#define METRICS_SUBSYSTEM(NAME) \
    METRICS_DECLARE_INIT(NAME); \
    static struct metrics_subsystem METRICS(NAME) = { \
        .node = METRICS_NODE_(NAME, NULL, SUBSYSTEM) \
    }; \
    METRICS_DEFINE_INIT(root, NAME);

/* Conditional:
 * This node is used to introduce conditional access to its sub-nodes.
 * A callback is required of type 'metrics_cond_enabled'. If this
 * callback returns 'false' the current operation on the tree will
 * not proceed to this node's children.
 *
 * This is used to disable some metrics if their subsystem is currently
 * disabled (e.g. hardware offloads).
 *
 * UP (C identifier):
 *      Parent metrics node.
 * NAME (C identifier):
 *      Name of this node.
 * ENABLED_CB (metrics_cond_enabled):
 *      Callback to determine if the tree operation should proceed.
 */
#define METRICS_COND(UP, NAME, ENABLED_CB) \
    METRICS_DECLARE_INIT(NAME); \
    static struct metrics_cond METRICS(NAME) = { \
        .node = METRICS_NODE_(NAME, NULL, COND), \
        .enabled = ENABLED_CB, \
    }; \
    METRICS_DEFINE_INIT(UP, NAME);

/* Label:
 * This node allows setting a variable number of metrics_label.
 * Those will be applied to all metrics having this node in its
 * path.
 *
 * The labels are passed as a list of keys. Then, the callback
 * of type 'metrics_label_set_value' provided is executed
 * when the node is visited, that must set each values.
 * The labels will be applied only on the sub-tree starting
 * from this node.
 *
 * UP (C identifier):
 *      Parent metrics node.
 * NAME (C identifier):
 *      Name of this node.
 * SET_VALUE_CB (metrics_label_set_value):
 *      Callback setting each label value when executed.
 * [...] (const char[]):
 *      A variadic list of label keys.
 */
#define METRICS_LABEL(UP, NAME, SET_VALUE_CB, ...) \
    static const char *METRICS(NAME##_keys)[] = { \
        __VA_ARGS__ \
    }; \
    static struct metrics_label METRICS(NAME##_label_array) \
        [ARRAY_SIZE(METRICS(NAME##_keys))]; \
    METRICS_DECLARE_INIT(NAME); \
    static struct metrics_add_label METRICS(NAME) = { \
        .node = METRICS_NODE_(NAME, NULL, LABEL), \
        .set_value = SET_VALUE_CB, \
        .array.labels = METRICS(NAME##_label_array), \
        .array.n_labels = ARRAY_SIZE(METRICS(NAME##_label_array)), \
        .keys = METRICS(NAME##_keys), \
    }; \
    METRICS_DEFINE_INIT(UP, NAME);

/* Collection:
 * This node is used to demultiply the current tree operation
 * on each of its children, following the iteration pattern executed
 * in its callback of type 'metrics_collection_iterate'.
 *
 * For example, when multiple interfaces exist in a datapath, each
 * of them have their own metrics (rx_packets, tx_packets, etc.).
 * Putting a 'collection' node above the interface metrics allows
 * visiting their metrics sub-tree once per instance.
 *
 * Each instance of the iteration must be labeled for the telemetry.
 * A variadic list of label keys are given in parameters. The resulting
 * 'metrics_label' struct are given as parameters of the 'iterate' callback.
 * For each iteration, their 'value' field must be set. The pointed
 * string must be valid memory during the execution of the visitor
 * function called.
 *
 * UP (C identifier):
 *      Parent metrics node.
 * NAME (C identifier):
 *      Name of this node.
 * ITERATE_CB (metrics_collection_iterate):
 *      Callback executing the iteration. This function takes
 *      a visitor function of type 'metrics_visitor_fn' as parameter,
 *      and must call this function once for each iteration it
 *      executes.
 * [...] (const char[]):
 *      A variadic list of label keys.
 */
#define METRICS_COLLECTION(UP, NAME, ITERATE_CB, ...) \
    METRICS_DECLARE_INIT(NAME##_coll); \
    static struct metrics_collection METRICS(NAME##_coll) = { \
        .node = METRICS_NODE_(NAME##_coll, NULL, COLLECTION), \
        .iterate = ITERATE_CB, \
    }; \
    METRICS_DEFINE_INIT(UP, NAME##_coll); \
    METRICS_LABEL(NAME##_coll, NAME, NULL, __VA_ARGS__)

/* Entries:
 * This node describes a set of entries. It is bound to a parent node 'UP'.
 * A callback must be provided of type 'metrics_set_read', that
 * will set the current value for each of the entries described in this
 * set when called.
 *
 * UP (C identifier):
 *      Parent metrics node.
 * NAME (C identifier):
 *      Name of this node.
 * DISPLAY_NAME (const char[]):
 *      Name of this section in telemetry.
 * READ_FN (metrics_set_read):
 *      Callback to read each listed entries.
 * [...] (const struct metrics_entry):
 *      A variadic list of metrics entries. These can be
 *        - METRICS_COUNTER
 *        - METRICS_GAUGE
 */
#define METRICS_ENTRIES(UP, NAME, DISPLAY_NAME, READ_FN, ...) \
    static struct metrics_entry METRICS(NAME##_entries)[] = { \
        __VA_ARGS__ \
    }; \
    METRICS_DECLARE_INIT(NAME); \
    static struct metrics_set METRICS(NAME) = { \
        .node = METRICS_NODE_(NAME, DISPLAY_NAME, SET), \
        .read = READ_FN, \
        .n_entries = ARRAY_SIZE(METRICS(NAME##_entries)), \
        .entries = METRICS(NAME##_entries), \
    }; \
    METRICS_DEFINE_INIT(UP, NAME);

/* Counter:
 * A counter describes a value that can only grow.
 * This macro must be used within a 'METRICS_ENTRIES' parameter list.
 *
 * NAME (const char[]):
 *      The name displayed in telemetry.
 * HELP (const char[]):
 *      Help string sent along with the name and current value.
 */
#define METRICS_COUNTER(NAME, HELP) \
    METRICS_ENTRY_(NAME, HELP, COUNTER)

/* Gauge:
 * A gauge describes a value that can go up and down.
 * This macro must be used within a 'METRICS_ENTRIES' parameter list.
 *
 * NAME (const char[]):
 *      The name displayed in telemetry.
 * HELP (const char[]):
 *      Help string sent along with the name and current value.
 */
#define METRICS_GAUGE(NAME, HELP) \
    METRICS_ENTRY_(NAME, HELP, GAUGE)

/* Histogram:
 * A histogram measures a distribution of samples across
 * several buckets. Each buckets will count the number of
 * occurences of each samples valued less-than or equal
 * to that bucket limit.
 *
 * The metrics_histogram node is backed by the 'histogram'
 * type available as a module.
 *
 * A histogram should be cumulative, each buckets matching
 * the sample value being incremented. To accelerate operations,
 * the 'histogram' type only writes to the highest matching
 * bucket.
 *
 * When the values are read, they are accumulated across buckets,
 * so the telemetry output generated from this metrics node
 * will respect the expected behavior of histograms.
 * i.e. its last bucket will be valued exactly to the total
 * number of samples measured.
 *
 * UP (C identifier):
 *      Parent metrics node.
 * NAME (C identifier):
 *      Name of this node. This name is also used
 *      externally in telemetry and must remain stable.
 * HELP (const char[]):
 *      Help string sent along with the name and current value.
 * GET_FN (metrics_histogram_get_fn):
 *      Callback to access the underlying histogram.
 */
#define METRICS_HISTOGRAM(UP, NAME, HELP, GET_FN) \
    METRICS_DECLARE_INIT(NAME); \
    static struct metrics_histogram METRICS(NAME) = { \
        .node = METRICS_NODE_(NAME, NULL, HISTOGRAM), \
        .entry = METRICS_ENTRY_(NAME, HELP, HISTOGRAM), \
        .get = GET_FN, \
    }; \
    METRICS_DEFINE_INIT(UP, NAME);

/* Register metrics entries:
 * All entries (defined using 'METRICS_ENTRIES' or 'METRICS_HISTOGRAM')
 * must be manually registered using the following macro.
 * Not doing so means those entries won't be reachable from the root,
 * and they won't appear in metrics reads.
 *
 * NAME (C identifier):
 *      Name of the registered node.
 *      For a metrics_set, it is the name of the whole set,
 *      not of an individual metric within.
 */
#define METRICS_REGISTER(NAME) metrics_register(METRICS_PTR(NAME));

METRICS_DECLARE(root);

void metrics_set_read_one(double *values, void *it);
void metrics_init(void);
void metrics_register(struct metrics_node *node);

/* Register metrics unixctl commands.
 *
 * The 'metrics_root_name' parameters, if set, overrides the
 * metrics root name. Metrics output will use the overridden
 * name as prefix to all metrics objects.
 *
 * Several processed can thus link to the metrics lib and
 * be differentiated by metrics consumers. */
void metrics_unixctl_register(const char *metrics_root_name);

/* Helpers available for 'METRICS_COND' that will
 * report whether the current metrics access requested
 * the extended and/or debug entries. */
bool metrics_ext_enabled(void *it);
bool metrics_dbg_enabled(void *it);

/* Some OVS generic stats functions expects a provider to fill
 * with 0xfffs the unused stats. Those are interpreted instead
 * as 'zero' for metrics purposes. Use this macro to cleanly
 * read those fields.
 */
#define MAX_IS_ZERO(v) \
    ((sizeof v == 1) ? (v == UINT8_MAX ? 0 : v) \
    :(sizeof v == 2) ? (v == UINT16_MAX ? 0 : v) \
    :(sizeof v == 4) ? (v == UINT32_MAX ? 0 : v) \
    :(sizeof v == 8) ? (v == UINT64_MAX ? 0 : v) \
    : 0)

#endif /* METRICS_H */
