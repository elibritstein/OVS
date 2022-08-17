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
#include "openvswitch/list.h"

enum metrics_node_type {
    METRICS_NODE_TYPE_SUBSYSTEM,
    METRICS_NODE_TYPE_SET,
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

struct metrics_visitor_context;
typedef void (*metrics_node_fn)(struct metrics_node *node,
                                struct metrics_visitor_context *ctx);

struct metrics_visitor_context {
    metrics_node_fn ops;
    void *ops_aux;
};

enum metrics_entry_type {
    METRICS_ENTRY_TYPE_GAUGE,
    METRICS_ENTRY_TYPE_COUNTER,
};

struct metrics_entry {
    const char *const name;
    const char *const help;
    enum metrics_entry_type type;
};

typedef void (*metrics_set_read)(double *values);

struct metrics_set {
    struct metrics_node node;
    metrics_set_read read;
    size_t n_entries;
    struct metrics_entry *entries;
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

/* Register metrics entries:
 * All entries (defined using 'METRICS_ENTRIES' above) must be manually
 * registered using the following macro. Not doing so means those
 * entries won't be reachable from the root, and they won't appear
 * in metrics reads.
 *
 * NAME (C identifier):
 *      Name of the registered node.
 *      For a metrics_set, it is the name of the whole set,
 *      not of an individual metric within.
 */
#define METRICS_REGISTER(NAME) metrics_register(METRICS_PTR(NAME));

METRICS_DECLARE(root);

void metrics_init(void);
void metrics_register(struct metrics_node *node);

#endif /* METRICS_H */
