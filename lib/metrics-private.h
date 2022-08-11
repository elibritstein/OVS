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

#ifndef METRICS_PRIVATE_H
#define METRICS_PRIVATE_H

#include "metrics.h"
#include "openvswitch/util.h"
#include "util.h"

#define METRICS_ROOT METRICS_PTR(root)

#define METRICS_MAX_DEPTH 20

static inline void *
metrics_node_cast(struct metrics_node *node)
{
    switch (node->type) {
    case METRICS_NODE_TYPE_SUBSYSTEM:
        return CONTAINER_OF(node, struct metrics_subsystem, node);
    case METRICS_NODE_TYPE_SET:
        return CONTAINER_OF(node, struct metrics_set, node);
    case METRICS_N_NODE_TYPE:
        OVS_NOT_REACHED();
    }
    OVS_NOT_REACHED();
    return NULL;
}

void metrics_root_set_name(const char *name);
void metrics_node_leaf_init(struct metrics_node *node);

struct metrics_class {
    void (*init)(struct metrics_node *node);
};
#define METRICS_CLASS_DEFAULT_INITIALIZER { \
    .init = NULL, \
}

extern struct metrics_class metrics_class_set;
extern struct metrics_class *metrics_classes[METRICS_N_NODE_TYPE];

static inline struct metrics_class *
metrics_ops(struct metrics_node *node)
{
    return metrics_classes[node->type];
}

#endif /* METRICS_PRIVATE_H */
