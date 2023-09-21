/*
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef REFMAP_H
#define REFMAP_H

#include <config.h>

#include <stddef.h>
#include <stdint.h>

#include "openvswitch/dynamic-string.h"

/*
 * Reference map
 * =============
 *
 * This key-value store acts like a regular concurrent hashmap,
 * except that insertion takes a reference on the value if already
 * present.
 *
 * As the value creation is dependent on it being already present
 * within the structure and the user cannot predict that, this structure
 * requires definitions for value_init and value_uninit functions,
 * that will be called only at creation (first reference taken) and
 * destruction (last reference released).
 *
 * Thread safety
 * =============
 *
 * MT-unsafe:
 *   * refmap_create
 *   * refmap_destroy
 *
 * MT-safe:
 *   * refmap_for_each
 *   * refmap_ref
 *   * refmap_ref_value
 *   * refmap_try_ref
 *   * refmap_unref
 *
 */

struct refmap;

/* Called once on a newly created 'value', i.e. when the first
 * reference is taken. */
typedef int (*refmap_value_init)(void *value, void *arg);

/* Called once on the last dereference to value. */
typedef void (*refmap_value_uninit)(void *value);

/* Format a (key, value, arg) tuple in 's'. */
typedef struct ds *(*refmap_value_format)(struct ds *s, void *key,
                                          void *value, void *arg);

/* Allocate and return a map handle.
 *
 * The user must ensure that the 'key' type (of which 'key_size' is the size)
 * does not contain padding. The macros 'OVS_PACKED' or 'OVS_ASSERT_PACKED'
 * (if one does not want a packed struct) can be used to enforce this property.
 */
struct refmap *refmap_create(const char *name,
                             size_t key_size,
                             size_t value_size,
                             refmap_value_init value_init,
                             refmap_value_uninit value_uninit,
                             refmap_value_format value_format);

/* Frees the map memory. */
void refmap_destroy(struct refmap *rfm);

/* refmap_try_ref takes a reference for the found value upon success. It's the
 * user's responsibility to unref it. */
void *refmap_try_ref(struct refmap *rfm, void *key);
void *refmap_ref(struct refmap *rfm, void *key, void *arg);
bool refmap_ref_value(struct refmap *rfm, void *value, bool safe);
void refmap_for_each(struct refmap *rfm,
                     void (*cb)(void *value, void *key, void *arg),
                     void *arg);
void *refmap_key_from_value(struct refmap *rfm, void *value);

/* Return 'true' if it was the last 'value' dereference and
 * 'value_uninit' has been called. */
bool refmap_unref(struct refmap *rfm, void *value);

unsigned int
refmap_value_refcount_read(struct refmap *rfm, void *value);

#endif /* REFMAP_H */
