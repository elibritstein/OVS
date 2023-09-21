/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
 * The key provided must be fully initialized, including potential pad bytes.
 *
 * As the value creation is dependent on it being already present
 * within the structure and the user cannot predict that, this structure
 * requires definitions for value_init and value_uninit functions,
 * that will be called only at creation (first reference taken) and
 * destruction (last reference released).
 *
 * Example:
 * 1. struct key key;
 * 2. memset(&key, 0, sizeof key);
 * 3. refmap_create()
 * 4. value = refmap_ref(key);
 *    Since it's the first reference for <key>, value_init is called.
 * 5. refmap_ref(key);
 *    This is not the first reference for <key>. Only ref-count is updated.
 * 6. refmap_unref(value);
 *    This is not the last reference released. Only ref-count is updated.
 * 7. refmap_unref(value);
 *    This is the last reference released. value_uninit is immediatelly
 *    called, while the value memory is freed after RCU grace period.
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
 *   * refmap_try_ref
 *   * refmap_try_ref_value
 *   * refmap_unref
 *
 */

struct refmap;

/* Called once on a newly created 'value', i.e. when the first
 * reference is taken. */
typedef int (*refmap_value_init)(void *value, void *arg);

/* Called once on the last dereference to value. */
typedef void (*refmap_value_uninit)(void *value);

/* Format a (key, value, arg) tuple in 's'. This is an optional (can be NULL)
 * callback, used for debug log purposes.
 */
typedef struct ds *(*refmap_value_format)(struct ds *s, void *key,
                                          void *value);

/* Allocate and return a map handle.
 *
 * The user must ensure the 'key' is fully initialized, including potential
 * pad bytes.
 */
struct refmap *refmap_create(const char *name,
                             size_t key_size,
                             size_t value_size,
                             refmap_value_init value_init,
                             refmap_value_uninit value_uninit,
                             refmap_value_format value_format);

/* Frees the map memory.
 *
 * The client is responsible for unreferencing any data previously held in
 * the map. */
void refmap_destroy(struct refmap *rfm);

/* refmap_try_ref takes a reference for the found value upon success.
 * It's the user's responsibility to unref it. */
void *refmap_try_ref(struct refmap *rfm, void *key);
void *refmap_ref(struct refmap *rfm, void *key, void *arg);
bool refmap_try_ref_value(struct refmap *rfm, void *value);
void refmap_for_each(struct refmap *rfm,
                     void (*cb)(void *value, void *key, void *arg),
                     void *arg);
/* The refmap_value_refcount_read() API requires the caller to hold a
 * reference, so a returned value of 1 only indicates you were the sole owner
 * at the moment of the read, but may no longer be by the time you receive the
 * value.  This makes it unsuitable for logic decisions and only useful for
 * debug logging.
 */
void *refmap_key_from_value(struct refmap *rfm, void *value);

/* Return 'true' if it was the last 'value' dereference and
 * 'value_uninit' has been called. */
bool refmap_unref(struct refmap *rfm, void *value);

unsigned int
refmap_value_refcount_read(struct refmap *rfm, void *value);

#endif /* REFMAP_H */
