/*
 * Copyright (c) 2023 NVIDIA Corporation.
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

#ifndef OFFLOAD_METADATA_H
#define OFFLOAD_METADATA_H

#include <config.h>

#include <stddef.h>
#include <stdint.h>

#include "openvswitch/dynamic-string.h"

/*
 * Offload metadata map
 * ====================
 *
 * This structure maps u32 ids to arbitrary metadata for offload
 * operations. The map allows lookups by id and lookup by data.
 *
 * Optionally, it is possible to request a deferred reclamation of
 * map entries. This deferral is not related to RCU but time-based.
 * If such option is used, a periodic upkeep function must be run
 * regularly, with a period shorter than the minimum requested deferral
 * latency.
 *
 * Thread safety
 * =============
 *
 * Concurrent operations are safe. At creation, the expected
 * number of user threads must be provided. All entries are shared
 * between all users, the maps are not partitioned.
 *
 * If deferred reclamation is used, all user threads must run the
 * upkeep function regularly, each with their unique user id.
 */

struct offload_metadata;

typedef uint32_t (*offload_metadata_id_alloc)(void);
typedef void (*offload_metadata_id_free)(uint32_t id);

/* Format a (data, priv, arg) tuple in 's'.
 * priv and arg *will* sometime be NULL. */
typedef struct ds *(*offload_metadata_data_format)(struct ds *s, void *data,
                                                   void *priv, void *arg);

/* Will be called on 'priv' each time a reference to data is
 * taken. Must be idempotent. */
typedef int (*offload_metadata_priv_init)(void *priv, void *priv_arg,
                                          uint32_t id);

/* Will be case on the last deref of a data node. Even if delayed_release
 * is set this will be called as soon as the last reference is removed.
 * It is possible that the associate data will be referenced again
 * before actual release, in which case 'priv_init' will be called again
 * and must work. */
typedef void (*offload_metadata_priv_uninit)(void *priv);

struct offload_metadata_parameters {
    offload_metadata_id_alloc id_alloc;
    offload_metadata_id_free id_free;
    size_t priv_size;
    offload_metadata_priv_init priv_init;
    offload_metadata_priv_uninit priv_uninit;
    long long int release_delay_ms;
    bool disable_map_shrink;
};

/* Allocate and return a map handle. */
struct offload_metadata *
offload_metadata_create(unsigned int nb_user,
                        const char *name,
                        size_t data_size,
                        offload_metadata_data_format data_format,
                        struct offload_metadata_parameters params);

/* Empties a map handle, execute all delayed reclamation,
 * free map memory. */
void offload_metadata_destroy(struct offload_metadata *md);

/* Execute delayed reclamations, if any. */
void offload_metadata_upkeep(struct offload_metadata *md, unsigned int uid);

/* From 'data', find its node in the map and return its attached priv if any.
 * If 'take_ref' is true, a reference is taken on the data.
 */
void *offload_metadata_priv_get(struct offload_metadata *md,
                                void *data, void *priv_arg, uint32_t *id,
                                bool take_ref);

/* Release a reference taken from a priv with 'offload_metadata_find_priv'. */
void offload_metadata_priv_unref(struct offload_metadata *md, unsigned int uid,
                                 void *priv);

/* From an id, find its node and copy the content of the stored data. */
int offload_metadata_data_from_id(struct offload_metadata *md,
                                  uint32_t id, void *data_out);

/* Given a data pointer 'data' and a pre-existing id.
 * The data <-> id reference is special: it has higher precedence
 * than potentially pre-existing links and can only have a single
 * reference.
 */
void offload_metadata_id_set(struct offload_metadata *md,
                             void *data, uint32_t id);

/* Remove the special reference taken with 'offload_metadata_id_set'. */
void offload_metadata_id_unset(struct offload_metadata *md, unsigned int uid,
                               uint32_t id);

/* For a given 'data', lookup its id in the map.
 * If none is found, allocate a data<->id link with one reference.
 * Otherwise, take one reference on the existing link.
 * The written 'id' on success is valid until dereferenced.
 * On success (found or allocated), 0 is returned, !0 otherwise.
 */
int offload_metadata_id_ref(struct offload_metadata *md,
                            void *data, void *priv_arg, uint32_t *id);

/* Unlink any data associated with 'id' and free any related
 * node. If the map is configured for 'delayed_release', the
 * id won't be freed until the delay has passed. Until then,
 * the same data would still receive that id, reactivating the
 * node. */
void offload_metadata_id_unref(struct offload_metadata *md, unsigned int uid,
                               uint32_t id);

#endif /* OFFLOAD_METADATA_H */
