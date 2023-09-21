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


#include <config.h>

#include "cmap.h"
#include "hash.h"
#include "fatal-signal.h"
#include "openvswitch/vlog.h"
#include "openvswitch/list.h"
#include "ovs-atomic.h"
#include "ovs-thread.h"
#include "refmap.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(refmap);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);

static struct ovs_mutex refmap_destroy_lock = OVS_MUTEX_INITIALIZER;
static struct ovs_list refmap_destroy_list
    OVS_GUARDED_BY(refmap_destroy_lock) =
    OVS_LIST_INITIALIZER(&refmap_destroy_list);

struct refmap {
    struct cmap map;
    struct ovs_mutex map_lock;
    size_t key_size;
    size_t value_size;
    refmap_value_init value_init;
    refmap_value_uninit value_uninit;
    refmap_value_format value_format;
    char *name;
    struct ovs_list in_destroy_list;
};

struct refmap_node {
    struct ovsrcu_inline_node rcu_node;
    /* CMAP related: */
    struct cmap_node map_node;
    uint32_t hash;
    /* Content: */
    struct ovs_refcount refcount;
    /* Key, then Value follows. */
};

static void
refmap_destroy__(struct refmap *rfm, bool global_destroy);

static void
refmap_destroy_unregister_protected(struct refmap *rfm)
    OVS_REQUIRES(refmap_destroy_lock)
{
    ovs_list_remove(&rfm->in_destroy_list);
}

static void
refmap_destroy_unregister(struct refmap *rfm)
    OVS_EXCLUDED(refmap_destroy_lock)
{
    ovs_mutex_lock(&refmap_destroy_lock);
    refmap_destroy_unregister_protected(rfm);
    ovs_mutex_unlock(&refmap_destroy_lock);
}

static void
refmap_destroy_register(struct refmap *rfm)
    OVS_EXCLUDED(refmap_destroy_lock)
{
    ovs_mutex_lock(&refmap_destroy_lock);
    ovs_list_push_back(&refmap_destroy_list, &rfm->in_destroy_list);
    ovs_mutex_unlock(&refmap_destroy_lock);
}

static void
refmap_destroy_all(void *aux OVS_UNUSED)
{
    struct refmap *rfm;

    ovs_mutex_lock(&refmap_destroy_lock);
    LIST_FOR_EACH_SAFE (rfm, in_destroy_list, &refmap_destroy_list) {
        refmap_destroy_unregister_protected(rfm);
        refmap_destroy__(rfm, true);
    }
    ovs_mutex_unlock(&refmap_destroy_lock);
    ovs_mutex_destroy(&refmap_destroy_lock);
}

static void
refmap_fatal_signal_hook(void *aux OVS_UNUSED)
{
    /* This argument is only for the type check in 'ovsrcu_postpone',
     * it is not otherwise used. */
    int dummy_arg;

    /* Do not run all destroys right in the signal handler.
     * Let other modules execute their own cleanup, and then
     * iterate over any remaining to warn about leaks. */
    ovsrcu_postpone(refmap_destroy_all, &dummy_arg);
}

struct refmap *
refmap_create(const char *name,
              size_t key_size,
              size_t value_size,
              refmap_value_init value_init,
              refmap_value_uninit value_uninit,
              refmap_value_format value_format)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    struct refmap *rfm;

    if (ovsthread_once_start(&once)) {
        fatal_signal_add_hook(refmap_fatal_signal_hook, NULL, NULL, true);
        ovsthread_once_done(&once);
    }

    rfm = xzalloc(sizeof *rfm);
    rfm->name = xstrdup(name);
    rfm->key_size = key_size;
    rfm->value_size = value_size;
    rfm->value_init = value_init;
    rfm->value_uninit = value_uninit;
    rfm->value_format = value_format;

    ovs_mutex_init(&rfm->map_lock);
    cmap_init(&rfm->map);

    refmap_destroy_register(rfm);

    return rfm;
}

static void
refmap_destroy__(struct refmap *rfm, bool global_destroy)
{
    bool leaks_detected = false;

    if (rfm == NULL) {
        return;
    }

    VLOG_DBG("%s: destroying the map", rfm->name);

    ovs_mutex_lock(&rfm->map_lock);
    if (!cmap_is_empty(&rfm->map)) {
        struct refmap_node *node;

        VLOG_WARN("%s: %s called with elements remaining in the map",
                  rfm->name, __func__);
        leaks_detected = true;
        CMAP_FOR_EACH (node, map_node, &rfm->map) {
            /* No need to remove the node from the CMAP, it will
             * be destroyed immediately. */
            ovsrcu_postpone_inline(free, node, rcu_node);
        }
    }
    cmap_destroy(&rfm->map);
    ovs_mutex_unlock(&rfm->map_lock);

    ovs_mutex_destroy(&rfm->map_lock);
    free(rfm->name);
    free(rfm);

    /* During the very last stage of execution of RCU callbacks,
     * the VLOG subsystem has been disabled. All logs are thus muted.
     * If leaks are detected, abort the process, even though we were
     * exiting due to a fatal signal. The SIGABRT generated will still
     * be visible. */
    if (global_destroy && leaks_detected) {
        ovs_abort(-1, "Refmap values leak detected.");
    }
}

void
refmap_destroy(struct refmap *rfm)
{
    if (rfm == NULL) {
        return;
    }

    refmap_destroy_unregister(rfm);
    refmap_destroy__(rfm, false);
}

static size_t
refmap_key_size(struct refmap *rfm)
{
    return ROUND_UP(rfm->key_size, 8);
}

static void *
refmap_node_key(struct refmap_node *node)
{
    if (!node) {
        return NULL;
    }

    return node + 1;
}

static void *
refmap_node_value(struct refmap *rfm, struct refmap_node *node)
{
    if (!node) {
        return NULL;
    }

    return ((char *) refmap_node_key(node)) + refmap_key_size(rfm);
}

static size_t
refmap_node_total_size(struct refmap *rfm)
{
    return sizeof(struct refmap_node) +
           refmap_key_size(rfm) + rfm->value_size;
}

static struct refmap_node *
refmap_node_from_value(struct refmap *rfm, void *value)
{
    size_t offset = sizeof(struct refmap_node) + refmap_key_size(rfm);

    if ((uintptr_t) value < offset) {
        return NULL;
    }
    return (void *) (((char *) value) - offset);
}

void
refmap_for_each(struct refmap *rfm,
                void (*cb)(void *value, void *key, void *arg), void *arg)
{
    struct refmap_node *node;

    CMAP_FOR_EACH (node, map_node, &rfm->map) {
        void *key, *value;

        if (!ovs_refcount_try_ref_rcu(&node->refcount)) {
            continue;
        }
        value = refmap_node_value(rfm, node);
        key = refmap_node_key(node);
        refmap_ref(rfm, key, NULL);
        cb(value, key, arg);
        ovs_refcount_unref(&node->refcount);
        refmap_unref(rfm, value);
    }
}

static uint32_t
refmap_key_hash(const struct refmap *rfm, const void *key)
{
    return hash_bytes(key, rfm->key_size, 0);
}

static void *
refmap_lookup_protected(struct refmap *rfm, void *key, uint32_t hash)
{
    struct refmap_node *node;

    CMAP_FOR_EACH_WITH_HASH_PROTECTED (node, map_node, hash, &rfm->map) {
        if (!memcmp(key, refmap_node_key(node), rfm->key_size) &&
            ovs_refcount_read(&node->refcount) != 0) {
            return refmap_node_value(rfm, node);
        }
    }

    return NULL;
}

static void *
refmap_lookup(struct refmap *rfm, void *key, uint32_t hash)
{
    struct refmap_node *node;

    CMAP_FOR_EACH_WITH_HASH (node, map_node, hash, &rfm->map) {
        if (!memcmp(key, refmap_node_key(node), rfm->key_size) &&
            ovs_refcount_read(&node->refcount) != 0) {
            return refmap_node_value(rfm, node);
        }
    }

    return NULL;
}

static bool
refmap_value_tryref(struct refmap *rfm, void *value)
{
    struct refmap_node *node;

    if (!value) {
        return false;
    }

    node = refmap_node_from_value(rfm, value);
    ovs_assert(NULL != node);
    return ovs_refcount_try_ref_rcu(&node->refcount);
}

void *
refmap_try_ref(struct refmap *rfm, void *key)
{
    struct refmap_node *node;
    void *value;

    value = refmap_lookup(rfm, key, refmap_key_hash(rfm, key));
    if (!refmap_value_tryref(rfm, value)) {
        return NULL;
    }
    node = refmap_node_from_value(rfm, value);
    refmap_ref(rfm, key, NULL);
    ovs_refcount_unref(&node->refcount);
    return value;
}

void *
refmap_ref(struct refmap *rfm, void *key, void *arg)
{
    struct refmap_node *node = NULL;
    uint32_t hash;
    void *value;
    bool error;

    error = false;

    hash = refmap_key_hash(rfm, key);

    value = refmap_lookup(rfm, key, hash);
    if (refmap_value_tryref(rfm, value)) {
        goto log_value;
    }

    ovs_mutex_lock(&rfm->map_lock);

    value = refmap_lookup_protected(rfm, key, hash);
    if (refmap_value_tryref(rfm, value)) {
        ovs_mutex_unlock(&rfm->map_lock);
        goto log_value;
    }

    node = xzalloc(refmap_node_total_size(rfm));
    node->hash = hash;
    ovs_refcount_init(&node->refcount);
    memcpy(refmap_node_key(node), key, rfm->key_size);
    value = refmap_node_value(rfm, node);
    if (rfm->value_init(value, arg) == 0) {
        cmap_insert(&rfm->map, &node->map_node, node->hash);
    } else {
        value = NULL;
        error = true;
    }
    ovs_mutex_unlock(&rfm->map_lock);

log_value:
    if (OVS_UNLIKELY(!VLOG_DROP_DBG((&rl)))) {
        struct ds s = DS_EMPTY_INITIALIZER;

        if (rfm->value_format) {
            ds_put_cstr(&s, ", '");
            if (value) {
                rfm->value_format(&s, key, value, arg);
            }
            ds_put_cstr(&s, "'");
        }
        if (value) {
            node = refmap_node_from_value(rfm, value);
        }
        VLOG_DBG("%s: %p ref, refcnt=%d%s", rfm->name,
                 value, ovs_refcount_read(&node->refcount),
                 ds_cstr(&s));
        ds_destroy(&s);
    }

    if (error) {
        free(node);
        return NULL;
    }

    return value;
}

bool
refmap_ref_value(struct refmap *rfm, void *value, bool safe)
{
    struct refmap_node *node;

    node = refmap_node_from_value(rfm, value);
    ovs_assert(NULL != node);
    if (safe) {
        ovs_refcount_ref(&node->refcount);
    } else if (!ovs_refcount_try_ref_rcu(&node->refcount)) {
        return false;
    }

    if (OVS_UNLIKELY(!VLOG_DROP_DBG((&rl)))) {
        VLOG_DBG("%s: %p ref, refcnt=%d", rfm->name,
                 value, ovs_refcount_read(&node->refcount));
    }

    return true;
}

bool
refmap_unref(struct refmap *rfm, void *value)
{
    struct refmap_node *node;

    if (value == NULL) {
        return false;
    }

    node = refmap_node_from_value(rfm, value);

    ovs_assert(NULL != node);

    if (OVS_UNLIKELY(!VLOG_DROP_DBG((&rl)))) {
        struct ds s = DS_EMPTY_INITIALIZER;

        VLOG_DBG("%s: %p deref, refcnt=%d", rfm->name,
                 value, ovs_refcount_read(&node->refcount));
        ds_destroy(&s);
    }

    if (ovs_refcount_unref(&node->refcount) == 1) {
        ovs_mutex_lock(&rfm->map_lock);
        rfm->value_uninit(refmap_node_value(rfm, node));
        cmap_remove(&rfm->map, &node->map_node, node->hash);
        ovs_mutex_unlock(&rfm->map_lock);
        ovsrcu_postpone_inline(free, node, rcu_node);
        return true;
    }
    return false;
}

void *
refmap_key_from_value(struct refmap *rfm, void *value)
{
    return refmap_node_key(refmap_node_from_value(rfm, value));
}

unsigned int
refmap_value_refcount_read(struct refmap *rfm, void *value)
{
    struct refmap_node *node;

    if (!value) {
        return 0;
    }

    node = refmap_node_from_value(rfm, value);
    if (node) {
        return ovs_refcount_read(&node->refcount);
    }

    return 0;
}
