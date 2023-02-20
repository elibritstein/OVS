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


#include <config.h>

#include "cmap.h"
#include "offload-metadata.h"
#include "timeval.h"
#include "hash.h"
#include "openvswitch/vlog.h"
#include "ovs-rcu.h"
#include "ovs-atomic.h"

VLOG_DEFINE_THIS_MODULE(offload_metadata);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);

struct offload_metadata {
    unsigned int nb_user;
    char *name;
    size_t data_size;
    offload_metadata_data_format data_format;
    offload_metadata_id_alloc id_alloc;
    offload_metadata_id_free id_free;
    size_t priv_size;
    offload_metadata_priv_init priv_init;
    offload_metadata_priv_uninit priv_uninit;
    struct ovs_mutex maps_lock;
    struct cmap d2i_map;
    struct cmap i2d_map;
    struct cmap associated_i2d_map;
    bool has_associated_map;
    long long int delay;
    struct ovs_list *free_lists;
};

struct data_entry {
    struct cmap_node d2i_node;
    uint32_t d2i_hash;
    struct cmap_node i2d_node;
    uint32_t i2d_hash;
    struct cmap_node associated_i2d_node;
    uint32_t associated_i2d_hash;
    uint32_t id;
    struct ovs_refcount refcount;
    bool priv_init_done;
    void *data;
    void *priv;
};

struct release_item {
    struct ovs_list node;
    struct ovsrcu_gc_node gc_node;
    long long int timestamp;
    struct offload_metadata *md;
    uint32_t id;
    struct data_entry *data;
    bool associated;
};

static void
context_item_gc(struct release_item *item)
{
    free(item->data);
    free(item);
}

static void
context_release(struct release_item *item)
{
    struct offload_metadata *md = item->md;
    struct data_entry *data = item->data;
    struct data_entry *data_cur;
    size_t ihash;

    VLOG_DBG_RL(&rl, "%s: md=%s, id=%d. associated=%d", __func__, md->name,
                item->id, item->associated);

    ovs_mutex_lock(&md->maps_lock);

    if (!item->associated
        && ovs_refcount_unref(&item->data->refcount) > 1) {
        /* Data has been referenced again since delayed release request. */
        goto maps_unlock;
    }

    if (item->id != 0) {
        ihash = hash_add(0, item->id);

        if (item->associated) {
            CMAP_FOR_EACH_WITH_HASH_PROTECTED (data_cur, associated_i2d_node,
                                               ihash,
                                               &item->md->associated_i2d_map) {
                if (data_cur->id == item->id) {
                    break;
                }
            }
        } else {
            CMAP_FOR_EACH_WITH_HASH_PROTECTED (data_cur, i2d_node, ihash,
                                               &item->md->i2d_map) {
                if (data_cur->id == item->id) {
                    break;
                }
            }
        }

        if (data_cur && data_cur->id == item->id) {
            if (!item->associated) {
                cmap_remove(&md->i2d_map, &data->i2d_node, data->i2d_hash);
                cmap_remove(&md->d2i_map, &data->d2i_node, data->d2i_hash);
                item->md->id_free(item->id);
            } else {
                cmap_remove(&md->associated_i2d_map,
                            &data->associated_i2d_node,
                            data->associated_i2d_hash);
            }
        }
    } else {
        cmap_remove(&md->d2i_map, &data->d2i_node, data->d2i_hash);
    }

    ovsrcu_gc(context_item_gc, item, gc_node);
    ovs_mutex_unlock(&md->maps_lock);
    return;

maps_unlock:
    ovs_mutex_unlock(&md->maps_lock);
    free(item);
}

static void
context_delayed_release(struct offload_metadata *md, unsigned int uid,
                        uint32_t id, struct data_entry *data, bool associated)
{
    struct release_item *item;
    struct ovs_list *list;

    item = xzalloc(sizeof *item);
    item->md = md;
    item->id = id;
    item->data = data;
    item->associated = associated;
    if (md->priv_uninit) {
        if (ovs_refcount_read(&data->refcount) == 1) {
            /* Immediately uninit the priv, even if the
             * data release is delayed. If another object takes
             * a ref on the data, the priv will then be re-initialized.
             */
            ovs_mutex_lock(&md->maps_lock);
            md->priv_uninit(item->data->priv);
            item->data->priv_init_done = false;
            ovs_mutex_unlock(&md->maps_lock);
        }
    }
    if (md->delay == 0) {
        context_release(item);
        return;
    }

    list = &md->free_lists[uid];

    item->timestamp = time_msec();
    ovs_list_push_back(list, &item->node);
    VLOG_DBG_RL(&rl, "%s: md=%s, id=%d, associated=%d, timestamp=%llu",
                __func__, item->md->name, item->id, associated,
                item->timestamp);
}

struct offload_metadata *
offload_metadata_create(unsigned int nb_user,
            const char *name,
            size_t data_size,
            offload_metadata_data_format data_format,
            struct offload_metadata_parameters params)
{
    struct offload_metadata *md;

    md = xzalloc(sizeof *md);
    md->nb_user = nb_user;
    md->name = xstrdup(name);
    md->data_size = data_size;
    md->data_format = data_format;
    md->id_alloc = params.id_alloc;
    md->id_free = params.id_free;
    md->priv_size = params.priv_size;
    md->priv_init = params.priv_init;
    md->priv_uninit = params.priv_uninit;

    md->delay = params.release_delay_ms;

    md->free_lists = xcalloc(nb_user, sizeof *md->free_lists);
    for (unsigned int i = 0; i < nb_user; i++) {
        ovs_list_init(&md->free_lists[i]);
    }

    cmap_init(&md->d2i_map);
    cmap_init(&md->i2d_map);
    cmap_init(&md->associated_i2d_map);

    if (params.disable_map_shrink) {
        cmap_set_min_load(&md->d2i_map, 0.0);
        cmap_set_min_load(&md->i2d_map, 0.0);
        cmap_set_min_load(&md->associated_i2d_map, 0.0);
    }

    ovs_mutex_init(&md->maps_lock);

    return md;
}

void
offload_metadata_destroy(struct offload_metadata *md)
{
    if (md == NULL) {
        return;
    }

    for (unsigned int i = 0; i < md->nb_user; i++) {
        struct ovs_list *list = &md->free_lists[i];
        struct ovs_list *node;

        while (!ovs_list_is_empty(list)) {
            struct release_item *item;

            node = ovs_list_front(list);
            item = CONTAINER_OF(node, struct release_item, node);
            VLOG_DBG_RL(&rl, "%s: md=%s, id=%d, associated=%d, timestamp=%llu",
                        __func__, item->md->name, item->id,
                        item->associated, item->timestamp);
            ovs_list_remove(node);
            context_release(item);
        }
    }

    cmap_destroy(&md->d2i_map);
    cmap_destroy(&md->i2d_map);
    cmap_destroy(&md->associated_i2d_map);

    ovs_mutex_destroy(&md->maps_lock);
    free(md->free_lists);
    free(md->name);
    free(md);
}

void
offload_metadata_upkeep(struct offload_metadata *md, unsigned int uid)
{
    struct ovs_list *list;
    struct ovs_list *node;
    long long int now;

    if (md == NULL) {
        return;
    }

    ovs_assert(uid < md->nb_user);
    list = &md->free_lists[uid];

    now = time_msec();
    while (!ovs_list_is_empty(list)) {
        struct release_item *item;

        node = ovs_list_front(list);
        item = CONTAINER_OF(node, struct release_item, node);
        if (now < item->timestamp + md->delay) {
            break;
        }
        VLOG_DBG_RL(&rl, "%s: md=%s, id=%d, associated=%d, timestamp=%llu, "
                    "now=%llu", __func__, item->md->name, item->id,
                    item->associated, item->timestamp, now);
        ovs_list_remove(node);
        context_release(item);
    }
}

static size_t
offload_metadata_data_size(struct offload_metadata *md)
{
    return ROUND_UP(md->data_size, 8);
}

static size_t
data_entry_total_size(struct offload_metadata *md)
{
    return sizeof(struct data_entry) +
           offload_metadata_data_size(md) +
           md->priv_size;
}

static struct data_entry *
data_entry_from_priv(struct offload_metadata *md, void *priv)
{
    size_t priv_offset = sizeof(struct data_entry) +
                         offload_metadata_data_size(md);

    if ((uintptr_t) priv < priv_offset) {
        return NULL;
    }
    return (void *) (((char *) priv) - priv_offset);
}

void *
offload_metadata_priv_get(struct offload_metadata *md, void *data,
                          void *priv_arg, uint32_t *id,
                          bool take_ref)
{
    struct data_entry *data_cur;
    uint32_t alloc_id = 0;
    size_t dhash, ihash;
    struct ds s;

    ds_init(&s);

    dhash = hash_bytes(data, md->data_size, 0);
    CMAP_FOR_EACH_WITH_HASH (data_cur, d2i_node, dhash, &md->d2i_map) {
        if (!memcmp(data, data_cur->data, md->data_size)) {
            if (take_ref) {
                if (!ovs_refcount_try_ref_rcu(&data_cur->refcount)) {
                    /* If a reference could not be taken, it means that
                     * while the data has been found within the map, it has
                     * since been removed and related ID freed. At this point,
                     * allocate a new data node altogether. */
                    break;
                }
            } else {
                if (ovs_refcount_read(&data_cur->refcount) == 0) {
                    /* If no reference is to be taken, ignore nodes that
                     * have reached the end of their refcount. */
                    break;
                }
            }
            VLOG_DBG_RL(&rl, "%s: %s: '%s', take_ref=%d, refcnt=%u, id=%d",
                        __func__, md->name,
                        ds_cstr(md->data_format(&s,
                                                data_cur->data,
                                                data_cur->priv,
                                                priv_arg)),
                        take_ref,
                        ovs_refcount_read(&data_cur->refcount),
                        data_cur->id);
            ds_destroy(&s);
            if (id) {
                *id = data_cur->id;
            }
            if (md->priv_init && !data_cur->priv_init_done) {
                int ret;

                ovs_mutex_lock(&md->maps_lock);
                ret = md->priv_init(data_cur->priv, priv_arg, data_cur->id);
                if (ret) {
                    ovs_mutex_unlock(&md->maps_lock);
                    return NULL;
                }
                data_cur->priv_init_done = true;
                ovs_mutex_unlock(&md->maps_lock);
            }
            return data_cur->priv;
        }
    }

    if (!take_ref) {
        return NULL;
    }

    if (md->id_alloc) {
        alloc_id = md->id_alloc();
        if (alloc_id == 0) {
            goto err_id_alloc;
        }
    }
    data_cur = xzalloc(data_entry_total_size(md));
    data_cur->data = data_cur + 1;
    data_cur->priv = (char *) data_cur->data + offload_metadata_data_size(md);
    memcpy(data_cur->data, data, md->data_size);
    ovs_refcount_init(&data_cur->refcount);
    data_cur->id = alloc_id;
    ovs_mutex_lock(&md->maps_lock);
    if (md->priv_init && md->priv_init(data_cur->priv, priv_arg, alloc_id)) {
        ovs_mutex_unlock(&md->maps_lock);
        goto err_priv_init;
    }
    data_cur->priv_init_done = true;
    data_cur->d2i_hash = dhash;
    cmap_insert(&md->d2i_map, &data_cur->d2i_node, dhash);
    if (alloc_id != 0) {
        ihash = hash_add(0, data_cur->id);
        data_cur->i2d_hash = ihash;
        cmap_insert(&md->i2d_map, &data_cur->i2d_node, ihash);
    }
    VLOG_DBG_RL(&rl, "%s: %s: '%s', refcnt=%d, id=%d", __func__, md->name,
                ds_cstr(md->data_format(&s,
                                        data_cur->data,
                                        data_cur->priv,
                                        priv_arg)),
                ovs_refcount_read(&data_cur->refcount),
                data_cur->id);
    if (id) {
        *id = data_cur->id;
    }

    ovs_mutex_unlock(&md->maps_lock);
    ds_destroy(&s);
    return data_cur->priv;

err_priv_init:
    free(data_cur->data);
    free(data_cur);
    VLOG_ERR_RL(&rl, "%s: %s: error. '%s'", __func__, md->name,
                ds_cstr(md->data_format(&s, data,
                                        NULL, NULL)));
err_id_alloc:
    ds_destroy(&s);
    return NULL;
}

void
offload_metadata_priv_unref(struct offload_metadata *md, unsigned int uid,
                            void *priv)
{
    struct data_entry *data;

    if (priv == NULL) {
        return;
    }

    data = data_entry_from_priv(md, priv);
    context_delayed_release(md, uid, data->id, data, false);
}

int
offload_metadata_data_from_id(struct offload_metadata *md, uint32_t id,
                              void *data_out)
{
    struct data_entry *data_cur = NULL;
    size_t ihash = hash_add(0, id);

    if (md->has_associated_map) {
        CMAP_FOR_EACH_WITH_HASH (data_cur, associated_i2d_node, ihash,
                                 &md->associated_i2d_map) {
            if (data_cur->id == id) {
                break;
            }
        }
    }

    if (data_cur == NULL) {
        CMAP_FOR_EACH_WITH_HASH (data_cur, i2d_node, ihash, &md->i2d_map) {
            if (data_cur->id == id) {
                break;
            }
        }
    }

    if (data_cur) {
        memcpy(data_out, data_cur->data, md->data_size);
    }

    return data_cur ? 0 : -1;
}

void
offload_metadata_id_set(struct offload_metadata *md, void *data, uint32_t id)
{
    struct data_entry *data_cur;
    size_t ihash;
    struct ds s;

    if (!md->has_associated_map) {
        md->has_associated_map = true;
    }

    ds_init(&s);
    data_cur = xzalloc(data_entry_total_size(md));
    data_cur->data = data_cur + 1;
    data_cur->priv = (char *) data_cur->data + offload_metadata_data_size(md);
    memcpy(data_cur->data, data, md->data_size);
    ovs_refcount_init(&data_cur->refcount);
    data_cur->id = id;
    ihash = hash_add(0, data_cur->id);
    ovs_mutex_lock(&md->maps_lock);
    data_cur->associated_i2d_hash = ihash;
    cmap_insert(&md->associated_i2d_map, &data_cur->associated_i2d_node,
                ihash);
    ovs_mutex_unlock(&md->maps_lock);
    VLOG_DBG_RL(&rl, "%s: %s: '%s', refcnt=%d, id=%d", __func__, md->name,
                ds_cstr(md->data_format(&s, data_cur->data,
                                        NULL, NULL)),
                ovs_refcount_read(&data_cur->refcount),
                data_cur->id);
    ds_destroy(&s);
}

void
offload_metadata_id_unset(struct offload_metadata *md, unsigned int uid,
                          uint32_t id)
{
    struct data_entry *data_cur = NULL;
    struct ds s;

    if (id == 0) {
        return;
    }

    if (md->has_associated_map) {
        size_t ihash = hash_add(0, id);
        CMAP_FOR_EACH_WITH_HASH (data_cur, associated_i2d_node, ihash,
                                 &md->associated_i2d_map) {
            if (data_cur->id == id) {
                break;
            }
        }
    }

    if (data_cur) {
        ds_init(&s);
        VLOG_DBG_RL(&rl,
                    "%s: %s: '%s', refcnt=%u, id=%d", __func__, md->name,
                    ds_cstr(md->data_format(&s, data_cur->data,
                                            NULL, NULL)),
                    ovs_refcount_read(&data_cur->refcount),
                    data_cur->id);
        ds_destroy(&s);
        context_delayed_release(md, uid, id, data_cur, true);
    }
}

int
offload_metadata_id_ref(struct offload_metadata *md,
            void *data, void *priv_arg, uint32_t *id)
{
    ovs_assert(md->id_alloc != NULL);
    return offload_metadata_priv_get(md, data, priv_arg, id, true) ? 0 : -1;
}

void
offload_metadata_id_unref(struct offload_metadata *md, unsigned int uid,
                          uint32_t id)
{
    struct data_entry *data_cur = NULL;
    size_t ihash;
    struct ds s;

    if (id == 0) {
        return;
    }

    ihash = hash_add(0, id);
    CMAP_FOR_EACH_WITH_HASH (data_cur, i2d_node, ihash, &md->i2d_map) {
        if (data_cur->id == id) {
            break;
        }
    }

    if (data_cur) {
        ds_init(&s);
        VLOG_DBG_RL(&rl,
                    "%s: %s: '%s', refcnt=%u, id=%d", __func__, md->name,
                    ds_cstr(md->data_format(&s, data_cur->data,
                                            NULL, NULL)),
                    ovs_refcount_read(&data_cur->refcount),
                    data_cur->id);
        ds_destroy(&s);
        context_delayed_release(md, uid, id, data_cur, false);
    }
}
