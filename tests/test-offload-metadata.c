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

#undef NDEBUG
#include <assert.h>
#include <getopt.h>
#include <string.h>

#include <config.h>

#include "id-fpool.h"
#include "offload-metadata.h"
#include "openvswitch/vlog.h"
#include "openvswitch/util.h"
#include "ovs-thread.h"
#include "ovs-rcu.h"
#include "ovs-numa.h"
#include "ovstest.h"
#include "random.h"
#include "timeval.h"
#include "util.h"

#define N 100

static unsigned int nb_thread = 1;
static unsigned int
thread_id(void)
{
    return 0;
}

static struct id_fpool *pool;

static void
id_alloc_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        pool = id_fpool_create(nb_thread, 1, N);
        ovsthread_once_done(&once);
    }
}

static long long int id_free_timestamp[N];

static uint32_t
id_alloc(void)
{
    unsigned int tid = thread_id();
    uint32_t id;

    id_alloc_init();
    if (id_fpool_new_id(pool, tid, &id)) {
        id_free_timestamp[id - 1] = 0;
        return id;
    }
    return 0;
}

static void
id_free(uint32_t id)
{
    unsigned int tid = thread_id();

    id_alloc_init();
    /* Check that we do not double-free ids. */
    ovs_assert(id_free_timestamp[id - 1] == 0);
    id_free_timestamp[id - 1] = time_msec();
    id_fpool_free_id(pool, tid, id);
}

OVS_ASSERT_PACKED(struct data,
    size_t idx;
    bool b;
    uint8_t pad[7];
);

struct priv {
    void *hdl;
    uint32_t id;
};

struct arg {
    void *ptr;
};

static int
priv_init(void *priv_, void *arg_, uint32_t id)
{
    struct priv *priv = priv_;
    struct arg *arg = arg_;

    if (priv->hdl) {
        return 0;
    }

    priv->hdl = arg->ptr;
    priv->id = id;
    return 0;
}

static void
priv_uninit(void *priv_)
{
    struct priv *priv = priv_;

    if (!priv->hdl) {
        return;
    }

    priv->hdl = NULL;
    priv->id = 0;
}

static struct ds *
data_format(struct ds *s, void *data_ OVS_UNUSED,
                          void *priv_ OVS_UNUSED,
                          void *arg_ OVS_UNUSED)
{
    return s;
}

static void
test_offload_metadata_id(long long int delay)
{
    struct offload_metadata_parameters params = {
        .id_alloc = id_alloc,
        .id_free = id_free,
        .release_delay_ms = delay,
    };
    struct offload_metadata *md;
    long long int release_start;
    struct data datas[N];
    uint32_t ids[N];

    /* Test an offload metadata map that uses
     * *only* IDs, and does not care about privs.
     */
    md = offload_metadata_create(nb_thread, "test-md-id",
                                 sizeof(struct data), data_format,
                                 params);

    memset(datas, 0, sizeof datas);
    for (int i = 0; i < N; i++) {
        datas[i].idx = i;
        datas[i].b = false;
        ovs_assert(0 == offload_metadata_id_ref(md, &datas[i], NULL, &ids[i]));
    }

    for (int i = 0; i < N; i++) {
        /* Declare the data struct on the stack to evaluate the common
         * use-case of using automatic variables with partial
         * initialization. Padding bytes, if they are properly defined,
         * would be set to 0. */
        struct data d = {
            .idx = datas[i].idx,
            .b = datas[i].b,
        };
        uint32_t id;

        ovs_assert(0 == offload_metadata_id_ref(md, &d, NULL, &id));
        ovs_assert(ids[i] == id);
    }

    for (int i = 0; i < N; i++) {
        struct data cur;

        ovs_assert(0 == offload_metadata_data_from_id(md, ids[i], &cur));
        ovs_assert(0 == memcmp(&cur, &datas[i], sizeof cur));
    }

    release_start = time_msec();
    for (int i = 0; i < N; i++) {
        offload_metadata_id_unref(md, 0, ids[i]);
        offload_metadata_id_unref(md, 0, ids[i]);
    }

    if (delay) {
        xnanosleep(delay * 1e6 + 1);
    }
    offload_metadata_upkeep(md, 0);

    for (int i = 0; i < N; i++) {
        struct data ff;
        struct data cur;

        memset(&cur, 0xff, sizeof cur);
        memset(&ff, 0xff, sizeof ff);

        ovs_assert(0 != offload_metadata_data_from_id(md, ids[i], &cur));
        /* Verify that 'cur' was not written to. */
        ovs_assert(0 == memcmp(&cur, &ff, sizeof cur));
    }

    if (delay != 0) {
        for (int i = 0; i < N; i++) {
            ovs_assert(id_free_timestamp[i] - release_start >= delay);
        }
    }

    offload_metadata_destroy(md);
}

static void
test_offload_metadata_id_set(long long int delay)
{
    struct offload_metadata_parameters params = {
        .id_alloc = id_alloc,
        .id_free = id_free,
        .release_delay_ms = delay,
    };
    struct offload_metadata *md;
    long long int release_start;
    struct data datas[N];
    uint32_t override[N];
    uint32_t ids[N];

    /* Test an offload metadata map that uses
     * *only* IDs, and does not care about privs,
     * however it will also choose some IDs.
     */
    md = offload_metadata_create(nb_thread, "test-md-id-set",
                                 sizeof(struct data), data_format,
                                 params);

    for (int i = 0; i < N; i++) {
        datas[i].idx = i;
        override[i] = N + i + 1;
        ovs_assert(0 == offload_metadata_id_ref(md, &datas[i], NULL, &ids[i]));
    }

    for (int i = 0; i < N; i++) {
        struct data cur;

        offload_metadata_id_set(md, &datas[i], override[i]);
        ovs_assert(0 == offload_metadata_data_from_id(md, override[i], &cur));
        ovs_assert(0 == memcmp(&cur, &datas[i], sizeof cur));
    }

    release_start = time_msec();
    for (int i = 0; i < N; i++) {
        offload_metadata_id_unset(md, 0, override[i]);
        offload_metadata_id_unref(md, 0, ids[i]);
    }

    if (delay) {
        xnanosleep(delay * 1e6 + 1);
    }
    offload_metadata_upkeep(md, 0);

    for (int i = 0; i < N; i++) {
        struct data ff;
        struct data cur;

        memset(&cur, 0xff, sizeof cur);
        memset(&ff, 0xff, sizeof ff);

        ovs_assert(0 != offload_metadata_data_from_id(md, override[i], &cur));
        ovs_assert(0 != offload_metadata_data_from_id(md, ids[i], &cur));
        /* Verify that 'cur' was not written to. */
        ovs_assert(0 == memcmp(&cur, &ff, sizeof cur));
    }

    if (delay != 0) {
        for (int i = 0; i < N; i++) {
            ovs_assert(id_free_timestamp[i] - release_start >= delay);
        }
    }

    offload_metadata_destroy(md);
}

static void
test_offload_metadata_id_priv(long long int delay)
{
    struct offload_metadata_parameters params = {
        .id_alloc = id_alloc,
        .id_free = id_free,
        .priv_size = sizeof(struct priv),
        .priv_init = priv_init,
        .priv_uninit = priv_uninit,
        .release_delay_ms = delay,
    };
    struct offload_metadata *md;
    long long int release_start;
    struct priv *privs[N];
    struct data datas[N];
    uint32_t ids[N];

    /* Test an offload metadata map that uses
     * both IDs and priv storage.
     */
    md = offload_metadata_create(nb_thread, "test-md-id-priv",
                                 sizeof(struct data), data_format,
                                 params);

    for (int i = 0; i < N; i++) {
        struct arg arg = {
            .ptr = &datas[i],
        };
        struct priv *priv;
        uint32_t id;

        datas[i].idx = i;
        ovs_assert(NULL == offload_metadata_priv_get(md, &datas[i], &arg,
                                                     NULL, false));
        ovs_assert(0 == offload_metadata_id_ref(md, &datas[i], &arg, &ids[i]));
        priv = offload_metadata_priv_get(md, &datas[i], &arg, &id, false);
        ovs_assert(ids[i] == id);
        ovs_assert(priv != NULL);
        ovs_assert(id != 0);
        ovs_assert(priv == offload_metadata_priv_get(md, &datas[i], &arg,
                                                     NULL, false));
        ovs_assert(priv == offload_metadata_priv_get(md, &datas[i], &arg,
                                                     NULL, true));
        offload_metadata_priv_unref(md, 0, priv);
        ovs_assert(priv == offload_metadata_priv_get(md, &datas[i], &arg,
                                                     NULL, false));
        privs[i] = priv;
    }

    release_start = time_msec();
    for (int i = 0; i < N; i++) {
        ovs_assert(privs[i]->id == ids[i]);
        if (i % 2 == 0) {
            offload_metadata_priv_unref(md, 0, privs[i]);
        } else {
            offload_metadata_id_unref(md, 0, ids[i]);
        }
    }

    if (delay) {
        xnanosleep(delay * 1e6 + 1);
    }
    offload_metadata_upkeep(md, 0);

    for (int i = 0; i < N; i++) {
        struct arg arg = {
            .ptr = &datas[i],
        };

        ovs_assert(NULL == offload_metadata_priv_get(md, &datas[i], &arg,
                                                     NULL, false));
    }

    if (delay != 0) {
        for (int i = 0; i < N; i++) {
            ovs_assert(id_free_timestamp[i] - release_start >= delay);
        }
    }

    offload_metadata_destroy(md);
}

static void
test_offload_metadata_priv(long long int delay)
{
    struct offload_metadata_parameters params = {
        .priv_size = sizeof(struct priv),
        .priv_init = priv_init,
        .priv_uninit = priv_uninit,
        .release_delay_ms = delay,
    };
    struct offload_metadata *md;
    struct data datas[N];
    struct priv *privs[N];

    /* Test an offload metadata map that uses
     * *only* the priv storage, and does not care
     * about IDs. */
    md = offload_metadata_create(nb_thread, "test-md-priv",
                                 sizeof(struct data), data_format,
                                 params);

    for (int i = 0; i < N; i++) {
        struct arg arg = {
            .ptr = &datas[i],
        };
        struct priv *priv;
        uint32_t id;

        datas[i].idx = i;
        ovs_assert(NULL == offload_metadata_priv_get(md, &datas[i], &arg,
                                                     NULL, false));
        priv = offload_metadata_priv_get(md, &datas[i], &arg, &id, true);
        ovs_assert(priv != NULL);
        ovs_assert(id == 0);
        ovs_assert(priv == offload_metadata_priv_get(md, &datas[i], &arg,
                                                     NULL, false));
        privs[i] = priv;
    }

    for (int i = 0; i < N; i++) {
        offload_metadata_priv_unref(md, 0, privs[i]);
    }

    if (delay) {
        xnanosleep(delay * 1e6 + 1);
    }
    offload_metadata_upkeep(md, 0);

    for (int i = 0; i < N; i++) {
        struct arg arg = {
            .ptr = &datas[i],
        };

        ovs_assert(NULL == offload_metadata_priv_get(md, &datas[i], &arg,
                                                     NULL, false));
    }

    offload_metadata_destroy(md);
}

static void
run_tests(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    test_offload_metadata_id(0);
    test_offload_metadata_id(5);
    test_offload_metadata_id_set(0);
    test_offload_metadata_id_set(5);
    test_offload_metadata_id_priv(0);
    test_offload_metadata_id_priv(5);
    test_offload_metadata_priv(0);
    test_offload_metadata_priv(5);
}

static const struct ovs_cmdl_command commands[] = {
    {"check", NULL, 0, 0, run_tests, OVS_RO},
    {NULL, NULL, 0, 0, NULL, OVS_RO},
};

static void
offload_metadata_test_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - optind,
        .argv = argv + optind,
    };

    vlog_set_levels(NULL, VLF_ANY_DESTINATION, VLL_OFF);

    /* Quiesce to trigger the RCU init. */
    ovsrcu_quiesce();

    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);

    id_fpool_destroy(pool);

    ovsrcu_quiesce();
}

OVSTEST_REGISTER("test-offload-metadata", offload_metadata_test_main);
