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
#include <errno.h>
#include <getopt.h>
#include <string.h>

#include <config.h>

#include "id-fpool.h"
#include "offload-metadata.h"
#include "openvswitch/vlog.h"
#include "openvswitch/util.h"
#include "ovs-atomic.h"
#include "ovs-thread.h"
#include "ovs-rcu.h"
#include "ovs-numa.h"
#include "ovstest.h"
#include "random.h"
#include "timeval.h"
#include "util.h"

#define N 100

enum test_mode {
    MODE_ANY,
    MODE_ID,
    MODE_PRIV,
};

static struct offload_metadata_test_params {
    enum test_mode mode;
    unsigned int n_threads;
    unsigned int n_ids;
    bool debug;
    bool csv_format;
} test_params = {
    .mode = MODE_ANY,
    .n_threads = 1,
    .n_ids = N,
    .debug = false,
    .csv_format = false,
};

DECLARE_EXTERN_PER_THREAD_DATA(unsigned int, thread_id);
DEFINE_EXTERN_PER_THREAD_DATA(thread_id, OVSTHREAD_ID_UNSET);

static unsigned int
thread_id(void)
{
    static atomic_count next_id = ATOMIC_COUNT_INIT(0);
    unsigned int id = *thread_id_get();

    if (OVS_UNLIKELY(id == OVSTHREAD_ID_UNSET)) {
        id = atomic_count_inc(&next_id);
        *thread_id_get() = id;
    }

    return id;
}

static bool mode_unit_test;
static struct id_fpool *pool;

static void
id_alloc_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        pool = id_fpool_create(test_params.n_threads, 1, test_params.n_ids);
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
        if (mode_unit_test) {
            id_free_timestamp[id - 1] = 0;
        }
        return id;
    }
    return 0;
}

static void
id_free(uint32_t id)
{
    unsigned int tid = thread_id();

    id_alloc_init();
    if (mode_unit_test) {
        /* Check that we do not double-free ids. */
        ovs_assert(id_free_timestamp[id - 1] == 0);
        id_free_timestamp[id - 1] = time_msec();
    }
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

    /* Verify that we don't double-init priv. */
    ovs_assert(priv->hdl == NULL);

    priv->hdl = arg->ptr;
    priv->id = id;
    return 0;
}

static void
priv_uninit(void *priv_)
{
    struct priv *priv = priv_;

    /* Verify that we don't double-uninit priv. */
    ovs_assert(priv->hdl != NULL);

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
    md = offload_metadata_create(test_params.n_threads, "test-md-id",
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
    offload_metadata_upkeep(md, 0, time_msec());

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
    md = offload_metadata_create(test_params.n_threads, "test-md-id-set",
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
    offload_metadata_upkeep(md, 0, time_msec());

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
    md = offload_metadata_create(test_params.n_threads, "test-md-id-priv",
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
        ovs_assert(priv->hdl != NULL);
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

    for (int i = 0; i < N; i++) {
        ovs_assert(privs[i]->hdl != NULL);
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
    offload_metadata_upkeep(md, 0, time_msec());

    for (int i = 0; i < N; i++) {
        struct arg arg = {
            .ptr = &datas[i],
        };

        ovs_assert(NULL == offload_metadata_priv_get(md, &datas[i], &arg,
                                                     NULL, false));
    }

    for (int i = 0; i < N; i++) {
        ovs_assert(privs[i]->hdl == NULL);
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
    md = offload_metadata_create(test_params.n_threads, "test-md-priv",
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
                                                     NULL, true));
        offload_metadata_priv_unref(md, 0, priv);
        ovs_assert(priv == offload_metadata_priv_get(md, &datas[i], &arg,
                                                     NULL, false));
        privs[i] = priv;
    }

    for (int i = 0; i < N; i++) {
        /* Verify that priv init is properly called. */
        ovs_assert(privs[i]->hdl != NULL);
    }

    for (int i = 0; i < N; i++) {
        offload_metadata_priv_unref(md, 0, privs[i]);
    }

    if (delay) {
        xnanosleep(delay * 1e6 + 1);
    }
    offload_metadata_upkeep(md, 0, time_msec());

    for (int i = 0; i < N; i++) {
        struct arg arg = {
            .ptr = &datas[i],
        };

        ovs_assert(NULL == offload_metadata_priv_get(md, &datas[i], &arg,
                                                     NULL, false));
    }

    for (int i = 0; i < N; i++) {
        /* Verify that priv uninit is actually executed. */
        ovs_assert(privs[i]->hdl == NULL);
    }

    offload_metadata_destroy(md);
}

static void
run_tests(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    mode_unit_test = true;
    test_offload_metadata_id(0);
    test_offload_metadata_id(5);
    test_offload_metadata_id_set(0);
    test_offload_metadata_id_set(5);
    test_offload_metadata_id_priv(0);
    test_offload_metadata_id_priv(5);
    test_offload_metadata_priv(0);
    test_offload_metadata_priv(5);
}

static uint32_t *ids;
static void **privs;
static atomic_uint *thread_working_ms; /* Measured work time. */

static struct ovs_barrier barrier_outer;
static struct ovs_barrier barrier_inner;

static unsigned int running_time_ms;
static volatile bool stop = false;

static unsigned int
elapsed(unsigned int start)
{
    return running_time_ms - start;
}

static void *
clock_main(void *arg OVS_UNUSED)
{
    struct timeval start;
    struct timeval end;

    xgettimeofday(&start);
    while (!stop) {
        xgettimeofday(&end);
        running_time_ms = timeval_to_msec(&end) - timeval_to_msec(&start);
        xnanosleep(1000);
    }

    return NULL;
}

enum step_id {
    STEP_NONE,
    STEP_ALLOC,
    STEP_REF,
    STEP_UNREF,
    STEP_FREE,
    STEP_MIXED,
    STEP_POS_QUERY,
    STEP_NEG_QUERY,
};

static const char *step_names[] = {
    [STEP_NONE] = "<bug>",
    [STEP_ALLOC] = "alloc",
    [STEP_REF] = "ref",
    [STEP_UNREF] = "unref",
    [STEP_FREE] = "free",
    [STEP_MIXED] = "mixed",
    [STEP_POS_QUERY] = "pos-query",
    [STEP_NEG_QUERY] = "neg-query",
};

#define MAX_N_STEP 10

#define FOREACH_STEP(STEP_VAR, SCHEDULE) \
        for (int __idx = 0, STEP_VAR = (SCHEDULE)[__idx]; \
             (STEP_VAR = (SCHEDULE)[__idx]) != STEP_NONE; \
             __idx++)

static const char *mode_names[] = {
    [MODE_ANY] = "<any>",
    [MODE_ID] = "id",
    [MODE_PRIV] = "priv",
};

struct test_desc {
    int idx;
    enum test_mode mode;
    enum step_id schedule[MAX_N_STEP];
};

static void
print_header(void)
{
    if (test_params.csv_format) {
        return;
    }

    printf("Benchmarking n=%u on %u thread%s.\n",
           test_params.n_ids, test_params.n_threads,
           test_params.n_threads > 1 ? "s" : "");

    printf("       step\\thread: ");
    printf("    Avg");
    for (size_t i = 0; i < test_params.n_threads; i++) {
        printf("    %3" PRIuSIZE, i + 1);
    }
    printf("\n");
}

static void
print_test_header(struct test_desc *test)
{
    if (test_params.csv_format) {
        return;
    }

    printf("[%d]---------------------------", test->idx);
    for (size_t i = 0; i < test_params.n_threads; i++) {
        printf("-------");
    }
    printf("\n");
}

static void
print_test_result(struct test_desc *test, enum step_id step, int step_idx)
{
    char test_name[50];
    uint64_t *twm;
    uint64_t avg;
    size_t i;

    twm = xcalloc(test_params.n_threads, sizeof *twm);
    for (i = 0; i < test_params.n_threads; i++) {
        atomic_read(&thread_working_ms[i], &twm[i]);
    }

    avg = 0;
    for (i = 0; i < test_params.n_threads; i++) {
        avg += twm[i];
    }
    avg /= test_params.n_threads;

    snprintf(test_name, sizeof test_name, "%s:%d.%d-%s",
             mode_names[test->mode],
             test->idx, step_idx,
             step_names[step]);
    if (test_params.csv_format) {
        printf("%s,%" PRIu64, test_name, avg);
    } else {
        printf("%*s: ", 18, test_name);
        printf(" %6" PRIu64, avg);
        for (i = 0; i < test_params.n_threads; i++) {
            printf(" %6" PRIu64, twm[i]);
        }
        printf(" ms");
    }
    printf("\n");

    free(twm);
}

static struct test_desc test_cases[] = {
    {
        .mode = MODE_ID,
        .schedule = {
            STEP_ALLOC,
            STEP_FREE,
        },
    },
    {
        .mode = MODE_ID,
        .schedule = {
            STEP_ALLOC,
            STEP_REF,
            STEP_UNREF,
            STEP_FREE,
        },
    },
    {
        .mode = MODE_ID,
        .schedule = {
            STEP_MIXED,
            STEP_FREE,
        },
    },
    {
        .mode = MODE_PRIV,
        .schedule = {
            STEP_ALLOC,
            STEP_FREE,
        },
    },
    {
        .mode = MODE_PRIV,
        .schedule = {
            STEP_ALLOC,
            STEP_REF,
            STEP_UNREF,
            STEP_FREE,
        },
    },
    {
        .mode = MODE_PRIV,
        .schedule = {
            STEP_MIXED,
            STEP_FREE,
        },
    },
    {
        .mode = MODE_PRIV,
        .schedule = {
            STEP_ALLOC,
            STEP_POS_QUERY,
            /* Test negative query with map full. */
            STEP_NEG_QUERY,
            STEP_FREE,
            /* Test negative query with map empty. */
            STEP_NEG_QUERY,
        },
    },
};

static void
swap_u32(uint32_t *a, uint32_t *b)
{
    uint32_t t;
    t = *a;
    *a = *b;
    *b = t;
}

static void
swap_ptr(void **a, void **b)
{
    void *t;
    t = *a;
    *a = *b;
    *b = t;
}

struct aux {
    struct test_desc test;
    struct offload_metadata *md;
};

static void *
benchmark_thread_worker(void *aux_)
{
    unsigned int tid = thread_id();
    unsigned int n_ids_per_thread;
    struct offload_metadata *md;
    unsigned int start_idx;
    struct aux *aux = aux_;
    enum test_mode mode;
    unsigned int start;
    uint32_t *th_ids;
    void **th_privs;
    size_t i;

    n_ids_per_thread = test_params.n_ids / test_params.n_threads;
    start_idx = tid * n_ids_per_thread;
    th_privs = &privs[start_idx];
    th_ids = &ids[start_idx];

    while (true) {
        ovs_barrier_block(&barrier_outer);
        if (stop) {
            break;
        }
        /* Wait for main thread to finish initializing
         * md and step schedule. */
        ovs_barrier_block(&barrier_inner);
        md = aux->md;
        mode = aux->test.mode;

        FOREACH_STEP(step, aux->test.schedule) {
            ovs_barrier_block(&barrier_inner);
            start = running_time_ms;
            switch (step) {
            case STEP_ALLOC:
            case STEP_REF:
                for (i = 0; i < n_ids_per_thread; i++) {
                    struct data d = {
                        .idx = start_idx + i,
                    };

                    if (mode == MODE_ID) {
                        offload_metadata_id_ref(md, &d, NULL, &th_ids[i]);
                    } else if (mode == MODE_PRIV) {
                        struct arg arg = {
                            .ptr = &th_ids[i],
                        };
                        th_privs[i] = offload_metadata_priv_get(md, &d, &arg,
                                                                NULL, true);
                    }
                }
                break;
            case STEP_POS_QUERY:
                if (mode == MODE_PRIV) {
                    for (i = 0; i < n_ids_per_thread; i++) {
                        struct data d = {
                            .idx = start_idx + i,
                        };
                        offload_metadata_priv_get(md, &d, NULL, NULL, false);
                    }
                }
                break;
            case STEP_NEG_QUERY:
                if (mode == MODE_PRIV) {
                    for (i = 0; i < n_ids_per_thread; i++) {
                        struct data d = {
                            .idx = test_params.n_ids + 1,
                        };
                        offload_metadata_priv_get(md, &d, NULL, NULL, false);
                    }
                }
                break;
            case STEP_UNREF:
            case STEP_FREE:
                for (i = 0; i < n_ids_per_thread; i++) {
                    if (mode == MODE_ID) {
                        offload_metadata_id_unref(md, tid, th_ids[i]);
                    } else if (mode == MODE_PRIV) {
                        offload_metadata_priv_unref(md, tid, th_privs[i]);
                    }
                }
                break;
            case STEP_MIXED:
                for (i = 0; i < n_ids_per_thread; i++) {
                    struct arg arg;
                    struct data d;
                    int shuffled;

                    /* Mixed mode is doing:
                     *   1. Alloc.
                     *   2. Shuffle two elements.
                     *   3. Delete shuffled element.
                     *   4. Alloc again.
                     * The loop ends with all elements allocated.
                     */

                    d.idx = start_idx + i;
                    shuffled = random_range(i + 1);

                    if (mode == MODE_ID) {
                        offload_metadata_id_ref(md, &d, NULL, &th_ids[i]);
                        swap_u32(&th_ids[i], &th_ids[shuffled]);
                        offload_metadata_id_unref(md, tid, th_ids[i]);
                        offload_metadata_id_ref(md, &d, NULL, &th_ids[i]);
                    } else if (mode == MODE_PRIV) {
                        arg.ptr = &th_ids[i];
                        th_privs[i] = offload_metadata_priv_get(md, &d, &arg,
                                                                NULL, true);
                        swap_ptr(&th_privs[i], &th_privs[shuffled]);
                        offload_metadata_priv_unref(md, tid, th_privs[i]);
                        arg.ptr = &th_ids[i];
                        th_privs[i] = offload_metadata_priv_get(md, &d, &arg,
                                                                NULL, true);
                    }
                }
                break;
            default:
                fprintf(stderr, "[%u]: Reached step %s\n",
                        tid, step_names[step]);
                OVS_NOT_REACHED();
                break;
            }
            atomic_store(&thread_working_ms[tid], elapsed(start));
            ovs_barrier_block(&barrier_inner);
            /* Main thread prints result now. */
        }
    }

    return NULL;
}

static void
benchmark_thread_main(struct aux *aux)
{
    struct offload_metadata_parameters md_params;
    int step_idx;

    memset(&md_params, 0, sizeof md_params);
    memset(ids, 0, test_params.n_ids * sizeof *ids);
    memset(privs, 0, test_params.n_ids * sizeof *privs);

    if (aux->test.mode == MODE_ID) {
        md_params = (struct offload_metadata_parameters) {
            .id_alloc = id_alloc,
            .id_free = id_free,
        };
    } else if (aux->test.mode == MODE_PRIV) {
        md_params = (struct offload_metadata_parameters) {
            .priv_size = sizeof(struct priv),
            .priv_init = priv_init,
            .priv_uninit = priv_uninit,
        };
    }
    aux->md = offload_metadata_create(test_params.n_threads, "benchmark",
                                      sizeof(struct data), data_format,
                                      md_params);

    print_test_header(&aux->test);
    ovs_barrier_block(&barrier_inner);
    /* Init is done, worker can start preparing to work. */
    step_idx = 0;
    FOREACH_STEP(step, aux->test.schedule) {
        ovs_barrier_block(&barrier_inner);
        /* Workers do the scheduled work now. */
        ovs_barrier_block(&barrier_inner);
        print_test_result(&aux->test, step, step_idx++);
    }

    offload_metadata_destroy(aux->md);
}

static bool
parse_benchmark_params(int argc, char *argv[])
{
    long int l_threads = 0;
    long int l_ids = 0;
    bool valid = true;
    int i;

    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-d")) {
            continue;
        } else if (!strcmp(argv[i], "-csv")) {
            test_params.csv_format = true;
        } else if (!strcmp(argv[i], "-id")) {
            test_params.mode = MODE_ID;
        } else if (!strcmp(argv[i], "-priv")) {
            test_params.mode = MODE_PRIV;
        } else {
            long int l;

            errno = 0;
            l = strtol(argv[i], NULL, 10);
            if (errno != 0 || l < 0) {
                fprintf(stderr,
                        "Invalid parameter '%s', expected positive integer.\n",
                        argv[i]);
                valid = false;
                goto out;
            }
            if (l_ids == 0) {
                l_ids = l;
            } else if (l_threads == 0) {
                l_threads = l;
            } else {
                fprintf(stderr,
                        "Invalid parameter '%s', too many integer values.\n",
                        argv[i]);
                valid = false;
                goto out;
            }
        }
    }

    if (l_ids != 0) {
        test_params.n_ids = l_ids;
    } else {
        fprintf(stderr, "Invalid parameters: no number of elements given.\n");
        valid = false;
    }

    if (l_threads != 0) {
        test_params.n_threads = l_threads;
    } else {
        fprintf(stderr, "Invalid parameters: no number of threads given.\n");
        valid = false;
    }

out:
    return valid;
}

static void
run_benchmark(struct ovs_cmdl_context *ctx)
{
    pthread_t *threads;
    pthread_t clock;
    struct aux aux;
    size_t i;

    if (!parse_benchmark_params(ctx->argc, ctx->argv)) {
        return;
    }

    ids = xcalloc(test_params.n_ids, sizeof *ids);
    privs = xcalloc(test_params.n_ids, sizeof *privs);
    thread_working_ms = xcalloc(test_params.n_threads,
                                sizeof *thread_working_ms);

    clock = ovs_thread_create("clock", clock_main, NULL);

    ovsrcu_quiesce_start();
    ovs_barrier_init(&barrier_outer, test_params.n_threads + 1);
    ovs_barrier_init(&barrier_inner, test_params.n_threads + 1);
    threads = xmalloc(test_params.n_threads * sizeof *threads);
    for (i = 0; i < test_params.n_threads; i++) {
        threads[i] = ovs_thread_create("worker",
                                       benchmark_thread_worker, &aux);
    }

    print_header();
    for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
        test_cases[i].idx = i;
        if (test_params.mode != MODE_ANY &&
            test_cases[i].mode != test_params.mode) {
            continue;
        }
        /* If we don't block workers from progressing now,
         * there would be a race for access to aux.test,
         * leading to some workers not respecting the schedule.
         */
        ovs_barrier_block(&barrier_outer);
        memcpy(&aux.test, &test_cases[i], sizeof aux.test);
        benchmark_thread_main(&aux);
    }
    stop = true;
    ovs_barrier_block(&barrier_outer);

    for (i = 0; i < test_params.n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }
    free(threads);

    ovs_barrier_destroy(&barrier_outer);
    ovs_barrier_destroy(&barrier_inner);
    free(ids);
    free(privs);
    free(thread_working_ms);
    xpthread_join(clock, NULL);
}

static const struct ovs_cmdl_command commands[] = {
    {"check", "[-d]", 0, 1, run_tests, OVS_RO},
    {"benchmark", "<nb elem> <nb threads> [-id|-priv] [-d] [-csv]", 2, 5,
        run_benchmark, OVS_RO},
    {NULL, NULL, 0, 0, NULL, OVS_RO},
};

static void
parse_test_params(int argc, char *argv[])
{
    int i;

    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-d")) {
            test_params.debug = true;
        }
    }
}

static void
offload_metadata_test_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - optind,
        .argv = argv + optind,
    };

    parse_test_params(argc - optind, argv + optind);

    vlog_set_levels(NULL, VLF_ANY_DESTINATION, VLL_OFF);
    if (test_params.debug) {
        vlog_set_levels_from_string_assert("offload_metadata:console:dbg");
    }

    /* Quiesce to trigger the RCU init. */
    ovsrcu_quiesce();

    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);

    if (pool) {
        id_fpool_destroy(pool);
    }

    ovsrcu_exit();
}

OVSTEST_REGISTER("test-offload-metadata", offload_metadata_test_main);
