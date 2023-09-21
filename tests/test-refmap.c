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

#include <config.h>

#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>

#include "ovs-atomic.h"
#include "ovs-numa.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "ovstest.h"
#include "random.h"
#include "refmap.h"
#include "timeval.h"
#include "util.h"

#include "openvswitch/util.h"
#include "openvswitch/vlog.h"

#define N 100

static struct refmap_test_params {
    unsigned int n_threads;
    unsigned int n_ids;
    int step_idx;
    bool debug;
    bool csv_format;
} params = {
    .n_threads = 1,
    .n_ids = N,
    .debug = false,
    .csv_format = false,
};

DEFINE_STATIC_PER_THREAD_DATA(unsigned int, thread_id, OVSTHREAD_ID_UNSET);

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

struct key {
    size_t idx;
    bool b;
    uint8_t pad[7];
};

struct value {
    uint32_t *hdl;
};

struct arg {
    uint32_t *ptr;
};

static int
value_init(void *value_, void *arg_)
{
    struct value *value = value_;
    struct arg *arg = arg_;

    /* Verify that we don't double-init value. */
    ovs_assert(!value->hdl);

    *arg->ptr = 1;
    value->hdl = arg->ptr;
    return 0;
}

static void
value_uninit(void *value_)
{
    struct value *value = value_;

    /* Verify that we don't double-uninit value. */
    ovs_assert(value->hdl);

    *value->hdl = 2;
    value->hdl = NULL;
}

static struct ds *
value_format(struct ds *s, void *key_, void *value_)
{
    struct key *key = key_;
    struct value *value = value_;

    ds_put_format(s, "idx=%"PRIuSIZE", b=%s, hdl=%p",
                  key->idx, key->b ? "1" : "0",
                  value->hdl);
    return s;
}

struct check_refmap_ctx {
    struct refmap *rfm;
    struct value **values;
    int count;
};

static void
check_refmap_cb(void *value_, void *key_, void *arg_)
{
    struct check_refmap_ctx *ctx = arg_;
    struct key *key = key_;

    ovs_assert(key->idx < N);
    if (ctx->values) {
        ovs_assert(ctx->values[key->idx] == value_);
    }

    ctx->count++;
}

static void
check_refmap(struct refmap *rfm, struct value **values, int n_expected)
{
    struct check_refmap_ctx ctx = {
        .rfm = rfm,
        .values = values,
        .count = 0,
    };

    refmap_for_each(rfm, check_refmap_cb, &ctx);
    ovs_assert(ctx.count == n_expected);
}

struct iter_modify_ctx {
    struct refmap *rfm;
    struct key *keys;
    struct value **extra_refs;
    int ref_count;
    int unref_count;
};

static void
iter_ref_cb(void *value_, void *key_, void *arg_)
{
    struct iter_modify_ctx *ctx = arg_;
    struct key *key = key_;

    ovs_assert(refmap_try_ref_value(ctx->rfm, value_));
    ctx->extra_refs[key->idx] = value_;
    ctx->ref_count++;
}

static void
iter_unref_cb(void *value_, void *key_ OVS_UNUSED, void *arg_)
{
    struct iter_modify_ctx *ctx = arg_;

    refmap_unref(ctx->rfm, value_);
    ctx->unref_count++;
}

struct try_ref_race_ctx {
    struct refmap *rfm;
    struct key key;
    atomic_bool stop;
};

static void
race_for_each_cb(void *value_, void *key_ OVS_UNUSED, void *arg_ OVS_UNUSED)
{
    struct value *value = value_;

    ovs_assert(value->hdl);
}

static void *
try_ref_racer(void *arg)
{
    struct try_ref_race_ctx *ctx = arg;

    for (;;) {
        bool stop_;

        atomic_read(&ctx->stop, &stop_);
        if (stop_) {
            break;
        }

        void *value = refmap_try_ref(ctx->rfm, &ctx->key);
        if (value) {
            struct value *v = value;

            ovs_assert(v->hdl);
            refmap_unref(ctx->rfm, value);
        }

        refmap_for_each(ctx->rfm, race_for_each_cb, NULL);
    }

    return NULL;
}

/* Stress-test that try_ref rejects entries at refcount 1 (the internal
 * reference used during value init/uninit synchronization).
 *
 * Thread A repeatedly creates and destroys the same entry.
 * Thread B continuously calls try_ref and for_each. */
static void
check_try_ref_race(void)
{
    struct try_ref_race_ctx race_ctx;
    pthread_t worker;
    struct refmap *rfm;

    rfm = refmap_create("try-ref-race", sizeof(struct key),
                        sizeof(struct value), value_init, value_uninit,
                        value_format);

    memset(&race_ctx.key, 0, sizeof race_ctx.key);
    race_ctx.key.idx = 0;
    race_ctx.rfm = rfm;
    atomic_init(&race_ctx.stop, false);

    worker = ovs_thread_create("try-ref-racer", try_ref_racer, &race_ctx);

    for (int i = 0; i < 10000; i++) {
        uint32_t arg_val = 0;
        struct arg arg = { .ptr = &arg_val };
        void *value;

        value = refmap_ref(rfm, &race_ctx.key, &arg);
        refmap_unref(rfm, value);
    }

    atomic_store(&race_ctx.stop, true);
    xpthread_join(worker, NULL);

    refmap_destroy(rfm);
}

static void
run_check(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct iter_modify_ctx im_ctx;
    struct value *extra_refs[N];
    struct value *values[N];
    struct key keys[N];
    struct refmap *rfm;
    uint32_t args[N];

    rfm = refmap_create("check-rfm", sizeof(struct key), sizeof(struct value),
                        value_init, value_uninit, value_format);

    check_refmap(rfm, NULL, 0);

    memset(keys, 0, sizeof keys);
    for (int i = 0; i < N; i++) {
        struct arg arg = {
            .ptr = &args[i],
        };
        struct value *value;

        keys[i].idx = i;
        args[i] = i;
        ovs_assert(!refmap_try_ref(rfm, &keys[i]));
        value = refmap_ref(rfm, &keys[i], &arg);
        ovs_assert(value);
        ovs_assert(value == refmap_ref(rfm, &keys[i], &arg));
        refmap_unref(rfm, value);
        ovs_assert(value == refmap_try_ref(rfm, &keys[i]));
        refmap_unref(rfm, value);
        values[i] = value;
    }

    check_refmap(rfm, (struct value **) values, N);

    for (int i = 0; i < N; i++) {
        /* Verify that value_init is properly called. */
        ovs_assert(values[i]->hdl == &args[i]);
        ovs_assert(args[i] == 1);
    }

    /* Verify refmap_value_refcount_read: each value has one user ref. */
    for (int i = 0; i < N; i++) {
        ovs_assert(refmap_value_refcount_read(rfm, values[i]) == 1);
    }

    ovs_assert(refmap_value_refcount_read(rfm, NULL) == 0);

    /* Verify refmap_key_from_value. */
    for (int i = 0; i < N; i++) {
        struct key *k = refmap_key_from_value(rfm, values[i]);
        ovs_assert(k->idx == keys[i].idx);
    }

    /* Verify refmap_try_ref_value and refcount changes. */
    for (int i = 0; i < N; i++) {
        ovs_assert(refmap_try_ref_value(rfm, values[i]));
        ovs_assert(refmap_value_refcount_read(rfm, values[i]) == 2);
        refmap_unref(rfm, values[i]);
        ovs_assert(refmap_value_refcount_read(rfm, values[i]) == 1);
    }

    ovs_assert(!refmap_try_ref_value(rfm, NULL));

    check_refmap(rfm, (struct value **) values, N);

    /* Take extra refs from within refmap_for_each callback. */
    memset(&im_ctx, 0, sizeof im_ctx);
    im_ctx.rfm = rfm;
    im_ctx.keys = keys;
    im_ctx.extra_refs = (struct value **) extra_refs;
    memset(extra_refs, 0, sizeof extra_refs);
    refmap_for_each(rfm, iter_ref_cb, &im_ctx);
    ovs_assert(im_ctx.ref_count == N);
    for (int i = 0; i < N; i++) {
        ovs_assert(extra_refs[i] == values[i]);
        ovs_assert(refmap_value_refcount_read(rfm, values[i]) == 2);
    }

    check_refmap(rfm, (struct value **) values, N);

    /* Drop extra refs from within refmap_for_each callback. */
    memset(&im_ctx, 0, sizeof im_ctx);
    im_ctx.rfm = rfm;
    refmap_for_each(rfm, iter_unref_cb, &im_ctx);
    ovs_assert(im_ctx.unref_count == N);
    for (int i = 0; i < N; i++) {
        ovs_assert(refmap_value_refcount_read(rfm, values[i]) == 1);
    }

    check_refmap(rfm, (struct value **) values, N);

    for (int i = 0; i < N; i++) {
        refmap_unref(rfm, values[i]);
    }

    for (int i = 0; i < N; i++) {
        ovs_assert(!refmap_try_ref(rfm, &keys[i]));
    }

    for (int i = 0; i < N; i++) {
        /* Verify that value_uninit is executed. */
        ovs_assert(args[i] == 2);
    }

    check_refmap(rfm, NULL, 0);

    refmap_destroy(rfm);

    check_try_ref_race();
}

static uint32_t *ids;
static void **values;
static atomic_uint *thread_working_ms; /* Measured work time. */

static struct ovs_barrier barrier_outer;
static struct ovs_barrier barrier_inner;

static atomic_uint running_time_ms;
static atomic_bool stop;

static unsigned int
elapsed(unsigned int start)
{
    unsigned int running_time_ms_;

    atomic_read(&running_time_ms, &running_time_ms_);

    return running_time_ms_ - start;
}

static void *
clock_main(void *arg OVS_UNUSED)
{
    struct timeval start;
    struct timeval end;

    xgettimeofday(&start);
    for (;;) {
        bool stop_;

        atomic_read(&stop, &stop_);
        if (stop_) {
            break;
        }

        xgettimeofday(&end);
        atomic_store(&running_time_ms,
                     timeval_to_msec(&end) - timeval_to_msec(&start));
        xnanosleep(100 * 1000);
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

struct test_case {
    int idx;
    enum step_id schedule[MAX_N_STEP];
};

static void
print_header(void)
{
    if (params.csv_format) {
        return;
    }

    printf("Benchmarking n=%u on %u thread%s.\n",
           params.n_ids, params.n_threads,
           params.n_threads > 1 ? "s" : "");

    printf("       step\\thread: ");
    printf("    Avg");
    for (size_t i = 0; i < params.n_threads; i++) {
        printf("    %3" PRIuSIZE, i + 1);
    }

    printf("\n");
}

static void
print_test_header(struct test_case *test)
{
    if (params.csv_format) {
        return;
    }

    printf("[%d]---------------------------", test->idx);
    for (size_t i = 0; i < params.n_threads; i++) {
        printf("-------");
    }

    printf("\n");
}

static void
print_test_result(struct test_case *test, enum step_id step, int step_idx)
{
    char test_name[50];
    uint32_t *twm;
    uint32_t avg;
    size_t i;

    twm = xcalloc(params.n_threads, sizeof *twm);
    for (i = 0; i < params.n_threads; i++) {
        atomic_read(&thread_working_ms[i], &twm[i]);
    }

    avg = 0;
    for (i = 0; i < params.n_threads; i++) {
        avg += twm[i];
    }

    ovs_assert(params.n_threads);
    avg /= params.n_threads;

    snprintf(test_name, sizeof test_name, "%d.%d-%s",
             test->idx, step_idx,
             step_names[step]);
    if (params.csv_format) {
        printf("%s,%" PRIu32, test_name, avg);
    } else {
        printf("%*s: ", 18, test_name);
        printf(" %6" PRIu32, avg);
        for (i = 0; i < params.n_threads; i++) {
            printf(" %6" PRIu32, twm[i]);
        }
        printf(" ms");
    }

    printf("\n");

    free(twm);
}

static struct test_case test_cases[] = {
    {
        .schedule = {
            STEP_ALLOC,
            STEP_FREE,
        },
    },
    {
        .schedule = {
            STEP_ALLOC,
            STEP_REF,
            STEP_UNREF,
            STEP_FREE,
        },
    },
    {
        .schedule = {
            STEP_MIXED,
            STEP_FREE,
        },
    },
    {
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
swap_ptr(void **a, void **b)
{
    void *t;
    t = *a;
    *a = *b;
    *b = t;
}

struct aux {
    struct test_case test;
    struct refmap *rfm;
};

static void *
benchmark_thread_worker(void *aux_)
{
    unsigned int tid = thread_id();
    unsigned int n_ids_per_thread;
    unsigned int start_idx;
    struct aux *aux = aux_;
    struct refmap *rfm;
    unsigned int start;
    uint32_t *th_ids;
    void **th_privs;
    void *value;
    size_t i;

    n_ids_per_thread = params.n_ids / params.n_threads;
    start_idx = tid * n_ids_per_thread;
    th_privs = &values[start_idx];
    th_ids = &ids[start_idx];

    for (;;) {
        bool stop_;

        ovs_barrier_block(&barrier_outer);
        atomic_read(&stop, &stop_);
        if (stop_) {
            break;
        }

        /* Wait for main thread to finish initializing
         * rfm and step schedule. */
        ovs_barrier_block(&barrier_inner);
        rfm = aux->rfm;

        FOREACH_STEP(step, aux->test.schedule) {
            ovs_barrier_block(&barrier_inner);
            atomic_read(&running_time_ms, &start);
            switch (step) {
            case STEP_ALLOC:
            case STEP_REF:
                for (i = 0; i < n_ids_per_thread; i++) {
                    struct key key = {
                        .idx = start_idx + i,
                    };
                    struct arg arg = {
                        .ptr = &th_ids[i],
                    };

                    th_privs[i] = refmap_ref(rfm, &key, &arg);
                }
                break;
            case STEP_POS_QUERY:
                for (i = 0; i < n_ids_per_thread; i++) {
                    struct key key = {
                        .idx = start_idx + i,
                    };
                    value = refmap_try_ref(rfm, &key);
                    refmap_unref(rfm, value);
                }
                break;
            case STEP_NEG_QUERY:
                for (i = 0; i < n_ids_per_thread; i++) {
                    struct key key = {
                        .idx = params.n_ids + 1,
                    };
                    value = refmap_try_ref(rfm, &key);
                    refmap_unref(rfm, value);
                }
                break;
            case STEP_UNREF:
            case STEP_FREE:
                for (i = 0; i < n_ids_per_thread; i++) {
                    refmap_unref(rfm, th_privs[i]);
                }
                break;
            case STEP_MIXED:
                for (i = 0; i < n_ids_per_thread; i++) {
                    struct arg arg;
                    struct key key;
                    int shuffled;

                    /* Mixed mode is doing:
                     *   1. Alloc.
                     *   2. Shuffle two elements.
                     *   3. Delete shuffled element.
                     *   4. Alloc again.
                     * The loop ends with all elements allocated.
                     */

                    memset(&key, 0, sizeof key);
                    key.idx = start_idx + i;
                    shuffled = random_range(i + 1);

                    arg.ptr = &th_ids[i];
                    th_privs[i] = refmap_ref(rfm, &key, &arg);
                    swap_ptr(&th_privs[i], &th_privs[shuffled]);
                    refmap_unref(rfm, th_privs[i]);
                    arg.ptr = &th_ids[i];
                    th_privs[i] = refmap_ref(rfm, &key, &arg);
                }
                break;
            default:
                fprintf(stderr, "[%u]: Reached step %d\n",
                        tid, step);
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
    int step_idx;

    memset(ids, 0, params.n_ids * sizeof *ids);
    memset(values, 0, params.n_ids * sizeof *values);

    aux->rfm = refmap_create("benchmark-rfm", sizeof(struct key),
                             sizeof(struct value), value_init, value_uninit,
                             value_format);

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

    refmap_destroy(aux->rfm);
}

static bool
parse_benchmark_params(int argc, char *argv[])
{
    long int l_threads = 0;
    long int l_ids = 0;
    bool valid = true;
    long int l;
    int i;

    params.step_idx = -1;
    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "benchmark") ||
            !strcmp(argv[i], "debug")) {
            continue;
        } else if (!strcmp(argv[i], "csv")) {
            params.csv_format = true;
        } else if (!strncmp(argv[i], "step=", 5)) {
            if (!str_to_long(&argv[i][5], 10, &l)) {
                fprintf(stderr,
                        "Invalid parameter '%s', expected positive integer.\n",
                        argv[i]);
                valid = false;
                goto out;
            }

            params.step_idx = l;
        } else {
            if (!str_to_long(argv[i], 10, &l)) {
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
        params.n_ids = l_ids;
    } else {
        fprintf(stderr, "Invalid parameters: no number of elements given.\n");
        valid = false;
    }

    if (l_threads != 0) {
        params.n_threads = l_threads;
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

    ids = xcalloc(params.n_ids, sizeof *ids);
    values = xcalloc(params.n_ids, sizeof *values);
    thread_working_ms = xcalloc(params.n_threads,
                                sizeof *thread_working_ms);
    for (i = 0; i < params.n_threads; i++) {
        atomic_init(&thread_working_ms[i], 0);
    }

    atomic_init(&stop, false);

    clock = ovs_thread_create("clock", clock_main, NULL);

    ovsrcu_quiesce_start();
    ovs_barrier_init(&barrier_outer, params.n_threads + 1);
    ovs_barrier_init(&barrier_inner, params.n_threads + 1);
    threads = xmalloc(params.n_threads * sizeof *threads);
    for (i = 0; i < params.n_threads; i++) {
        threads[i] = ovs_thread_create("worker",
                                       benchmark_thread_worker, &aux);
    }

    print_header();
    for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
        test_cases[i].idx = i;
        if (params.step_idx != -1 &&
            params.step_idx != i) {
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

    atomic_store(&stop, true);
    ovs_barrier_block(&barrier_outer);

    for (i = 0; i < params.n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }

    free(threads);

    ovs_barrier_destroy(&barrier_outer);
    ovs_barrier_destroy(&barrier_inner);
    free(ids);
    free(values);
    free(thread_working_ms);
    xpthread_join(clock, NULL);
}

static const struct ovs_cmdl_command commands[] = {
    {"check", "[debug]", 0, 1, run_check, OVS_RO},
    {"benchmark", "<nb elem> <nb threads> [step=<uint>] [csv]", 0, 4,
     run_benchmark, OVS_RO},
    {NULL, NULL, 0, 0, NULL, OVS_RO},
};

static void
parse_test_params(int argc, char *argv[])
{
    int i;

    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "debug")) {
            params.debug = true;
        }
    }
}

static void
refmap_test_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - optind,
        .argv = argv + optind,
    };

    parse_test_params(argc - optind, argv + optind);

    vlog_set_levels(NULL, VLF_ANY_DESTINATION, VLL_OFF);
    if (params.debug) {
        vlog_set_levels_from_string_assert("refmap:console:dbg");
    }

    /* Quiesce to start the RCU. */
    ovsrcu_quiesce();

    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);

    ovsrcu_exit();
}

OVSTEST_REGISTER("test-refmap", refmap_test_main);
