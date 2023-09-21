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

OVS_ASSERT_PACKED(struct key,
    size_t idx;
    bool b;
    uint8_t pad[7];
);

struct value {
    void *hdl;
};

struct arg {
    void *ptr;
};

static int
value_init(void *value_, void *arg_)
{
    struct value *value = value_;
    struct arg *arg = arg_;

    /* Verify that we don't double-init value. */
    ovs_assert(value->hdl == NULL);

    value->hdl = arg->ptr;
    return 0;
}

static void
value_uninit(void *value_)
{
    struct value *value = value_;

    /* Verify that we don't double-uninit value. */
    ovs_assert(value->hdl != NULL);

    value->hdl = NULL;
}

static struct ds *
value_format(struct ds *s,
             void *key_, void *value_, void *arg_)
{
    struct key *key = key_;
    struct value *value = value_;
    struct arg *arg = arg_;

    ds_put_format(s, "idx=%"PRIuSIZE", b=%s, hdl=%p, ptr=%p",
                  key->idx, key->b ? "1" : "0",
                  value->hdl, arg->ptr);
    return s;
}

static void
run_check(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct value *values[N];
    struct key keys[N];
    struct refmap *rfm;

    rfm = refmap_create("check-rfm", sizeof(struct key), sizeof(struct value),
                        value_init, value_uninit, value_format);

    memset(keys, 0, sizeof keys);
    for (int i = 0; i < N; i++) {
        struct arg arg = {
            .ptr = &keys[i],
        };
        struct value *value;

        keys[i].idx = i;
        ovs_assert(NULL == refmap_try_ref(rfm, &keys[i]));
        value = refmap_ref(rfm, &keys[i], &arg);
        ovs_assert(value != NULL);
        ovs_assert(value == refmap_ref(rfm, &keys[i], &arg));
        refmap_unref(rfm, value);
        ovs_assert(value == refmap_try_ref(rfm, &keys[i]));
        refmap_unref(rfm, value);
        values[i] = value;
    }

    for (int i = 0; i < N; i++) {
        /* Verify that value_init is properly called. */
        ovs_assert(values[i]->hdl != NULL);
    }

    for (int i = 0; i < N; i++) {
        refmap_unref(rfm, values[i]);
    }

    for (int i = 0; i < N; i++) {
        ovs_assert(NULL == refmap_try_ref(rfm, &keys[i]));
    }

    for (int i = 0; i < N; i++) {
        /* Verify that value_uninit is executed. */
        ovs_assert(values[i]->hdl == NULL);
    }

    refmap_destroy(rfm);
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
    uint64_t *twm;
    uint64_t avg;
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
        printf("%s,%" PRIu64, test_name, avg);
    } else {
        printf("%*s: ", 18, test_name);
        printf(" %6" PRIu64, avg);
        for (i = 0; i < params.n_threads; i++) {
            printf(" %6" PRIu64, twm[i]);
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
