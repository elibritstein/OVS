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

#include <config.h>

#include "command-line.h"
#include "memory.h"
#include "metrics.h"
#include "metrics-private.h"
#include "ovstest.h"
#include "random.h"
#include "util.h"
#include "openvswitch/util.h"

static void
test_malloc_measure(void)
{
    for (int i = 0; i < 100; i++) {
        size_t before, after;
        size_t s;
        void *p;

        s = 1 + random_range(4096 * 500);

        before = after = 0;
        memory_in_use(&before);
        p = xmalloc(s);
        memory_in_use(&after);

        ovs_assert(after > before);
        ovs_assert(after - before >= s);

        free(p);
    }
}

static void
test_calloc_measure(void)
{
    for (int i = 0; i < 100; i++) {
        size_t before, after;
        size_t s;
        void *p;

        s = 1 + random_range(4096 * 500);

        before = after = 0;
        memory_in_use(&before);
        p = xcalloc(1, s);
        memory_in_use(&after);

        ovs_assert(after > before);
        ovs_assert(after - before >= s);

        free(p);
    }
}

static void
test_realloc_measure(void)
{
    for (int i = 0; i < 100; i++) {
        size_t before, after;
        size_t s;
        void *p;

        s = 1 + random_range(4096 * 500);

        before = after = 0;
        memory_in_use(&before);
        p = xrealloc(NULL, s);
        memory_in_use(&after);
        ovs_assert(after > before);
        ovs_assert(after - before >= s);

        s += 50;
        p = xrealloc(p, s);
        memory_in_use(&after);
        ovs_assert(after > before);
        ovs_assert(after - before >= s);

        s -= 10;
        p = xrealloc(p, s);
        memory_in_use(&after);
        ovs_assert(after > before);
        ovs_assert(after - before >= s);

        s = 0;
        memory_in_use(&before);
        p = xrealloc(p, s);
        memory_in_use(&after);
        ovs_assert(after <= before);

        free(p);
    }
}

static void
test_xmalloc_size_align_measure(void)
{
    for (int i = 0; i < 100; i++) {
        size_t before, after;
        size_t align;
        size_t s;
        void *p;

        s = 1 + random_range(4096 * 500);

        /* 'align' must be a power of two and a multiple of sizeof(void *). */
        align = sizeof(void *) * (UINT32_C(1) << random_range(3));

        before = after = 0;
        memory_in_use(&before);
        p = xmalloc_size_align(s, align);
        memory_in_use(&after);

        ovs_assert(after > before);
        ovs_assert(after - before >= s);

        free_size_align(p);
    }
}

static void
test_free_measure(void)
{
    for (int i = 0; i < 100; i++) {
        size_t before, after;
        size_t s;
        void *p;

        s = 1 + random_range(4096 * 500);

        before = after = 0;
        memory_in_use(&before);
        p = xmalloc(s);
        memory_in_use(&after);
        ovs_assert(after > before);
        ovs_assert(after - before >= s);

        memory_in_use(&before);
        free(p);
        memory_in_use(&after);
        ovs_assert(after < before);
    }
}

static void
test_introspect(void)
{
    if (!memory_in_use(NULL)) {
        return;
    }

    random_init();

    test_malloc_measure();
    test_calloc_measure();
    test_realloc_measure();
    test_xmalloc_size_align_measure();
    test_free_measure();
}

static void
memory_test_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    test_introspect();
}

OVSTEST_REGISTER("test-memory", memory_test_main);
