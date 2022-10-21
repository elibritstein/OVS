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

#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "introspect.h"

#include "util.h"
#include "openvswitch/compiler.h"
#include "openvswitch/util.h"
#include "ovs-atomic.h"

static atomic_size_t used_memory;
static bool override_enabled;

bool
introspect_used_memory(size_t *n_bytes)
{
    if (!override_enabled) {
        return false;
    }
    if (n_bytes) {
        atomic_read_relaxed(&used_memory, n_bytes);
    }
    return true;
}

#ifdef HAVE_DL

typedef void * (*malloc_fn)(size_t n);
typedef void * (*calloc_fn)(size_t m, size_t n);
typedef void * (*realloc_fn)(void *p, size_t n);
typedef void   (*free_fn)(void *p);
typedef size_t (*usable_size_fn)(void *);

static malloc_fn orig_malloc;
static calloc_fn orig_calloc;
static realloc_fn orig_realloc;
static free_fn orig_free;

extern void *__libc_malloc(size_t size);
extern void *__libc_calloc(size_t m, size_t n);
extern void *__libc_realloc(void *p, size_t n);
extern void __libc_free(void *ptr);

static usable_size_fn intr_usable_size;

struct header {
    size_t size;
};

#define memory_used_add(__n) do { \
    size_t __old; (void) __old; \
    atomic_add_relaxed(&used_memory, __n, &__old); \
} while (0)

#define memory_used_sub(__n) do { \
    size_t __old; (void) __old; \
    atomic_sub_relaxed(&used_memory, __n, &__old); \
} while (0)

static void *
intr_malloc(size_t n)
{
    struct header *head;

    if (intr_usable_size) {
        void *p = orig_malloc(n);

        memory_used_add(intr_usable_size(p));
        return p;
    }

    head = orig_malloc(sizeof(*head) + n);
    if (head == NULL) {
        return NULL;
    }

    head->size = sizeof(*head) + n;
    memory_used_add(head->size);

    return head + 1;
}

/*
 * This is sqrt(SIZE_MAX+1), such that if both
 * s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 * then (s1 * s2) <= SIZE_MAX.
 */
#define MUL_NO_OVERFLOW (1UL << (sizeof(size_t) * 4))

/* Return true if m * n > SIZE_MAX.
 * Try to reduce the number of divisions.
 */
static inline bool
size_overflow(size_t m, size_t n)
{
    return (m >= MUL_NO_OVERFLOW || n >= MUL_NO_OVERFLOW) &&
            m > 0 && SIZE_MAX / m < n;
}

static void *
intr_calloc(size_t m, size_t n)
{
    struct header *head;
    size_t mul;

    if (intr_usable_size) {
        void *p = orig_calloc(m, n);

        memory_used_add(intr_usable_size(p));
        return p;
    }

    ovs_assert(!size_overflow(m, n));
    mul = m * n;
    ovs_assert(mul < SIZE_MAX - sizeof(*head));

    head = orig_calloc(1, sizeof(*head) + mul);
    if (head == NULL) {
        return NULL;
    }

    head->size = sizeof(*head) + mul;
    memory_used_add(head->size);

    return head + 1;
}

static void *
intr_realloc(void *p, size_t n)
{
    struct header *phead;
    struct header *head;

    if (intr_usable_size) {
        size_t old_use = intr_usable_size(p);
        void *new_p = orig_realloc(p, n);
        size_t new_use = intr_usable_size(new_p);

        if (old_use < new_use) {
            memory_used_add(new_use - old_use);
        } else if (old_use > new_use) {
            memory_used_sub(old_use - new_use);
        }

        return new_p;
    }

    phead = p ? ((struct header *) p) - 1 : NULL;
    if (phead) {
        memory_used_sub(phead->size);
    }

    head = orig_realloc(phead, sizeof(*head) + n);
    if (head == NULL) {
        return NULL;
    }

    head->size = sizeof(*head) + n;
    memory_used_add(head->size);

    return head + 1;
}

static void
intr_free(void *p)
{
    struct header *head;
    size_t s;

    if (intr_usable_size) {
        memory_used_sub(intr_usable_size(p));
        orig_free(p);
        return;
    }

    if (p == NULL) {
        return;
    }

    head = ((struct header *) p) - 1;
    s = head->size;
    orig_free(head);

    memory_used_sub(s);
}

void *
malloc(size_t n)
{
    if (!override_enabled) {
        return __libc_malloc(n);
    }

    return intr_malloc(n);
}

void *
calloc(size_t m, size_t n)
{
    if (!override_enabled) {
        return __libc_calloc(m, n);
    }

    return intr_calloc(m, n);
}

void *
realloc(void *p, size_t n)
{
    if (!override_enabled) {
        return __libc_realloc(p, n);
    }

    return intr_realloc(p, n);
}

void
free(void *p)
{
    if (!override_enabled) {
        return __libc_free(p);
    }

    return intr_free(p);
}

#ifdef HAVE_POSIX_MEMALIGN

typedef int (*posix_memalign_fn)(void **memptr, size_t align, size_t s);
static posix_memalign_fn orig_posix_memalign;
extern int __posix_memalign(void **memptr, size_t align, size_t s);

static int
intr_posix_memalign(void **memptr, size_t align, size_t s)
{
    struct header *head;
    void *p;
    int ret;

    if (intr_usable_size) {
        ret = orig_posix_memalign(&p, align, s);

        if (ret == 0) {
            memory_used_add(intr_usable_size(p));
            *memptr = p;
        }
        return ret;
    }

    ret = orig_posix_memalign(&p, align, sizeof(*head) + s);
    if (ret != 0) {
        return ret;
    }

    head = p;
    head->size = sizeof(*head) + s;
    memory_used_add(head->size);

    return ret;
}

int
posix_memalign(void **memptr, size_t align, size_t s)
{
    if (!override_enabled) {
        /* Not allowed to posix_memalign in very early stage of
         * startup. There is no hook mechanism for this posix extension,
         * and it will only be used afterward. */
        return ENOMEM;
    }

    return intr_posix_memalign(memptr, align, s);
}

#endif /* HAVE_POSIX_MEMALIGN */

/* According to GCC:
 * "constructor priorities from 0 to 100 are reserved for the implementation",
 * use the highest available priorities (the lower the number, the earlier
 * this function executes). Ensure that the destructor is symmetrical. */
__attribute__((constructor(101), used))
static void introspect_init(void)
{
    static const char *syms[] = {
        "tc_malloc_size",
        "je_malloc_usable_size",
        "malloc_usable_size",
        "malloc_size",
        "_msize",
    };
    size_t i;

    for (i = 0; i < ARRAY_SIZE(syms); i++) {
        intr_usable_size = dlsym(RTLD_DEFAULT, syms[i]);
        if (intr_usable_size != NULL) {
            break;
        }
    }

    orig_malloc = dlsym(RTLD_NEXT, "malloc");
    ovs_assert(orig_malloc != NULL);

    orig_calloc = dlsym(RTLD_NEXT, "calloc");
    ovs_assert(orig_calloc != NULL);

    orig_realloc = dlsym(RTLD_NEXT, "realloc");
    ovs_assert(orig_realloc != NULL);

    orig_free = dlsym(RTLD_NEXT, "free");
    ovs_assert(orig_free != NULL);

#ifdef HAVE_POSIX_MEMALIGN
    orig_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
    ovs_assert(orig_posix_memalign != NULL);
#endif

    override_enabled = true;
}

__attribute__((destructor(101), used))
static void introspect_fini(void)
{
    override_enabled = false;
}

#endif /* HAVE_DL */
