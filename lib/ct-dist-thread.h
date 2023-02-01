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

#ifndef CT_DIST_THREAD_H
#define CT_DIST_THREAD_H 1

#include "conntrack.h"
#include "conntrack-private.h"
#include "ct-dist.h"
#include "ct-dist-msg.h"
#include "mpsc-queue.h"
#include "ovs-atomic.h"
#include "ovs-thread.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define DEFAULT_CT_DIST_THREAD_NB 0
#define MAX_CT_DIST_THREAD_NB     10
DECLARE_EXTERN_PER_THREAD_DATA(unsigned int, ct_thread_id);
extern unsigned int ctd_n_threads;

struct ct_thread {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct mpsc_queue queue;
        struct conntrack *ct;
    );
};

static inline unsigned int
ct_thread_id(void)
{
    unsigned int id;

    id = *ct_thread_id_get();
    ovs_assert(id != OVSTHREAD_ID_UNSET);

    return id;
}

static inline unsigned int
ctd_h2tid(uint32_t hash)
{
    return fastrange32(hash, ctd_n_threads);
}

void ctd_thread_create(struct conntrack *ct);
void ctd_send_msg_to_thread(struct ctd_msg *m, unsigned int id);

#ifdef  __cplusplus
}
#endif

#endif /* CT_DIST_THREAD_H */
