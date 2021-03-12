/*
 * Copyright (c) 2016 Nicira, Inc.
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
#undef NDEBUG
#include "fatal-signal.h"
#include "ovs-atomic.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "ovstest.h"
#include "seq.h"
#include "timeval.h"
#include "util.h"

#include "openvswitch/poll-loop.h"

static void *
quiescer_main(void *aux OVS_UNUSED)
{
    /* A new thread must be not be quiescent */
    ovs_assert(!ovsrcu_is_quiescent());
    ovsrcu_quiesce_start();
    /* After the above call it must be quiescent */
    ovs_assert(ovsrcu_is_quiescent());

    return NULL;
}

static void
test_rcu_quiesce(void)
{
    pthread_t quiescer;

    quiescer = ovs_thread_create("quiescer", quiescer_main, NULL);

    /* This is the main thread of the process. After spawning its first
     * thread it must not be quiescent. */
    ovs_assert(!ovsrcu_is_quiescent());

    xpthread_join(quiescer, NULL);
}

static void
add_count(void *_count)
{
    unsigned *count = (unsigned *)_count;
    (*count) ++;
}

static void
test_rcu_barrier(void)
{
    unsigned count = 0;
    for (int i = 0; i < 10; i ++) {
        ovsrcu_postpone(add_count, &count);
    }

    ovsrcu_barrier();
    ovs_assert(count == 10);
}

struct element {
    struct ovsrcu_node rcu_node;
    struct seq *trigger;
    atomic_bool wait;
};

static void
trigger_cb(void *e_)
{
    struct element *e = (struct element *) e_;

    seq_change(e->trigger);
}

static void *
wait_main(void *aux)
{
    struct element *e = aux;

    for (;;) {
        bool wait;

        atomic_read(&e->wait, &wait);
        if (!wait) {
            break;
        }
    }

    seq_wait(e->trigger, seq_read(e->trigger));
    poll_block();

    return NULL;
}

static void
test_rcu_postpone_embedded(bool multithread)
{
    long long int timeout;
    pthread_t waiter;
    struct element e;
    uint64_t seqno;

    atomic_init(&e.wait, true);

    if (multithread) {
        waiter = ovs_thread_create("waiter", wait_main, &e);
    }

    e.trigger = seq_create();
    seqno = seq_read(e.trigger);

    ovsrcu_postpone_embedded(trigger_cb, &e, rcu_node);

    /* Check that GC holds out until all threads are quiescent. */
    timeout = time_msec();
    if (multithread) {
        timeout += 200;
    }
    while (time_msec() <= timeout) {
        ovs_assert(seq_read(e.trigger) == seqno);
    }

    atomic_store(&e.wait, false);

    seq_wait(e.trigger, seqno);
    poll_timer_wait_until(time_msec() + 200);
    poll_block();

    /* Verify that GC executed. */
    ovs_assert(seq_read(e.trigger) != seqno);
    seq_destroy(e.trigger);

    if (multithread) {
        xpthread_join(waiter, NULL);
    }
}

#define N_ORDER_CBS 5

struct order_element {
    struct ovsrcu_node rcu_node;
    int id;
    int *log;
    int *log_idx;
};

static void
order_cb(void *aux)
{
    struct order_element *e = aux;
    e->log[(*e->log_idx)++] = e->id;
}

static void
test_rcu_ordering(void)
{
    struct order_element elems[N_ORDER_CBS];
    int log[N_ORDER_CBS];
    int log_idx = 0;

    for (int i = 0; i < N_ORDER_CBS; i++) {
        elems[i].id = i;
        elems[i].log = log;
        elems[i].log_idx = &log_idx;
        ovsrcu_postpone_embedded(order_cb, &elems[i], rcu_node);
    }

    ovsrcu_barrier();

    ovs_assert(log_idx == N_ORDER_CBS);
    for (int i = 0; i < N_ORDER_CBS; i++) {
        if (log[i] != i) {
            ovs_abort(0, "RCU embedded callback ordering violated: "
                      "expected cb %d at position %d, got %d",
                      i, i, log[i]);
        }
    }
}

static void
test_rcu(int argc OVS_UNUSED, char *argv[] OVS_UNUSED) {
    const bool multithread = true;

    /* Execute single-threaded check before spawning additional threads. */
    test_rcu_postpone_embedded(!multithread);
    test_rcu_postpone_embedded(multithread);

    test_rcu_quiesce();
    test_rcu_barrier();
    test_rcu_ordering();
}

OVSTEST_REGISTER("test-rcu", test_rcu);
