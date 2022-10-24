/*
 * Copyright (c) 2012, 2013 Nicira, Inc.
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

#ifdef __linux__
#include <unistd.h>
#endif

#include "memory.h"
#include <stdbool.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "introspect.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/poll-loop.h"
#include "metrics.h"
#include "simap.h"
#include "timeval.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(memory);

/* The number of milliseconds before the first report of daemon memory usage,
 * and the number of milliseconds between checks for daemon memory growth.  */
#define MEMORY_CHECK_INTERVAL (10 * 1000)

/* When we should next check memory usage and possibly trigger a report. */
static long long int next_check;

/* The last time at which we reported memory usage, and the usage we reported
 * at that time. */
static long long int last_report;
static unsigned long int last_reported_maxrss;

/* Are we expecting a call to memory_report()? */
static bool want_report;

/* Unixctl connections waiting for responses. */
static struct unixctl_conn **conns;
static size_t n_conns;

static void memory_init(void);

/* Runs the memory monitor.
 *
 * The client should call memory_should_report() afterward.
 *
 * This function, and the remainder of this module's interface, should be
 * called from only a single thread. */
void
memory_run(void)
{
    struct rusage usage;
    long long int now;

    memory_init();

    /* Time for a check? */
    now = time_msec();
    if (now < next_check) {
        return;
    }
    next_check = now + MEMORY_CHECK_INTERVAL;

    /* Time for a report? */
    getrusage(RUSAGE_SELF, &usage);
    if (!last_reported_maxrss) {
        VLOG_INFO("%lu kB peak resident set size after %.1f seconds",
                  (unsigned long int) usage.ru_maxrss,
                  (now - time_boot_msec()) / 1000.0);
    } else if (usage.ru_maxrss >= last_reported_maxrss * 1.5) {
        VLOG_INFO("peak resident set size grew %.0f%% in last %.1f seconds, "
                  "from %lu kB to %lu kB",
                  ((double) usage.ru_maxrss / last_reported_maxrss - 1) * 100,
                  (now - last_report) / 1000.0,
                  last_reported_maxrss, (unsigned long int) usage.ru_maxrss);
    } else {
        return;
    }

    /* Request a report. */
    want_report = true;
    last_report = now;
    last_reported_maxrss = usage.ru_maxrss;
}

/* Causes the poll loop to wake up if the memory monitor needs to run. */
void
memory_wait(void)
{
    if (memory_should_report()) {
        poll_immediate_wake();
    }
}

/* Returns true if the caller should log some information about memory usage
 * (with memory_report()), false otherwise. */
bool
memory_should_report(void)
{
    return want_report || n_conns > 0;
}

static void
compose_report(const struct simap *usage, struct ds *s)
{
    const struct simap_node **nodes = simap_sort(usage);
    size_t n = simap_count(usage);
    size_t i;

    for (i = 0; i < n; i++) {
        const struct simap_node *node = nodes[i];

        ds_put_format(s, "%s:%u ", node->name, node->data);
    }
    ds_chomp(s, ' ');
    free(nodes);
}

/* Logs the contents of 'usage', as a collection of name-count pairs.
 *
 * 'usage' should capture large-scale statistics that one might reasonably
 * expect to correlate with memory usage.  For example, each OpenFlow flow
 * requires some memory, so ovs-vswitchd includes the total number of flows in
 * 'usage'. */
void
memory_report(const struct simap *usage)
{
    struct ds s;
    size_t i;

    ds_init(&s);
    compose_report(usage, &s);

    if (want_report) {
        if (s.length) {
            VLOG_INFO("%s", ds_cstr(&s));
        }
        want_report = false;
    }
    if (n_conns) {
        for (i = 0; i < n_conns; i++) {
            unixctl_command_reply(conns[i], ds_cstr(&s));
        }
        free(conns);
        conns = NULL;
        n_conns = 0;
    }

    ds_destroy(&s);
}

static void
memory_unixctl_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    conns = xrealloc(conns, (n_conns + 1) * sizeof *conns);
    conns[n_conns++] = conn;
}

static void
memory_metrics_register(void);

static void
memory_init(void)
{
    static bool inited = false;

    if (!inited) {
        inited = true;
        unixctl_command_register("memory/show", "", 0, 0,
                                 memory_unixctl_show, NULL);
        memory_metrics_register();

        next_check = time_boot_msec() + MEMORY_CHECK_INTERVAL;
    }
}

#if defined(__linux__) && defined(__GLIBC__)

struct memory_measure {
    size_t vms; /* Total size in bytes. */
    size_t rss; /* RSS in bytes. */
    size_t shared; /* Resident shared pages: RssFile+RssShmem in bytes. */
    size_t text; /* Text size of the process (code) in bytes. */
    size_t data; /* (data + stack) size of the process in bytes. */
    size_t in_use; /* Internal measure of used memory in bytes. */
};

static bool
introspect_enabled(void *it OVS_UNUSED)
{
    return introspect_used_memory(NULL);
}

static bool
memory_read_statm(struct memory_measure *m)
{
    size_t pagesize = get_page_size();
    FILE *stream;
    int n;

    stream = fopen("/proc/self/statm", "r");
    if (!stream) {
        return false;
    }

    n = fscanf(stream,
            "%lu"  /* vmSize */
            "%lu"  /* RSSize */
            "%lu"  /* Shared */
            "%lu"  /* Text */
            "%*d"  /* (lib) */
            "%lu"  /* Data + stack */
            "%*d"  /* (dirty pages) */
            , &m->vms, &m->rss,
            &m->shared, &m->text, &m->data);

    fclose(stream);

    if (n != 5) {
        return false;
    }

    m->vms *= pagesize;
    m->rss *= pagesize;
    m->shared *= pagesize;
    m->text *= pagesize;
    m->data *= pagesize;

    return true;
}

static void
memory_measure_read(struct memory_measure *m)
{
    memset(m, 0, sizeof(*m));
    memory_read_statm(m);
    memory_in_use(&m->in_use);
}

bool
memory_in_use(size_t *n_bytes)
{
    return introspect_used_memory(n_bytes);
}

bool
memory_frag_factor(double *frag)
{
    struct memory_measure m;

    if (!introspect_enabled(NULL)) {
        return false;
    }

    memory_measure_read(&m);

    if (m.in_use > 0.0) {
        *frag = (double) m.rss / (double) m.in_use;
    } else {
        *frag = 0.0;
    }
    return true;
}

METRICS_SUBSYSTEM(memory);

enum {
    MEMORY_VMS,
    MEMORY_RSS,
    MEMORY_DATA,
};

static void
memory_read_value(double *values, void *it OVS_UNUSED)
{
    struct memory_measure m;

    memory_measure_read(&m);

    values[MEMORY_VMS] = m.vms;
    values[MEMORY_RSS] = m.rss;
    values[MEMORY_DATA] = m.data;
}

METRICS_ENTRIES(memory, memory_entries,
    "memory", memory_read_value,
    [MEMORY_VMS] = METRICS_GAUGE(vmsize,
        "The process virtual memory size in bytes."),
    [MEMORY_RSS] = METRICS_GAUGE(rss,
        "The process resident set size in bytes."),
    [MEMORY_DATA] = METRICS_GAUGE(data,
        "The process sum of data and stack size in bytes."),
);

enum {
    MEMORY_IN_USE,
    MEMORY_FRAG_FACTOR,
};

static void
memory_introspect_read_value(double *values, void *it OVS_UNUSED)
{
    struct memory_measure m;
    double frag = 0.0;

    memory_measure_read(&m);

    if (m.in_use > 0.0) {
        frag = (double) m.rss / (double) m.in_use;
    }

    values[MEMORY_IN_USE] = m.in_use;
    values[MEMORY_FRAG_FACTOR] = frag;
}

METRICS_COND(memory, memory_introspect,
             introspect_enabled);
METRICS_ENTRIES(memory_introspect, memory_introspect_entries,
    "memory", memory_introspect_read_value,
    [MEMORY_IN_USE] = METRICS_GAUGE(in_use,
        "The amount of memory currently allocated in bytes."),
    [MEMORY_FRAG_FACTOR] = METRICS_GAUGE(frag_factor,
        "The fragmentation factor of the process dynamic memory, "
        "defined as (rss/in_use)."),
);

#else /* !__linux__ || !__GLIBC__ */

bool
memory_in_use(size_t *n_bytes OVS_UNUSED)
{
    return false;
}

bool
memory_frag_factor(double *frag OVS_UNUSED)
{
    return false;
}

#endif /* __linux__ && __GLIBC__ */

static void
memory_metrics_register(void)
{
    static bool inited = false;

    if (!inited) {
#if defined(__linux__) && defined(__GLIBC__)
        METRICS_REGISTER(memory_entries);
        METRICS_REGISTER(memory_introspect_entries);
#endif
        inited = true;
    }
}
