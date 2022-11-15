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

#include "coverage.h"
#include "ct-dpif.h"
#include "dpif-metrics.h"
#include "dpif.h"
#include "metrics.h"
#include "sset.h"

METRICS_SUBSYSTEM(dpif);

static void
do_foreach_dpif(metrics_visitor_fn visitor,
                struct metrics_visitor_context *ctx,
                struct metrics_node *node,
                struct metrics_label *labels,
                size_t n OVS_UNUSED)
{
    struct sset types;
    const char *type;

    sset_init(&types);
    dp_enumerate_types(&types);
    SSET_FOR_EACH (type, &types) {
        struct dpif *dpif;
        struct sset names;
        const char *name;

        sset_init(&names);
        dp_enumerate_names(type, &names);
        SSET_FOR_EACH (name, &names) {
            if (!dpif_open(name, type, &dpif)) {
                ctx->it = dpif;
                if (labels[0].key) {
                    labels[0].value = name;
                }
                visitor(ctx, node);
                dpif_close(dpif);
            }
        }
        sset_destroy(&names);
    }
    sset_destroy(&types);
}

METRICS_COLLECTION(dpif, foreach_dpif, do_foreach_dpif, "datapath");
METRICS_COLLECTION(dpif, foreach_dpif_nolabel, do_foreach_dpif, NULL);

enum {
    DPIF_N_DESTROY,
    DPIF_N_PORT_ADD,
    DPIF_N_PORT_DEL,
    DPIF_N_FLOW_FLUSH,
    DPIF_N_FLOW_GET,
    DPIF_N_FLOW_PUT,
    DPIF_N_FLOW_DEL,
    DPIF_N_EXECUTE,
    DPIF_N_PURGE,
    DPIF_N_EXECUTE_WITH_HELP,
    DPIF_N_METER_SET,
    DPIF_N_METER_GET,
    DPIF_N_METER_DEL,
};

static void
dpif_read_value(double *values, void *it OVS_UNUSED)
{
    char *names[] = {
        [DPIF_N_DESTROY] = "dpif_destroy",
        [DPIF_N_PORT_ADD] = "dpif_port_add",
        [DPIF_N_PORT_DEL] = "dpif_port_del",
        [DPIF_N_FLOW_FLUSH] = "dpif_flow_flush",
        [DPIF_N_FLOW_GET] = "dpif_flow_get",
        [DPIF_N_FLOW_PUT] = "dpif_flow_put",
        [DPIF_N_FLOW_DEL] = "dpif_flow_del",
        [DPIF_N_EXECUTE] = "dpif_execute",
        [DPIF_N_PURGE] = "dpif_purge",
        [DPIF_N_EXECUTE_WITH_HELP] = "dpif_execute_with_help",
        [DPIF_N_METER_SET] = "dpif_meter_set",
        [DPIF_N_METER_GET] = "dpif_meter_get",
        [DPIF_N_METER_DEL] = "dpif_meter_del",
    };
    size_t i;

    for (i = 0; i < ARRAY_SIZE(names); i++) {
        unsigned long long int count;

        if (coverage_read_counter(names[i], &count)) {
            values[i] = count;
        } else {
            values[i] = 0;
        }
    }
}

METRICS_COND(dpif, dpif_dbg, metrics_dbg_enabled);
METRICS_ENTRIES(dpif_dbg, dpif_entries,
    "dpif", dpif_read_value,
    [DPIF_N_DESTROY] = METRICS_COUNTER(n_destroy,
        "Number of datapath deletion done."),
    [DPIF_N_PORT_ADD] = METRICS_COUNTER(n_port_add,
        "Number of port add operations done in all dpif."),
    [DPIF_N_PORT_DEL] = METRICS_COUNTER(n_port_del,
        "Number of port del operations done in all dpif."),
    [DPIF_N_FLOW_FLUSH] = METRICS_COUNTER(n_flow_flush,
        "Number of flow flush operations done in all dpif."),
    [DPIF_N_FLOW_GET] = METRICS_COUNTER(n_flow_get,
        "Number of flow queries done in all dpif."),
    [DPIF_N_FLOW_PUT] = METRICS_COUNTER(n_flow_put,
        "Number of flow addition or modification in all dpif."),
    [DPIF_N_FLOW_DEL] = METRICS_COUNTER(n_flow_del,
        "Number of flow deletion operations done in all dpif."),
    [DPIF_N_EXECUTE] = METRICS_COUNTER(n_execute,
        "Number of 'execute' calls made on packets in all dpif."),
    [DPIF_N_PURGE] = METRICS_COUNTER(n_purge,
        "Number of purge done in all dpif."),
    [DPIF_N_EXECUTE_WITH_HELP] = METRICS_COUNTER(n_execute_with_help,
        "Number of 'execute' split between userspace and dpif for all dpif."),
    [DPIF_N_METER_SET] = METRICS_COUNTER(n_meter_set,
        "Number of addition or modification of a meter in all dpif."),
    [DPIF_N_METER_GET] = METRICS_COUNTER(n_meter_get,
        "Number of meter queries in all dpif."),
    [DPIF_N_METER_DEL] = METRICS_COUNTER(n_meter_del,
        "Number of meter deletions in all dpif."),
);

static bool
ct_stats_supported(void *dpif)
{
    uint32_t u32;

    return ct_dpif_get_nconns(dpif, &u32) == 0;
}

METRICS_COND(foreach_dpif, if_ct_stats_supported, ct_stats_supported);

enum {
    CT_DPIF_METRICS_N_CONNECTIONS,
    CT_DPIF_METRICS_CONNECTION_LIMIT,
    CT_DPIF_METRICS_TCP_SEQ_CHK,
};

static void
ct_dpif_read_value(double *values, void *_dpif)
{
    struct dpif *dpif = _dpif;
    bool tcp_seq_chk;
    uint32_t u32;

    ct_dpif_get_nconns(dpif, &u32);
    values[CT_DPIF_METRICS_N_CONNECTIONS] = u32;

    ct_dpif_get_maxconns(dpif, &u32);
    values[CT_DPIF_METRICS_CONNECTION_LIMIT] = u32;

    ct_dpif_get_tcp_seq_chk(dpif, &tcp_seq_chk);
    values[CT_DPIF_METRICS_TCP_SEQ_CHK] = tcp_seq_chk ? 1 : 0;
}

METRICS_ENTRIES(if_ct_stats_supported, ct_dpif_entries,
        "conntrack", ct_dpif_read_value,
    [CT_DPIF_METRICS_N_CONNECTIONS] = METRICS_GAUGE(n_connections,
        "Number of tracked connections."),
    [CT_DPIF_METRICS_CONNECTION_LIMIT] = METRICS_GAUGE(connection_limit,
        "Maximum number of connections allowed."),
    [CT_DPIF_METRICS_TCP_SEQ_CHK] = METRICS_GAUGE(tcp_seq_chk,
        "The TCP sequence checking mode: disabled(0) or enabled(1)."),
);

static bool
ct_get_stats_supported(void *dpif)
{
    return ct_dpif_get_stats(dpif, NULL) == 0;
}

METRICS_COND(foreach_dpif, if_ct_get_stats_supported, ct_get_stats_supported);

enum {
    CT_DPIF_METRICS_N_UDP,
    CT_DPIF_METRICS_N_TCP,
    CT_DPIF_METRICS_N_SCTP,
    CT_DPIF_METRICS_N_ICMP,
    CT_DPIF_METRICS_N_ICMPV6,
    CT_DPIF_METRICS_N_UDPLITE,
    CT_DPIF_METRICS_N_DCCP,
    CT_DPIF_METRICS_N_IGMP,
    CT_DPIF_METRICS_N_OTHER,
};

static void
ct_dpif_adv_read_value(double *values, void *dpif)
{
    struct ct_dpif_stats stats;
    uint32_t *n_conns;

    ct_dpif_get_stats(dpif, &stats);
    n_conns = stats.n_conns_per_proto;

    values[CT_DPIF_METRICS_N_UDP] = n_conns[CT_STATS_UDP];
    values[CT_DPIF_METRICS_N_TCP] = n_conns[CT_STATS_TCP];
    values[CT_DPIF_METRICS_N_SCTP] = n_conns[CT_STATS_SCTP];
    values[CT_DPIF_METRICS_N_ICMP] = n_conns[CT_STATS_ICMP];
    values[CT_DPIF_METRICS_N_ICMPV6] = n_conns[CT_STATS_ICMPV6];
    values[CT_DPIF_METRICS_N_UDPLITE] = n_conns[CT_STATS_UDPLITE];
    values[CT_DPIF_METRICS_N_DCCP] = n_conns[CT_STATS_DCCP];
    values[CT_DPIF_METRICS_N_IGMP] = n_conns[CT_STATS_IGMP];
    values[CT_DPIF_METRICS_N_OTHER] = n_conns[CT_STATS_OTHER];
}

METRICS_ENTRIES(if_ct_get_stats_supported, ct_dpif_adv_entries,
        "conntrack", ct_dpif_adv_read_value,
    [CT_DPIF_METRICS_N_UDP] = METRICS_GAUGE(n_udp,
        "Number of tracked UDP connections."),
    [CT_DPIF_METRICS_N_TCP] = METRICS_GAUGE(n_tcp,
        "Number of tracked TCP connections."),
    [CT_DPIF_METRICS_N_SCTP] = METRICS_GAUGE(n_sctp,
        "Number of tracked SCTP connections."),
    [CT_DPIF_METRICS_N_ICMP] = METRICS_GAUGE(n_icmp,
        "Number of tracked ICMP connections."),
    [CT_DPIF_METRICS_N_ICMPV6] = METRICS_GAUGE(n_icmp6,
        "Number of tracked ICMPv6 connections."),
    [CT_DPIF_METRICS_N_UDPLITE] = METRICS_GAUGE(n_udplite,
        "Number of tracked UDPLite connections."),
    [CT_DPIF_METRICS_N_DCCP] = METRICS_GAUGE(n_dccp,
        "Number of tracked DCCP connections."),
    [CT_DPIF_METRICS_N_IGMP] = METRICS_GAUGE(n_igmp,
        "Number of tracked IGMP connections."),
    [CT_DPIF_METRICS_N_OTHER] = METRICS_GAUGE(n_other,
        "Number of tracked connections of undefined type."),
);

void
dpif_metrics_register(void)
{
    METRICS_REGISTER(dpif_entries);
    METRICS_REGISTER(ct_dpif_entries);
    METRICS_REGISTER(ct_dpif_adv_entries);
}
