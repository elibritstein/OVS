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

#include "metrics.h"
#include "ofproto-dpif.h"
#include "ofproto-provider.h"

METRICS_SUBSYSTEM(ofproto_dpif);

static void
do_foreach_dpif_backer(metrics_visitor_fn visitor,
                       struct metrics_visitor_context *ctx,
                       struct metrics_node *node,
                       struct metrics_label *labels,
                       size_t n OVS_UNUSED)
{
    const struct shash_node **backers;
    const struct dpif_backer *backer;
    int i;

    backers = shash_sort(&all_dpif_backers);
    for (i = 0; i < shash_count(&all_dpif_backers); i++) {
        backer = backers[i]->data;
        ctx->it = CONST_CAST(void *, backer);
        labels[0].value = dpif_name(backer->dpif);
        visitor(ctx, node);
    }
    free(backers);
}

METRICS_COLLECTION(ofproto_dpif, foreach_dpif_backer,
                   do_foreach_dpif_backer, "datapath");

enum {
    OF_DATAPATH_HIT,
    OF_DATAPATH_MISSED,
    OF_DATAPATH_LOST,
    OF_DATAPATH_N_FLOWS,
    OF_DATAPATH_CACHE_HIT,
    OF_DATAPATH_MASK_HIT,
    OF_DATAPATH_N_MASKS,
    OF_DATAPATH_PACKETS,
    OF_DATAPATH_BYTES,
    OF_DATAPATH_OFL_PACKETS,
    OF_DATAPATH_OFL_BYTES,
    OF_DATAPATH_TX_PACKETS,
    OF_DATAPATH_TX_BYTES,
    OF_DATAPATH_TX_OFL_PACKETS,
    OF_DATAPATH_TX_OFL_BYTES,
};

static void
datapath_read_value(double *values, void *it)
{
    const struct dpif_backer *backer = it;
    const struct shash_node **ofprotos;
    struct dpif_dp_stats dp_stats;
    struct pkt_stats sum_tx_stats;
    struct pkt_stats sum_stats;
    struct shash ofproto_shash;
    size_t i;

    dpif_get_dp_stats(backer->dpif, &dp_stats);

    values[OF_DATAPATH_HIT] = MAX_IS_ZERO(dp_stats.n_hit);
    values[OF_DATAPATH_MISSED] = MAX_IS_ZERO(dp_stats.n_missed);
    values[OF_DATAPATH_LOST] = MAX_IS_ZERO(dp_stats.n_lost);
    values[OF_DATAPATH_N_FLOWS] = MAX_IS_ZERO(dp_stats.n_flows);
    values[OF_DATAPATH_CACHE_HIT] = MAX_IS_ZERO(dp_stats.n_cache_hit);
    values[OF_DATAPATH_MASK_HIT] = MAX_IS_ZERO(dp_stats.n_mask_hit);
    values[OF_DATAPATH_N_MASKS] = MAX_IS_ZERO(dp_stats.n_masks);

    memset(&sum_tx_stats, 0, sizeof sum_tx_stats);
    memset(&sum_stats, 0, sizeof sum_stats);
    shash_init(&ofproto_shash);
    ofprotos = ofproto_dpif_get_ofprotos(&ofproto_shash);
    for (i = 0; i < shash_count(&ofproto_shash); i++) {
        struct ofproto_dpif *ofproto = ofprotos[i]->data;
        struct pkt_stats tx_stats;
        struct pkt_stats stats;

        if (ofproto->backer != backer) {
            continue;
        }

        memset(&tx_stats, 0, sizeof tx_stats);
        memset(&stats, 0, sizeof stats);
        ofproto_get_pkt_stats(&ofproto->up, &stats, &tx_stats);
        pkt_stats_add(&sum_tx_stats, tx_stats);
        pkt_stats_add(&sum_stats, stats);
    }
    shash_destroy(&ofproto_shash);
    free(ofprotos);

    values[OF_DATAPATH_PACKETS] = sum_stats.n_packets;
    values[OF_DATAPATH_BYTES] = sum_stats.n_bytes;
    values[OF_DATAPATH_OFL_PACKETS] = sum_stats.n_offload_packets;
    values[OF_DATAPATH_OFL_BYTES] = sum_stats.n_offload_bytes;

    values[OF_DATAPATH_TX_PACKETS] = sum_tx_stats.n_packets;
    values[OF_DATAPATH_TX_BYTES] = sum_tx_stats.n_bytes;
    values[OF_DATAPATH_TX_OFL_PACKETS] = sum_tx_stats.n_offload_packets;
    values[OF_DATAPATH_TX_OFL_BYTES] = sum_tx_stats.n_offload_bytes;
}

METRICS_ENTRIES(foreach_dpif_backer, datapath_entries,
    "datapath", datapath_read_value,
    [OF_DATAPATH_HIT] = METRICS_COUNTER(hit,
        "Number of flow table matches."),
    [OF_DATAPATH_MISSED] = METRICS_COUNTER(missed,
        "Number of flow table misses."),
    [OF_DATAPATH_LOST] = METRICS_COUNTER(lost,
        "Number of misses not sent to userspace."),
    [OF_DATAPATH_N_FLOWS] = METRICS_GAUGE(n_flows,
        "Number of flows present."),
    [OF_DATAPATH_CACHE_HIT] = METRICS_COUNTER(cache_hit,
        "Number of mega flow mask cache hits for flow table matches."),
    [OF_DATAPATH_MASK_HIT] = METRICS_COUNTER(mask_hit,
        "Number of mega flow masks visited for flow table matches."),
    [OF_DATAPATH_N_MASKS] = METRICS_GAUGE(n_masks,
        "Number of mega flow masks."),
    [OF_DATAPATH_PACKETS] = METRICS_COUNTER(packets,
        "Number of packets processed in total on this datapath."),
    [OF_DATAPATH_BYTES] = METRICS_COUNTER(bytes,
        "Number of bytes processed in total on this datapath."),
    [OF_DATAPATH_OFL_PACKETS] = METRICS_COUNTER(offloaded_packets,
        "Number of packets processed in hardware on this datapath."),
    [OF_DATAPATH_OFL_BYTES] = METRICS_COUNTER(offloaded_bytes,
        "Number of bytes processed in hardware on this datapath."),
    [OF_DATAPATH_TX_PACKETS] = METRICS_COUNTER(tx_packets,
        "Number of packets emitted in total from this datapath."),
    [OF_DATAPATH_TX_BYTES] = METRICS_COUNTER(tx_bytes,
        "Number of bytes emitted in total from this datapath."),
    [OF_DATAPATH_TX_OFL_PACKETS] = METRICS_COUNTER(tx_offloaded_packets,
        "Total number of packets emitted from this datapath and fully "
        "processed in hardware."),
    [OF_DATAPATH_TX_OFL_BYTES] = METRICS_COUNTER(tx_offloaded_bytes,
        "Total number of bytes emitted from this datapath and fully "
        "processed in hardware."),
);

METRICS_DECLARE(udpif_entries);
METRICS_DECLARE(udpif_total_entries);
METRICS_DECLARE(revalidator_dump_duration);
METRICS_DECLARE(revalidator_flow_del_latency);

void
ofproto_dpif_metrics_register(void)
{
    static bool registered;
    if (registered) {
        return;
    }
    registered = true;

    METRICS_REGISTER(datapath_entries);
    METRICS_REGISTER(udpif_entries);
    METRICS_REGISTER(udpif_total_entries);
    METRICS_REGISTER(revalidator_dump_duration);
    METRICS_REGISTER(revalidator_flow_del_latency);
}
