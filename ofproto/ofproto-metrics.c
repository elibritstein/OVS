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
#include "netdev.h"
#include "ofproto-private.h"
#include "ofproto-provider.h"

METRICS_SUBSYSTEM(ofproto);

static void
do_foreach_ofproto(metrics_visitor_fn visitor,
                   struct metrics_visitor_context *ctx,
                   struct metrics_node *node,
                   struct metrics_label *labels,
                   size_t n OVS_UNUSED)
{
    struct ofproto *ofproto;

    HMAP_FOR_EACH (ofproto, hmap_node, &all_ofprotos) {
        ctx->it = ofproto;
        if (labels[0].key) {
            labels[0].value = ofproto->name;
            labels[1].value = ofproto->type;
        }
        visitor(ctx, node);
    }
}

METRICS_COLLECTION(ofproto, foreach_ofproto,
                   do_foreach_ofproto, "name", "type");

METRICS_COLLECTION(ofproto, foreach_ofproto_nolabel,
                   do_foreach_ofproto, NULL);

static void
bridge_n_read_value(double *values, void *it OVS_UNUSED)
{
    values[0] = hmap_count(&all_ofprotos);
}
METRICS_ENTRIES(ofproto, n_bridges, "bridge", bridge_n_read_value,
    METRICS_GAUGE(n_bridges,
        "Number of bridges present in the instance."),
);

enum {
    OF_BRIDGE_NAME,
    OF_BRIDGE_N_PORTS,
    OF_BRIDGE_N_FLOWS,
};

static void
bridge_read_value(double *values, void *it)
{
    struct ofproto *ofproto = it;
    struct oftable *table;
    unsigned int n_flows;

    n_flows = 0;
    OFPROTO_FOR_EACH_TABLE (table, ofproto) {
        n_flows += table->n_flows;
    }

    values[OF_BRIDGE_NAME] = 1.0;
    values[OF_BRIDGE_N_PORTS] = hmap_count(&ofproto->ports);
    values[OF_BRIDGE_N_FLOWS] = n_flows;
}

METRICS_ENTRIES(foreach_ofproto, bridge_entries, "bridge", bridge_read_value,
    [OF_BRIDGE_NAME] = METRICS_GAUGE(,
        "A metric with a constant value '1' labeled by bridge name and type "
        "present on the instance."),
    [OF_BRIDGE_N_PORTS] = METRICS_GAUGE(n_ports,
        "Number of ports present on the bridge."),
    [OF_BRIDGE_N_FLOWS] = METRICS_GAUGE(n_flows,
        "Number of flows present on the bridge."),
);

static void
do_foreach_ports(metrics_visitor_fn visitor,
                 struct metrics_visitor_context *ctx,
                 struct metrics_node *node,
                 struct metrics_label *labels,
                 size_t n OVS_UNUSED)
{
    struct ofproto *ofproto = ctx->it;
    struct ofport *port;

    HMAP_FOR_EACH (port, hmap_node, &ofproto->ports) {
        labels[0].value = port->ofproto->name;
        labels[1].value = netdev_get_name(port->netdev);
        labels[2].value = netdev_get_type(port->netdev);
        labels[3].value = port->pp.name;
        ctx->it = port;
        visitor(ctx, node);
    }
}

METRICS_COLLECTION(foreach_ofproto_nolabel, foreach_ports,
                   do_foreach_ports, "bridge", "name", "type", "port");

enum {
    OF_NETDEV_ADMIN_STATE,
    OF_NETDEV_MTU,
    OF_NETDEV_OF_PORT,
    OF_NETDEV_IFINDEX,
    OF_NETDEV_POLICY_BIT_RATE,
    OF_NETDEV_POLICY_BIT_BURST,
    OF_NETDEV_POLICY_PKT_RATE,
    OF_NETDEV_POLICY_PKT_BURST,
    OF_NETDEV_DUPLEXITY,
    OF_NETDEV_LINK_RESETS,
    OF_NETDEV_LINK_SPEED,
    OF_NETDEV_LINK_STATE,
    OF_NETDEV_STATS_RX_PACKETS,
    OF_NETDEV_STATS_TX_PACKETS,
    OF_NETDEV_STATS_RX_BYTES,
    OF_NETDEV_STATS_TX_BYTES,
    OF_NETDEV_STATS_RX_ERRORS,
    OF_NETDEV_STATS_TX_ERRORS,
    OF_NETDEV_STATS_RX_DROPPED,
    OF_NETDEV_STATS_TX_DROPPED,
    OF_NETDEV_STATS_RX_LENGTH_ERRORS,
    OF_NETDEV_STATS_RX_OVER_ERRORS,
    OF_NETDEV_STATS_RX_CRC_ERRORS,
    OF_NETDEV_STATS_RX_FRAME_ERRORS,
    OF_NETDEV_STATS_RX_FIFO_ERRORS,
    OF_NETDEV_STATS_RX_MISSED_ERRORS,
    OF_NETDEV_STATS_MULTICAST,
    OF_NETDEV_STATS_COLLISIONS,
};

static void
interface_read_value(double *values, void *it)
{
    const size_t n_stats = sizeof(struct netdev_stats) / sizeof(uint64_t);
    uint32_t kbits_rate, kbits_burst;
    uint32_t kpkts_rate, kpkts_burst;
    enum netdev_features current;
    unsigned int link_speed_mbps;
    struct netdev_stats stats;
    enum netdev_flags flags;
    struct netdev *netdev;
    struct ofport *port;
    uint64_t *u64_stats;
    bool full_duplex;
    int ifindex;
    size_t i;
    int mtu;

    port = it;
    netdev = port->netdev;

    ifindex = netdev_get_ifindex(netdev);
    if (netdev_get_flags(netdev, &flags)) {
        flags = 0;
    }

    netdev_get_stats(netdev, &stats);
    /* Overwrite unused / error stats with 0. */
    u64_stats = (void *) &stats;
    for (i = 0; i < n_stats; i++) {
        u64_stats[i] = MAX_IS_ZERO(u64_stats[i]);
    }

    netdev_get_policing(netdev,
                        &kbits_rate, &kbits_burst,
                        &kpkts_rate, &kpkts_burst);

    netdev_get_features(netdev, &current, NULL, NULL, NULL);
    full_duplex = netdev_features_is_full_duplex(current);

    link_speed_mbps = netdev_features_to_bps(current, 0) / 1000000;

    values[OF_NETDEV_ADMIN_STATE] = (flags & NETDEV_UP) ? 1 : 0;
    values[OF_NETDEV_MTU] = netdev_get_mtu(netdev, &mtu) ? 0 : mtu;
    values[OF_NETDEV_OF_PORT] = (OVS_FORCE uint32_t) port->ofp_port;
    values[OF_NETDEV_IFINDEX] = (ifindex > 0) ? ifindex : 0;
    values[OF_NETDEV_POLICY_BIT_RATE] = kbits_rate;
    values[OF_NETDEV_POLICY_BIT_BURST] = kbits_burst;
    values[OF_NETDEV_POLICY_PKT_RATE] = kpkts_rate;
    values[OF_NETDEV_POLICY_PKT_BURST] = kpkts_burst;
    values[OF_NETDEV_DUPLEXITY] = full_duplex ? 1 : 0;
    values[OF_NETDEV_LINK_RESETS] = netdev_get_carrier_resets(netdev);
    values[OF_NETDEV_LINK_SPEED] = link_speed_mbps;
    values[OF_NETDEV_LINK_STATE] = !!netdev_get_carrier(netdev);

    values[OF_NETDEV_STATS_RX_PACKETS] = stats.rx_packets;
    values[OF_NETDEV_STATS_TX_PACKETS] = stats.tx_packets;
    values[OF_NETDEV_STATS_RX_BYTES] = stats.rx_bytes;
    values[OF_NETDEV_STATS_TX_BYTES] = stats.tx_bytes;
    values[OF_NETDEV_STATS_RX_ERRORS] = stats.rx_errors;
    values[OF_NETDEV_STATS_TX_ERRORS] = stats.tx_errors;
    values[OF_NETDEV_STATS_RX_DROPPED] = stats.rx_dropped;
    values[OF_NETDEV_STATS_TX_DROPPED] = stats.tx_dropped;
    values[OF_NETDEV_STATS_RX_LENGTH_ERRORS] = stats.rx_length_errors;
    values[OF_NETDEV_STATS_RX_OVER_ERRORS] = stats.rx_over_errors;
    values[OF_NETDEV_STATS_RX_CRC_ERRORS] = stats.rx_crc_errors;
    values[OF_NETDEV_STATS_RX_FRAME_ERRORS] = stats.rx_frame_errors;
    values[OF_NETDEV_STATS_RX_FIFO_ERRORS] = stats.rx_fifo_errors;
    values[OF_NETDEV_STATS_RX_MISSED_ERRORS] = stats.rx_missed_errors;
    values[OF_NETDEV_STATS_MULTICAST] = stats.multicast;
    values[OF_NETDEV_STATS_COLLISIONS] = stats.collisions;
}

METRICS_ENTRIES(foreach_ports, port_entries,
    "interface", interface_read_value,
    [OF_NETDEV_ADMIN_STATE] = METRICS_GAUGE(admin_state,
        "The administrative state of the interface: down(0) or up(1)."),
    [OF_NETDEV_MTU] = METRICS_GAUGE(mtu,
        "The MTU of the interface."),
    [OF_NETDEV_OF_PORT] = METRICS_GAUGE(of_port,
        "The OpenFlow port ID associated with the interface."),
    [OF_NETDEV_IFINDEX] = METRICS_GAUGE(ifindex,
        "The ifindex of the interface."),
    [OF_NETDEV_POLICY_BIT_RATE] = METRICS_GAUGE(ingress_policy_bit_rate,
        "Maximum receive rate in kbps on the interface. "
        "Disabled if set to 0."),
    [OF_NETDEV_POLICY_BIT_BURST] = METRICS_GAUGE(ingress_policy_bit_burst,
        "Maximum receive burst size in kb."),
    [OF_NETDEV_POLICY_PKT_RATE] = METRICS_GAUGE(ingress_policy_pkt_rate,
        "Maximum receive rate in pps on the interface. "
        "Disabled if set to 0."),
    [OF_NETDEV_POLICY_PKT_BURST] = METRICS_GAUGE(ingress_policy_pkt_burst,
        "Maximum receive burst size in number of packets."),
    [OF_NETDEV_DUPLEXITY] = METRICS_GAUGE(duplex,
        "The duplex mode of the interface: half(0) or full(1)."),
    [OF_NETDEV_LINK_RESETS] = METRICS_COUNTER(link_resets,
        "The number of time the interface link changed."),
    [OF_NETDEV_LINK_SPEED] = METRICS_GAUGE(link_speed,
        "The current speed of the interface link in Mbps."),
    [OF_NETDEV_LINK_STATE] = METRICS_GAUGE(link_state,
        "The state of the interface link: down(0) or up(1)."),
    [OF_NETDEV_STATS_RX_PACKETS] = METRICS_COUNTER(rx_packets,
        "The number of packets received."),
    [OF_NETDEV_STATS_TX_PACKETS] = METRICS_COUNTER(tx_packets,
        "The number of packets transmitted."),
    [OF_NETDEV_STATS_RX_BYTES] = METRICS_COUNTER(rx_bytes,
        "The number of bytes received."),
    [OF_NETDEV_STATS_TX_BYTES] = METRICS_COUNTER(tx_bytes,
        "The number of bytes transmitted."),
    [OF_NETDEV_STATS_RX_ERRORS] = METRICS_COUNTER(rx_errors,
        "Total number of bad packets received on this interface. "
        "This counter includes all rx_length_errors, rx_crc_errors, "
        "rx_frame_errors and other errors not otherwise counted."),
    [OF_NETDEV_STATS_TX_ERRORS] = METRICS_COUNTER(tx_errors,
        "Total number of transmit issues on this interface."),
    [OF_NETDEV_STATS_RX_DROPPED] = METRICS_COUNTER(rx_dropped,
        "Number of packets received but not processed, "
        "e.g. due to lack of resources or unsupported protocol. "
        "For hardware interface this counter should not include packets "
        "dropped by the device due to buffer exhaustion which are counted "
        "separately in rx_missed_errors."),
    [OF_NETDEV_STATS_TX_DROPPED] = METRICS_COUNTER(tx_dropped,
        "The number of packets dropped on their way to transmission, "
        "e.g. due to lack of resources."),
    [OF_NETDEV_STATS_RX_LENGTH_ERRORS] = METRICS_COUNTER(rx_length_errors,
        "The number of packets dropped due to invalid length."),
    [OF_NETDEV_STATS_RX_OVER_ERRORS] = METRICS_COUNTER(rx_over_errors,
        "Receiver FIFO overflow event counter. This statistics was "
        "used interchangeably with rx_fifo_errors. This statistics "
        "corresponds to hardware events and is not commonly used on "
        "software devices."),
    [OF_NETDEV_STATS_RX_CRC_ERRORS] = METRICS_COUNTER(rx_crc_errors,
        "The number of packets with CRC errors received by the interface."),
    [OF_NETDEV_STATS_RX_FRAME_ERRORS] = METRICS_COUNTER(rx_frame_errors,
        "The number of received packets with frame alignment errors on "
        "the interface."),
    [OF_NETDEV_STATS_RX_FIFO_ERRORS] = METRICS_COUNTER(rx_fifo_errors,
        "Receiver FIFO error counter. This statistics was used "
        "interchangeably with rx_over_errors but is not recommended for use "
        "in drivers for high speed interfaces. This statistics is used on "
        "software devices, e.g. to count software packets queue overflow or "
        "sequencing errors."),
    [OF_NETDEV_STATS_RX_MISSED_ERRORS] = METRICS_COUNTER(rx_missed_errors,
        "The number of packets missed by the host due to lack of buffer "
        "space. This usually indicates that the host interface is slower than "
        "the hardware interface. This statistics corresponds to hardware "
        "events and is not used on software devices."),
    [OF_NETDEV_STATS_MULTICAST] = METRICS_COUNTER(multicast,
        "The number of multicast packets received by the interface."),
    [OF_NETDEV_STATS_COLLISIONS] = METRICS_COUNTER(collisions,
        "The number of collisions during packet transmission."),
);

static void
netdev_info_label(struct metrics_label *labels, size_t n, void *it)
{
    static char values[3][100];
    struct smap netdev_status;
    struct netdev *netdev;
    struct ofport *port;
    size_t i;

    port = it;
    netdev = port->netdev;

    labels[0].value = values[0];
    labels[1].value = values[1];
    labels[2].value = values[2];

    /* By default, reset the labels values to an empty string. */
    for (i = 0; i < n; i++) {
        values[i][0] = '\0';
    }

    smap_init(&netdev_status);
    if (netdev_get_status(netdev, &netdev_status) == 0) {
        for (i = 0; i < n; i++) {
            const char *value = smap_get(&netdev_status, labels[i].key);

            if (value != NULL) {
                snprintf(values[i], sizeof values[i], "%s", value);
            }
        }
    }
    smap_destroy(&netdev_status);
}

METRICS_LABEL(foreach_ports,
    netdev_labeled_info, netdev_info_label,
    "driver_name", "driver_version", "firmware_version");

METRICS_ENTRIES(netdev_labeled_info, netdev_info,
    "interface", metrics_set_read_one,
    METRICS_GAUGE(info,
        "A metric with a constant value '1' labeled with the driver name, "
        "version and firmware version of the interface."),
);

void
ofproto_metrics_register(void)
{
    static bool registered;
    if (registered) {
        return;
    }
    registered = true;

    METRICS_REGISTER(n_bridges);
    METRICS_REGISTER(bridge_entries);
    METRICS_REGISTER(port_entries);
    METRICS_REGISTER(netdev_info);
}
