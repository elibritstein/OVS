/*
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
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

#include "netdev-dpdk-common.h"
#include "netdev-provider.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_dpdk_common);

void
netdev_dpdk_common_update_ol_flags(struct netdev_dpdk_common *common)
{
    const struct {
        enum dpdk_hw_ol_features hw_ol_feature;
        enum netdev_ol_flags flag;
    } ol_flags_map[] = {
        { NETDEV_TX_IPV4_CKSUM_OFFLOAD, NETDEV_TX_OFFLOAD_IPV4_CKSUM },
        { NETDEV_TX_TCP_CKSUM_OFFLOAD, NETDEV_TX_OFFLOAD_TCP_CKSUM },
        { NETDEV_TX_UDP_CKSUM_OFFLOAD, NETDEV_TX_OFFLOAD_UDP_CKSUM },
        { NETDEV_TX_SCTP_CKSUM_OFFLOAD, NETDEV_TX_OFFLOAD_SCTP_CKSUM },
        { NETDEV_TX_TSO_OFFLOAD, NETDEV_TX_OFFLOAD_TCP_TSO },
        { NETDEV_TX_VXLAN_TNL_TSO_OFFLOAD, NETDEV_TX_VXLAN_TNL_TSO },
        { NETDEV_TX_GRE_TNL_TSO_OFFLOAD, NETDEV_TX_GRE_TNL_TSO },
        { NETDEV_TX_GENEVE_TNL_TSO_OFFLOAD, NETDEV_TX_GENEVE_TNL_TSO },
        { NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD, NETDEV_TX_OFFLOAD_OUTER_IP_CKSUM },
        { NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD,
          NETDEV_TX_OFFLOAD_OUTER_UDP_CKSUM },
    };
    uint32_t hw_ol_features = common->hw_ol_features;
    struct netdev *netdev = &common->up;

    for (unsigned int i = 0; i < ARRAY_SIZE(ol_flags_map); i++) {
        if (hw_ol_features & ol_flags_map[i].hw_ol_feature) {
            netdev->ol_flags |= ol_flags_map[i].flag;
        } else {
            netdev->ol_flags &= ~ol_flags_map[i].flag;
        }
    }
}

int
netdev_dpdk_common_get_numa_id(const struct netdev *netdev)
{
    const struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);

    return common->socket_id;
}

void
netdev_dpdk_common_get_etheraddr(const struct netdev_dpdk_common *common,
                                 struct eth_addr *mac)
{
    *mac = common->hwaddr;
}

void
netdev_dpdk_common_get_mtu(const struct netdev_dpdk_common *common, int *mtup)
{
    *mtup = common->mtu;
}

int
netdev_dpdk_common_get_ifindex(const struct netdev_dpdk_common *common)
{
    const struct netdev *netdev = &common->up;

    /* Calculate hash from the netdev name. Ensure that ifindex is a 24-bit
     * positive integer to meet RFC 2863 recommendations.
     */
    return hash_string(netdev->name, 0) % 0xfffffe + 1;
}

int
netdev_dpdk_common_set_mtu(struct netdev_dpdk_common *common, int mtu)
{
    struct netdev *netdev = &common->up;

    /* XXX: Ensure that the overall frame length of the requested MTU does not
     * surpass the NETDEV_DPDK_MAX_PKT_LEN. DPDK device drivers differ in how
     * the L2 frame length is calculated for a given MTU when
     * rte_eth_dev_set_mtu(mtu) is called e.g. i40e driver includes 2 x vlan
     * headers, the em driver includes 1 x vlan header, the ixgbe driver does
     * not include vlan headers. As such we should use
     * MTU_TO_MAX_FRAME_LEN(mtu) which includes an additional 2 x vlan headers
     * (8 bytes) for comparison. This avoids a failure later with
     * rte_eth_dev_set_mtu(). This approach should be used until DPDK provides
     * a method to retrieve the upper bound MTU for a given device.
     */
    if (MTU_TO_MAX_FRAME_LEN(mtu) > NETDEV_DPDK_MAX_PKT_LEN
        || mtu < RTE_ETHER_MIN_MTU) {
        VLOG_WARN("%s: unsupported MTU %d\n", netdev->name, mtu);
        return EINVAL;
    }

    if (common->requested_mtu != mtu) {
        common->requested_mtu = mtu;
        netdev_request_reconfigure(netdev);
    }

    return 0;
}

void
netdev_dpdk_common_get_sw_custom_stats(struct netdev_dpdk_common *common,
                                       struct netdev_custom_stats *stats)
{
    int i, n;

#define SW_CSTATS                    \
    SW_CSTAT(tx_retries)             \
    SW_CSTAT(tx_failure_drops)       \
    SW_CSTAT(tx_mtu_exceeded_drops)  \
    SW_CSTAT(tx_qos_drops)           \
    SW_CSTAT(rx_qos_drops)           \
    SW_CSTAT(tx_invalid_hwol_drops)

#define SW_CSTAT(NAME) + 1
    stats->size = SW_CSTATS;
#undef SW_CSTAT
    stats->counters = xcalloc(stats->size, sizeof *stats->counters);

    rte_spinlock_lock(&common->stats_lock);
    i = 0;
#define SW_CSTAT(NAME) \
    stats->counters[i++].value = common->sw_stats->NAME;
    SW_CSTATS;
#undef SW_CSTAT
    rte_spinlock_unlock(&common->stats_lock);

    i = 0;
    n = 0;
#define SW_CSTAT(NAME) \
    if (stats->counters[i].value != UINT64_MAX) {                \
        ovs_strlcpy(stats->counters[n].name,                     \
                    "ovs_"#NAME, NETDEV_CUSTOM_STATS_NAME_SIZE); \
        stats->counters[n].value = stats->counters[i].value;     \
        n++;                                                     \
    }                                                            \
    i++;
    SW_CSTATS;
#undef SW_CSTAT

    stats->size = n;
}
