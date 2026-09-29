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

#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "dp-packet.h"
#include "hash.h"
#include "netdev-dpdk-common.h"
#include "netdev-provider.h"
#include "openvswitch/list.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"
#include "smap.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(netdev_dpdk_common);

static bool per_port_memory = false; /* Status of per port memory support */

/* MAX_NB_MBUF can be divided by 2 many times, until MIN_NB_MBUF */
BUILD_ASSERT_DECL(MAX_NB_MBUF % ROUND_DOWN_POW2(MAX_NB_MBUF / MIN_NB_MBUF)
                  == 0);

/* The smallest possible NB_MBUF that we're going to try should be a multiple
 * of MP_CACHE_SZ. This is advised by DPDK documentation. */
BUILD_ASSERT_DECL((MAX_NB_MBUF / ROUND_DOWN_POW2(MAX_NB_MBUF / MIN_NB_MBUF))
                  % MP_CACHE_SZ == 0);

struct ovs_mutex dpdk_mp_mutex OVS_ACQ_AFTER(dpdk_mutex)
    = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dpdk_mp's. */
static struct ovs_list dpdk_mp_list OVS_GUARDED_BY(dpdk_mp_mutex)
    = OVS_LIST_INITIALIZER(&dpdk_mp_list);

struct user_mempool_config {
    int adj_mtu;
    int socket_id;
};

static struct user_mempool_config *user_mempools = NULL;
static int n_user_mempools;

bool
dpdk_mp_per_port_memory(void)
{
    return per_port_memory;
}

/* DPDK NIC drivers allocate RX buffers at a particular granularity, typically
 * aligned at 1k or less. If a declared mbuf size is not a multiple of this
 * value, insufficient buffers are allocated to accomodate the packet in its
 * entirety. Furthermore, certain drivers need to ensure that there is also
 * sufficient space in the Rx buffer to accommodate two VLAN tags (for QinQ
 * frames). If the RX buffer is too small, then the driver enables scatter RX
 * behaviour, which reduces performance. To prevent this, use a buffer size
 * that is closest to 'mtu', but which satisfies the aforementioned criteria.
 */
static uint32_t
dpdk_buf_size(int mtu)
{
    return ROUND_UP(MTU_TO_MAX_FRAME_LEN(mtu), NETDEV_DPDK_MBUF_ALIGN)
            + RTE_PKTMBUF_HEADROOM;
}

static int
dpdk_get_user_adjusted_mtu(int port_adj_mtu, int port_mtu, int port_socket_id)
{
    int best_adj_user_mtu = INT_MAX;

    for (unsigned i = 0; i < n_user_mempools; i++) {
        int user_adj_mtu, user_socket_id;

        user_adj_mtu = user_mempools[i].adj_mtu;
        user_socket_id = user_mempools[i].socket_id;
        if (port_adj_mtu > user_adj_mtu
            || (user_socket_id != INT_MAX
                && user_socket_id != port_socket_id)) {
            continue;
        }
        if (user_adj_mtu < best_adj_user_mtu) {
            /* This is the is the lowest valid user MTU. */
            best_adj_user_mtu = user_adj_mtu;
            if (best_adj_user_mtu == port_adj_mtu) {
                /* Found an exact fit, no need to keep searching. */
                break;
            }
        }
    }
    if (best_adj_user_mtu == INT_MAX) {
        VLOG_DBG("No user configured shared mempool mbuf sizes found "
                 "suitable for port with MTU %d, NUMA %d.", port_mtu,
                 port_socket_id);
        best_adj_user_mtu = port_adj_mtu;
    } else {
        VLOG_DBG("Found user configured shared mempool with mbufs "
                 "of size %d, suitable for port with MTU %d, NUMA %d.",
                 MTU_TO_FRAME_LEN(best_adj_user_mtu), port_mtu,
                 port_socket_id);
    }
    return best_adj_user_mtu;
}

static void
ovs_rte_pktmbuf_init(struct rte_mempool *mp OVS_UNUSED,
                     void *opaque_arg OVS_UNUSED,
                     void *_p,
                     unsigned i OVS_UNUSED)
{
    struct rte_mbuf *pkt = _p;

    dp_packet_init_dpdk((struct dp_packet *) pkt);
}

static int
dpdk_mp_full(const struct rte_mempool *mp) OVS_REQUIRES(dpdk_mp_mutex)
{
    /* At this point we want to know if all the mbufs are back
     * in the mempool. rte_mempool_full() is not atomic but it's
     * the best available and as we are no longer requesting mbufs
     * from the mempool, it means mbufs will not move from
     * 'mempool ring' --> 'mempool cache'. In rte_mempool_full()
     * the ring is counted before caches, so we won't get false
     * positives in this use case and we handle false negatives.
     *
     * If future implementations of rte_mempool_full() were to change
     * it could be possible for a false positive. Even that would
     * likely be ok, as there are additional checks during mempool
     * freeing but it would make things racey.
     */
    return rte_mempool_full(mp);
}

/* Free unused mempools. */
static void
dpdk_mp_sweep(void) OVS_REQUIRES(dpdk_mp_mutex)
{
    struct dpdk_mp *dmp;

    LIST_FOR_EACH_SAFE (dmp, list_node, &dpdk_mp_list) {
        if (!dmp->refcount && dpdk_mp_full(dmp->mp)) {
            VLOG_DBG("Freeing mempool \"%s\"", dmp->mp->name);
            ovs_list_remove(&dmp->list_node);
            rte_mempool_free(dmp->mp);
            rte_free(dmp);
        }
    }
}

/* Calculating the required number of mbufs differs depending on the
 * mempool model being used. Check if per port memory is in use before
 * calculating.
 */
static uint32_t
dpdk_calculate_mbufs(struct dpdk_mp_config *cfg, int mtu)
{
    uint32_t n_mbufs;

    if (!per_port_memory) {
        /* Shared memory are being used.
         * XXX: this is a really rough method of provisioning memory.
         * It's impossible to determine what the exact memory requirements are
         * when the number of ports and rxqs that utilize a particular mempool
         * can change dynamically at runtime. For now, use this rough
         * heurisitic.
         */
        if (mtu >= RTE_ETHER_MTU) {
            n_mbufs = MAX_NB_MBUF;
        } else {
            n_mbufs = MIN_NB_MBUF;
        }
    } else {
        /* Per port memory is being used.
         * XXX: rough estimation of number of mbufs required for this port:
         * <packets required to fill the device rxqs>
         * + <packets that could be stuck on other ports txqs>
         * + <packets in the pmd threads>
         * + <additional memory for corner cases>
         */
        n_mbufs = cfg->n_rxq * cfg->rxq_size
                  + cfg->n_txq * cfg->txq_size
                  + MIN(RTE_MAX_LCORE, cfg->n_rxq) * NETDEV_MAX_BURST
                  + MIN_NB_MBUF;
    }

    return n_mbufs;
}

static struct dpdk_mp *
dpdk_mp_create(struct dpdk_mp_config *cfg, int mtu)
{
    char mp_name[RTE_MEMPOOL_NAMESIZE];
    const char *netdev_name = cfg->name;
    int socket_id = cfg->socket_id;
    uint32_t n_mbufs = 0;
    uint32_t mbuf_size = 0;
    uint32_t aligned_mbuf_size = 0;
    uint32_t mbuf_priv_data_len = 0;
    uint32_t pkt_size = 0;
    uint32_t hash = hash_string(netdev_name, 0);
    struct dpdk_mp *dmp = NULL;
    int ret;

    dmp = dpdk_zmalloc(sizeof *dmp);
    if (!dmp) {
        return NULL;
    }
    dmp->socket_id = socket_id;
    dmp->mtu = mtu;
    dmp->refcount = 1;

    /* Get the size of each mbuf, based on the MTU */
    mbuf_size = MTU_TO_FRAME_LEN(mtu);

    n_mbufs = dpdk_calculate_mbufs(cfg, mtu);

    do {
        /* Full DPDK memory pool name must be unique and cannot be
         * longer than RTE_MEMPOOL_NAMESIZE. Note that for the shared
         * mempool case this can result in one device using a mempool
         * which references a different device in it's name. However as
         * mempool names are hashed, the device name will not be readable
         * so this is not an issue for tasks such as debugging.
         */
        ret = snprintf(mp_name, RTE_MEMPOOL_NAMESIZE,
                       "ovs%08x%02d%05d%07u",
                        hash, socket_id, mtu, n_mbufs);
        if (ret < 0 || ret >= RTE_MEMPOOL_NAMESIZE) {
            VLOG_DBG("snprintf returned %d. "
                     "Failed to generate a mempool name for \"%s\". "
                     "Hash:0x%x, socket_id: %d, mtu:%d, mbufs:%u.",
                     ret, netdev_name, hash, socket_id, mtu, n_mbufs);
            break;
        }

        VLOG_DBG("Port %s: Requesting a mempool of %u mbufs of size %u "
                  "on socket %d for %d Rx and %d Tx queues, "
                  "cache line size of %u",
                  netdev_name, n_mbufs, mbuf_size, socket_id,
                  cfg->n_rxq, cfg->n_txq,
                  RTE_CACHE_LINE_SIZE);

        /* The size of the mbuf's private area (i.e. area that holds OvS'
         * dp_packet data)*/
        mbuf_priv_data_len = sizeof(struct dp_packet) -
                                 sizeof(struct rte_mbuf);
        /* The size of the entire dp_packet. */
        pkt_size = sizeof(struct dp_packet) + mbuf_size;
        /* mbuf size, rounded up to cacheline size. */
        aligned_mbuf_size = ROUND_UP(pkt_size, RTE_CACHE_LINE_SIZE);
        /* If there is a size discrepancy, add padding to mbuf_priv_data_len.
         * This maintains mbuf size cache alignment, while also honoring RX
         * buffer alignment in the data portion of the mbuf. If this adjustment
         * is not made, there is a possiblity later on that for an element of
         * the mempool, buf, buf->data_len < (buf->buf_len - buf->data_off).
         * This is problematic in the case of multi-segment mbufs, particularly
         * when an mbuf segment needs to be resized (when [push|popp]ing a VLAN
         * header, for example.
         */
        mbuf_priv_data_len += (aligned_mbuf_size - pkt_size);

        dmp->mp = rte_pktmbuf_pool_create(mp_name, n_mbufs, MP_CACHE_SZ,
                                          mbuf_priv_data_len,
                                          mbuf_size,
                                          socket_id);

        if (dmp->mp) {
            VLOG_DBG("Allocated \"%s\" mempool with %u mbufs",
                     mp_name, n_mbufs);
            /* rte_pktmbuf_pool_create has done some initialization of the
             * rte_mbuf part of each dp_packet, while ovs_rte_pktmbuf_init
             * initializes some OVS specific fields of dp_packet.
             */
            rte_mempool_obj_iter(dmp->mp, ovs_rte_pktmbuf_init, NULL);
            return dmp;
        } else if (rte_errno == EEXIST) {
            /* A mempool with the same name already exists.  We just
             * retrieve its pointer to be returned to the caller. */
            dmp->mp = rte_mempool_lookup(mp_name);
            /* As the mempool create returned EEXIST we can expect the
             * lookup has returned a valid pointer.  If for some reason
             * that's not the case we keep track of it. */
            VLOG_DBG("A mempool with name \"%s\" already exists at %p.",
                     mp_name, dmp->mp);
            return dmp;
        } else {
            VLOG_DBG("Failed to create mempool \"%s\" with a request of "
                     "%u mbufs, retrying with %u mbufs",
                     mp_name, n_mbufs, n_mbufs / 2);
        }
    } while (!dmp->mp && rte_errno == ENOMEM && (n_mbufs /= 2) >= MIN_NB_MBUF);

    VLOG_ERR("Failed to create mempool \"%s\" with a request of %u mbufs",
             mp_name, n_mbufs);

    rte_free(dmp);
    return NULL;
}

struct dpdk_mp *
dpdk_mp_get(struct dpdk_mp_config *cfg)
{
    int mtu = FRAME_LEN_TO_MTU(dpdk_buf_size(cfg->mtu));
    struct dpdk_mp *dmp = NULL, *next;
    bool reuse = false;

    ovs_mutex_lock(&dpdk_mp_mutex);
    /* Check if shared memory is being used, if so check existing mempools
     * to see if reuse is possible. */
    if (!per_port_memory) {
        /* If user has provided defined mempools, check if one is suitable
         * and get new buffer size.*/
        mtu = dpdk_get_user_adjusted_mtu(mtu, cfg->mtu,
                                         cfg->socket_id);
        LIST_FOR_EACH (dmp, list_node, &dpdk_mp_list) {
            if (dmp->socket_id == cfg->socket_id
                && dmp->mtu == mtu) {
                VLOG_DBG("Reusing mempool \"%s\"", dmp->mp->name);
                dmp->refcount++;
                reuse = true;
                break;
            }
        }
    }
    /* Sweep mempools after reuse or before create. */
    dpdk_mp_sweep();

    if (!reuse) {
        dmp = dpdk_mp_create(cfg, mtu);
        if (dmp) {
            /* Shared memory will hit the reuse case above so will not
             * request a mempool that already exists but we need to check
             * for the EEXIST case for per port memory case. Compare the
             * mempool returned by dmp to each entry in dpdk_mp_list. If a
             * match is found, free dmp as a new entry is not required, set
             * dmp to point to the existing entry and increment the refcount
             * to avoid being freed at a later stage.
             */
            if (per_port_memory && rte_errno == EEXIST) {
                LIST_FOR_EACH (next, list_node, &dpdk_mp_list) {
                    if (dmp->mp == next->mp) {
                        rte_free(dmp);
                        dmp = next;
                        dmp->refcount++;
                    }
                }
            } else {
                ovs_list_push_back(&dpdk_mp_list, &dmp->list_node);
            }
        }
    }

    ovs_mutex_unlock(&dpdk_mp_mutex);

    return dmp;
}

/* Decrement reference to a mempool. */
void
dpdk_mp_put(struct dpdk_mp *dmp)
{
    if (!dmp) {
        return;
    }

    ovs_mutex_lock(&dpdk_mp_mutex);
    ovs_assert(dmp->refcount);
    dmp->refcount--;
    ovs_mutex_unlock(&dpdk_mp_mutex);
}

void
dpdk_mp_dump(FILE *stream, struct dpdk_mp *dmp)
{
    ovs_mutex_lock(&dpdk_mp_mutex);
    if (dmp && dmp->mp) {
        rte_mempool_dump(stream, dmp->mp);
        fprintf(stream, "    count: avail (%u), in use (%u)\n",
                rte_mempool_avail_count(dmp->mp),
                rte_mempool_in_use_count(dmp->mp));
    } else {
        rte_mempool_list_dump(stream);
    }
    ovs_mutex_unlock(&dpdk_mp_mutex);
}

static void
parse_mempool_config(const struct smap *ovs_other_config)
{
    per_port_memory = smap_get_bool(ovs_other_config,
                                    "per-port-memory", false);
    VLOG_INFO("Per port memory for DPDK devices %s.",
              per_port_memory ? "enabled" : "disabled");
}

static void
parse_user_mempools_list(const struct smap *ovs_other_config)
{
    const char *mtus = smap_get(ovs_other_config, "shared-mempool-config");
    char *list, *copy, *key, *value;
    int error = 0;

    if (!mtus) {
        return;
    }

    n_user_mempools = 0;
    list = copy = xstrdup(mtus);

    while (ofputil_parse_key_value(&list, &key, &value)) {
        int socket_id, mtu, adj_mtu;

        if (!str_to_int(key, 0, &mtu) || mtu < 0) {
            error = EINVAL;
            VLOG_WARN("Invalid user configured shared mempool MTU.");
            break;
        }

        if (!str_to_int(value, 0, &socket_id)) {
            /* No socket specified. It will apply for all numas. */
            socket_id = INT_MAX;
        } else if (socket_id < 0) {
            error = EINVAL;
            VLOG_WARN("Invalid user configured shared mempool NUMA.");
            break;
        }

        user_mempools = xrealloc(user_mempools, (n_user_mempools + 1) *
                                 sizeof(struct user_mempool_config));
        adj_mtu = FRAME_LEN_TO_MTU(dpdk_buf_size(mtu));
        user_mempools[n_user_mempools].adj_mtu = adj_mtu;
        user_mempools[n_user_mempools].socket_id = socket_id;
        n_user_mempools++;
        VLOG_INFO("User configured shared mempool set for: MTU %d, NUMA %s.",
                  mtu, socket_id == INT_MAX ? "ALL" : value);
    }

    if (error) {
        VLOG_WARN("User configured shared mempools will not be used.");
        n_user_mempools = 0;
        free(user_mempools);
        user_mempools = NULL;
    }
    free(copy);
}

void
dpdk_mp_init(const struct smap *ovs_other_config)
{
    parse_mempool_config(ovs_other_config);
    parse_user_mempools_list(ovs_other_config);
}

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
