/*
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
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

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <rte_bus.h>
#include <rte_config.h>
#include <rte_dev.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_version.h>

#include "dpif-netdev.h"
#include "dp-packet.h"
#include "hash.h"
#include "netdev-dpdk.h"
#include "netdev-provider.h"
#include "packets.h"
#include "smap.h"
#include "timeval.h"
#include "userspace-tso.h"
#include "util.h"

#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_dpdk_common);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

#define DPDK_PORT_WATCHDOG_INTERVAL 5
#define OVS_CACHE_LINE_SIZE CACHE_LINE_SIZE
#define OVS_VPORT_DPDK "ovs_dpdk"
#define OVS_VHOST_QUEUE_MAP_UNKNOWN (-1)

uint32_t
netdev_dpdk_buf_size(int mtu)
{
    return ROUND_UP(MTU_TO_MAX_FRAME_LEN(mtu), NETDEV_DPDK_MBUF_ALIGN)
            + RTE_PKTMBUF_HEADROOM;
}

static void *
dpdk_rte_mzalloc(size_t sz)
{
    return rte_zmalloc(OVS_VPORT_DPDK, sz, OVS_CACHE_LINE_SIZE);
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

struct rte_mempool *
netdev_dpdk_mp_create_pool(const char *pool_name, uint32_t n_mbufs,
                           uint32_t mbuf_size, int socket_id)
{
    uint32_t mbuf_priv_data_len;
    uint32_t aligned_mbuf_size;
    struct rte_mempool *mp;
    uint32_t pkt_size;

    /* The size of the mbuf's private area (i.e. area that holds OvS'
     * dp_packet data). */
    mbuf_priv_data_len = sizeof(struct dp_packet) - sizeof(struct rte_mbuf);
    /* The size of the entire dp_packet. */
    pkt_size = sizeof(struct dp_packet) + mbuf_size;
    /* mbuf size, rounded up to cacheline size. */
    aligned_mbuf_size = ROUND_UP(pkt_size, RTE_CACHE_LINE_SIZE);
    /* If there is a size discrepancy, add padding to mbuf_priv_data_len.
     * This maintains mbuf size cache alignment, while also honoring RX
     * buffer alignment in the data portion of the mbuf.  If this adjustment
     * is not made, there is a possiblity later on that for an element of
     * the mempool, buf, buf->data_len < (buf->buf_len - buf->data_off).
     * This is problematic in the case of multi-segment mbufs, particularly
     * when an mbuf segment needs to be resized (when [push|popp]ing a VLAN
     * header, for example. */
    mbuf_priv_data_len += (aligned_mbuf_size - pkt_size);

    mp = rte_pktmbuf_pool_create(pool_name, n_mbufs, MP_CACHE_SZ,
                                 mbuf_priv_data_len, mbuf_size,
                                 socket_id);

    if (mp) {
        /* rte_pktmbuf_pool_create has done some initialization of the
         * rte_mbuf part of each dp_packet, while ovs_rte_pktmbuf_init
         * initializes some OVS specific fields of dp_packet. */
        rte_mempool_obj_iter(mp, ovs_rte_pktmbuf_init, NULL);
    }

    return mp;
}

/* Max and min number of packets in the mempool. OVS tries to allocate a
 * mempool with MAX_NB_MBUF: if this fails (because the system doesn't have
 * enough hugepages) we keep halving the number until the allocation succeeds
 * or we reach MIN_NB_MBUF. */

#define MAX_NB_MBUF          (4096 * 64)
#define MIN_NB_MBUF          (4096 * 4)

/* MAX_NB_MBUF can be divided by 2 many times, until MIN_NB_MBUF */
BUILD_ASSERT_DECL(MAX_NB_MBUF % ROUND_DOWN_POW2(MAX_NB_MBUF / MIN_NB_MBUF)
                  == 0);

/* The smallest possible NB_MBUF that we're going to try should be a multiple
 * of MP_CACHE_SZ. This is advised by DPDK documentation. */
BUILD_ASSERT_DECL((MAX_NB_MBUF / ROUND_DOWN_POW2(MAX_NB_MBUF / MIN_NB_MBUF))
                  % MP_CACHE_SZ == 0);

static bool per_port_memory;

struct ovs_mutex dpdk_mp_mutex OVS_ACQ_AFTER(dpdk_common_mutex)
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

static void
mempool_clear_user_pools(void)
{
    n_user_mempools = 0;
    free(user_mempools);
    user_mempools = NULL;
}

static void
mempool_add_user_pool(int adj_mtu, int socket_id)
{
    user_mempools = xrealloc(user_mempools, (n_user_mempools + 1) *
                             sizeof *user_mempools);
    user_mempools[n_user_mempools].adj_mtu = adj_mtu;
    user_mempools[n_user_mempools].socket_id = socket_id;
    n_user_mempools++;
}

void
netdev_dpdk_mempool_init(const struct smap *ovs_other_config)
{
    bool enable = smap_get_bool(ovs_other_config, "per-port-memory", false);
    const char *mtus = smap_get(ovs_other_config, "shared-mempool-config");
    char *list, *copy, *key, *value;
    int error = 0;

    per_port_memory = enable;
    VLOG_INFO("Per port memory for DPDK devices %s.",
              enable ? "enabled" : "disabled");

    if (!mtus) {
        return;
    }

    mempool_clear_user_pools();
    list = copy = xstrdup(mtus);

    while (ofputil_parse_key_value(&list, &key, &value)) {
        int socket_id, mtu, adj_mtu;

        if (!str_to_int(key, 0, &mtu) || mtu < 0) {
            error = EINVAL;
            VLOG_WARN("Invalid user configured shared mempool MTU.");
            break;
        }

        if (!str_to_int(value, 0, &socket_id)) {
            /* No socket specified. It will apply for all 'numas'. */
            socket_id = INT_MAX;
        } else if (socket_id < 0) {
            error = EINVAL;
            VLOG_WARN("Invalid user configured shared mempool NUMA.");
            break;
        }

        adj_mtu = FRAME_LEN_TO_MTU(netdev_dpdk_buf_size(mtu));
        mempool_add_user_pool(adj_mtu, socket_id);
        VLOG_INFO("User configured shared mempool set for: MTU %d, NUMA %s.",
                  mtu, socket_id == INT_MAX ? "ALL" : value);
    }

    if (error) {
        VLOG_WARN("User configured shared mempools will not be used.");
        mempool_clear_user_pools();
    }

    free(copy);
}

int
netdev_dpdk_mempool_full(const struct rte_mempool *mp)
{
    /* At this point we want to know if all the mbufs are back
     * in the mempool. rte_mempool_full() is not atomic but it's
     * the best available and as we are no longer requesting mbufs
     * from the mempool, it means mbufs will not move from
     * 'mempool ring' --> 'mempool cache'.  In rte_mempool_full()
     * the ring is counted before caches, so we won't get false
     * positives in this use case and we handle false negatives.
     *
     * If future implementations of rte_mempool_full() were to change
     * it could be possible for a false positive.  Even that would
     * likely be ok, as there are additional checks during mempool
     * freeing but it would make things racey. */
    return rte_mempool_full(mp);
}

uint32_t
netdev_dpdk_mempool_calculate_mbufs_per_port(
    const struct netdev_dpdk_common *common)
{
    /* XXX: rough estimation of number of mbufs required for this port:
     * <packets required to fill the device rxqs>
     * + <packets that could be stuck on other ports txqs>
     * + <packets in the pmd threads>
     * + <additional memory for corner cases> */
    return common->requested_n_rxq * common->requested_rxq_size
           + common->requested_n_txq * common->requested_txq_size
           + MIN(RTE_MAX_LCORE, common->requested_n_rxq) * NETDEV_MAX_BURST
           + MIN_NB_MBUF;
}

void
netdev_dpdk_mempool_dump(struct rte_mempool *mp, FILE *stream)
{
    if (!mp) {
        return;
    }

    ovs_mutex_lock(&dpdk_mp_mutex);

    rte_mempool_dump(stream, mp);
    fprintf(stream, "    count: avail (%u), in use (%u)\n",
            rte_mempool_avail_count(mp),
            rte_mempool_in_use_count(mp));

    ovs_mutex_unlock(&dpdk_mp_mutex);
}

void
netdev_dpdk_mempool_list_dump(FILE *stream)
{
    ovs_mutex_lock(&dpdk_mp_mutex);
    rte_mempool_list_dump(stream);
    ovs_mutex_unlock(&dpdk_mp_mutex);
}

/* DPDK NIC drivers allocate RX buffers at a particular granularity, typically
 * aligned at 1k or less.  If a declared mbuf size is not a multiple of this
 * value, insufficient buffers are allocated to accomodate the packet in its
 * entirety.  Furthermore, certain drivers need to ensure that there is also
 * sufficient space in the Rx buffer to accommodate two VLAN tags (for QinQ
 * frames).  If the RX buffer is too small, then the driver enables scatter RX
 * behaviour, which reduces performance. To prevent this, use a buffer size
 * that is closest to 'mtu', but which satisfies the aforementioned
 * criteria. */
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

/* Free unused mempools. */
static void
dpdk_mp_sweep(void)
    OVS_REQUIRES(dpdk_mp_mutex)
{
    struct dpdk_mp *dmp;

    LIST_FOR_EACH_SAFE (dmp, list_node, &dpdk_mp_list) {
        if (!dmp->refcount && netdev_dpdk_mempool_full(dmp->mp)) {
            VLOG_DBG("Freeing mempool \"%s\"", dmp->mp->name);
            ovs_list_remove(&dmp->list_node);
            rte_mempool_free(dmp->mp);
            rte_free(dmp);
        }
    }
}

void
netdev_dpdk_mempool_sweep(void)
{
    ovs_mutex_lock(&dpdk_mp_mutex);
    dpdk_mp_sweep();
    ovs_mutex_unlock(&dpdk_mp_mutex);
}

/* Add 'dmp' to the global list, or reuse an existing entry if 'dmp' was
 * created from an already existing mempool (rte_errno == EEXIST). */
static struct dpdk_mp *
dpdk_mp_register(struct dpdk_mp *dmp, bool check_eexist)
    OVS_REQUIRES(dpdk_mp_mutex)
{
    if (check_eexist && rte_errno == EEXIST) {
        struct dpdk_mp *next;

        LIST_FOR_EACH (next, list_node, &dpdk_mp_list) {
            if (dmp->mp == next->mp) {
                rte_free(dmp);
                next->refcount++;
                return next;
            }
        }
    }

    ovs_list_push_back(&dpdk_mp_list, &dmp->list_node);
    return dmp;
}

/* Calculating the required number of mbufs differs depending on the
 * mempool model being used. Check if per port memory is in use before
 * calculating. */
static uint32_t
dpdk_calculate_mbufs(struct netdev_dpdk_common *common, int mtu)
{
    uint32_t n_mbufs;

    if (!per_port_memory) {
        /* Shared memory are being used.
         * XXX: this is a really rough method of provisioning memory.
         * It's impossible to determine what the exact memory requirements are
         * when the number of ports and rxqs that utilize a particular mempool
         * can change dynamically at runtime.  For now, use this rough
         * heurisitic. */
        if (mtu >= RTE_ETHER_MTU) {
            n_mbufs = MAX_NB_MBUF;
        } else {
            n_mbufs = MIN_NB_MBUF;
        }
    } else {
        n_mbufs = netdev_dpdk_mempool_calculate_mbufs_per_port(common);
    }

    return n_mbufs;
}

static struct dpdk_mp *
dpdk_mp_create(struct netdev_dpdk_common *common, int mtu,
               bool force_per_port)
{
    const char *netdev_name = netdev_get_name(&common->up);
    uint32_t hash = hash_string(netdev_name, 0);
    int socket_id = common->requested_socket_id;
    char mp_name[RTE_MEMPOOL_NAMESIZE];
    struct dpdk_mp *dmp = NULL;
    uint32_t mbuf_size = 0;
    uint32_t n_mbufs = 0;
    int ret;

    dmp = dpdk_rte_mzalloc(sizeof *dmp);
    if (!dmp) {
        return NULL;
    }

    dmp->socket_id = socket_id;
    dmp->mtu = mtu;
    dmp->refcount = 1;

    /* Get the size of each mbuf, based on the MTU */
    mbuf_size = MTU_TO_FRAME_LEN(mtu);

    n_mbufs = force_per_port
        ? netdev_dpdk_mempool_calculate_mbufs_per_port(common)
        : dpdk_calculate_mbufs(common, mtu);

    do {
        /* Full DPDK memory pool name must be unique and cannot be
         * longer than RTE_MEMPOOL_NAMESIZE.  Note that for the shared
         * mempool case this can result in one device using a mempool
         * which references a different device in it's name.  However as
         * mempool names are hashed, the device name will not be readable
         * so this is not an issue for tasks such as debugging. */
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
                 common->requested_n_rxq, common->requested_n_txq,
                 RTE_CACHE_LINE_SIZE);

        dmp->mp = netdev_dpdk_mp_create_pool(mp_name, n_mbufs, mbuf_size,
                                             socket_id);

        if (dmp->mp) {
            VLOG_DBG("Allocated \"%s\" mempool with %u mbufs",
                     mp_name, n_mbufs);
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
netdev_dpdk_mempool_create(struct netdev_dpdk_common *common,
                           bool force_per_port, int mtu)
{
    struct dpdk_mp *dmp;

    ovs_mutex_lock(&dpdk_mp_mutex);
    dpdk_mp_sweep();

    dmp = dpdk_mp_create(common, mtu, force_per_port);
    if (dmp) {
        dmp = dpdk_mp_register(dmp, true);
    }

    ovs_mutex_unlock(&dpdk_mp_mutex);

    return dmp;
}

static struct dpdk_mp *
dpdk_mp_get(struct netdev_dpdk_common *common, int mtu)
{
    struct dpdk_mp *dmp = NULL;
    bool reuse = false;

    ovs_mutex_lock(&dpdk_mp_mutex);
    /* Check if shared memory is being used, if so check existing mempools
     * to see if reuse is possible. */
    if (!per_port_memory) {
        /* If user has provided defined mempools, check if one is suitable
         * and get new buffer size. */
        mtu = dpdk_get_user_adjusted_mtu(mtu, common->requested_mtu,
                                         common->requested_socket_id);
        LIST_FOR_EACH (dmp, list_node, &dpdk_mp_list) {
            if (dmp->socket_id == common->requested_socket_id
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
        dmp = dpdk_mp_create(common, mtu, false);
        if (dmp) {
            /* Shared memory will hit the reuse case above so will not
             * request a mempool that already exists but we need to check
             * for the EEXIST case for per port memory case. */
            dmp = dpdk_mp_register(dmp, per_port_memory);
        }
    }

    ovs_mutex_unlock(&dpdk_mp_mutex);

    return dmp;
}

/* Decrement reference to a mempool. */
void
netdev_dpdk_mempool_release(struct dpdk_mp *dmp)
{
    if (!dmp) {
        return;
    }

    ovs_mutex_lock(&dpdk_mp_mutex);
    ovs_assert(dmp->refcount);
    dmp->refcount--;
    ovs_mutex_unlock(&dpdk_mp_mutex);
}

/* Depending on the memory model being used this function tries to
 * identify and reuse an existing mempool or tries to allocate a new
 * mempool on requested_socket_id with mbuf size corresponding to the
 * requested_mtu.  On success, a new configuration will be applied.
 * On error, device will be left unchanged. */
int
netdev_dpdk_mempool_configure(struct netdev_dpdk_common *common)
    OVS_REQUIRES(common->mutex)
{
    uint32_t buf_size = netdev_dpdk_buf_size(common->requested_mtu);
    struct dpdk_mp *dmp;
    int ret = 0;

    /* With shared memory we do not need to configure a mempool if the MTU
     * and socket ID have not changed, the previous configuration is still
     * valid so return 0 */
    if (!per_port_memory && common->mtu == common->requested_mtu
        && common->socket_id == common->requested_socket_id) {
        return ret;
    }

    dmp = dpdk_mp_get(common, FRAME_LEN_TO_MTU(buf_size));

    if (!dmp) {
        VLOG_ERR("Failed to create memory pool for netdev "
                 "%s, with MTU %d on socket %d: %s\n",
                 common->up.name,
                 common->requested_mtu,
                 common->requested_socket_id,
                 rte_strerror(rte_errno));
        ret = rte_errno;
    } else {
        /* Check for any pre-existing dpdk_mp for the device before accessing
         * the associated mempool. */
        if (common->dpdk_mp) {
            /* A new MTU was requested, decrement the reference count for the
             * devices current dpdk_mp.  This is required even if a pointer to
             * same dpdk_mp is returned by dpdk_mp_get.  The refcount for dmp
             * has already been incremented by dpdk_mp_get at this stage so it
             * must be decremented to keep an accurate refcount for the
             * dpdk_mp. */
            netdev_dpdk_mempool_release(common->dpdk_mp);
        }

        common->dpdk_mp = dmp;
        common->mtu = common->requested_mtu;
        common->socket_id = common->requested_socket_id;
        common->max_packet_len = MTU_TO_FRAME_LEN(common->mtu);
    }

    return ret;
}

void
netdev_dpdk_check_link_status(struct netdev_dpdk_common *common)
{
    struct rte_eth_link link;

    if (common->port_id == DPDK_ETH_PORT_ID_INVALID) {
        return;
    }

    if (rte_eth_link_get_nowait(common->port_id, &link) < 0) {
        VLOG_DBG_RL(&rl,
                    "Failed to retrieve link status for port "DPDK_PORT_ID_FMT,
                    common->port_id);
        return;
    }

    if (common->link.link_status != link.link_status) {
        netdev_change_seq_changed(&common->up);

        common->link_reset_cnt++;
        common->link = link;
        if (common->link.link_status) {
            VLOG_DBG_RL(&rl,
                        "Port "DPDK_PORT_ID_FMT" Link Up - speed %u Mbps - %s",
                        common->port_id,
                        (unsigned) common->link.link_speed,
                        (common->link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX)
                        ? "full-duplex" : "half-duplex");
        } else {
            VLOG_DBG_RL(&rl, "Port "DPDK_PORT_ID_FMT" Link Down",
                        common->port_id);
        }
    }
}

void *
netdev_dpdk_watchdog(void *list_)
{
    struct netdev_dpdk_common *common;
    struct ovs_list *list = list_;

    ovs_assert(list);

    pthread_detach(pthread_self());

    for (;;) {
        ovs_mutex_lock(&dpdk_common_mutex);
        LIST_FOR_EACH (common, list_node, list) {
            ovs_mutex_lock(&common->mutex);
            if (!netdev_dpdk_is_vhost(&common->up)) {
                netdev_dpdk_check_link_status(common);
            }

            ovs_mutex_unlock(&common->mutex);
        }

        ovs_mutex_unlock(&dpdk_common_mutex);
        xsleep(DPDK_PORT_WATCHDOG_INTERVAL);
    }

    return NULL;
}

static void
netdev_dpdk_update_netdev_flag(struct netdev_dpdk_common *common,
                               enum dpdk_hw_ol_features hw_ol_features,
                               enum netdev_ol_flags flag)
    OVS_REQUIRES(common->mutex)
{
    if (common->hw_ol_features & hw_ol_features) {
        common->up.ol_flags |= flag;
    } else {
        common->up.ol_flags &= ~flag;
    }
}

void
netdev_dpdk_update_netdev_flags(struct netdev_dpdk_common *common)
    OVS_REQUIRES(common->mutex)
{
    netdev_dpdk_update_netdev_flag(common, NETDEV_TX_IPV4_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_IPV4_CKSUM);
    netdev_dpdk_update_netdev_flag(common, NETDEV_TX_TCP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_TCP_CKSUM);
    netdev_dpdk_update_netdev_flag(common, NETDEV_TX_UDP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_UDP_CKSUM);
    netdev_dpdk_update_netdev_flag(common, NETDEV_TX_SCTP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_SCTP_CKSUM);
    netdev_dpdk_update_netdev_flag(common, NETDEV_TX_TSO_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_TCP_TSO);
    netdev_dpdk_update_netdev_flag(common, NETDEV_TX_VXLAN_TNL_TSO_OFFLOAD,
                                   NETDEV_TX_VXLAN_TNL_TSO);
    netdev_dpdk_update_netdev_flag(common, NETDEV_TX_GRE_TNL_TSO_OFFLOAD,
                                   NETDEV_TX_GRE_TNL_TSO);
    netdev_dpdk_update_netdev_flag(common, NETDEV_TX_GENEVE_TNL_TSO_OFFLOAD,
                                   NETDEV_TX_GENEVE_TNL_TSO);
    netdev_dpdk_update_netdev_flag(common, NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_OUTER_IP_CKSUM);
    netdev_dpdk_update_netdev_flag(common, NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD,
                                   NETDEV_TX_OFFLOAD_OUTER_UDP_CKSUM);
}

void
netdev_dpdk_detect_hw_ol_features(struct netdev_dpdk_common *common,
                                  const struct rte_eth_dev_info *info)
    OVS_REQUIRES(common->mutex)
{
    uint32_t rx_chksm_offload_capa = RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
                                     RTE_ETH_RX_OFFLOAD_TCP_CKSUM |
                                     RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;

    if (strstr(info->driver_name, "vf") != NULL) {
        VLOG_INFO("Virtual function detected, HW_CRC_STRIP will be enabled");
        common->hw_ol_features |= NETDEV_RX_HW_CRC_STRIP;
    } else {
        common->hw_ol_features &= ~NETDEV_RX_HW_CRC_STRIP;
    }

    if ((info->rx_offload_capa & rx_chksm_offload_capa) !=
            rx_chksm_offload_capa) {
        VLOG_WARN("Rx checksum offload is not supported on port "
                  DPDK_PORT_ID_FMT, common->port_id);
        common->hw_ol_features &= ~NETDEV_RX_CHECKSUM_OFFLOAD;
    } else {
        common->hw_ol_features |= NETDEV_RX_CHECKSUM_OFFLOAD;
    }

    if (info->rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER) {
        common->hw_ol_features |= NETDEV_RX_HW_SCATTER;
    } else {
        /* Do not warn on lack of scatter support */
        common->hw_ol_features &= ~NETDEV_RX_HW_SCATTER;
    }

    if (info->tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
        common->hw_ol_features |= NETDEV_TX_IPV4_CKSUM_OFFLOAD;
    } else {
        common->hw_ol_features &= ~NETDEV_TX_IPV4_CKSUM_OFFLOAD;
    }

    if (info->tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) {
        common->hw_ol_features |= NETDEV_TX_TCP_CKSUM_OFFLOAD;
    } else {
        common->hw_ol_features &= ~NETDEV_TX_TCP_CKSUM_OFFLOAD;
    }

    if (info->tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
        common->hw_ol_features |= NETDEV_TX_UDP_CKSUM_OFFLOAD;
    } else {
        common->hw_ol_features &= ~NETDEV_TX_UDP_CKSUM_OFFLOAD;
    }

    if (info->tx_offload_capa & RTE_ETH_TX_OFFLOAD_SCTP_CKSUM) {
        common->hw_ol_features |= NETDEV_TX_SCTP_CKSUM_OFFLOAD;
    } else {
        common->hw_ol_features &= ~NETDEV_TX_SCTP_CKSUM_OFFLOAD;
    }

    if (info->tx_offload_capa & RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM) {
        common->hw_ol_features |= NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD;
    } else {
        common->hw_ol_features &= ~NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD;
    }

    if (info->tx_offload_capa & RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM) {
        common->hw_ol_features |= NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD;
    } else {
        common->hw_ol_features &= ~NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD;
    }

    common->hw_ol_features &= ~NETDEV_TX_TSO_OFFLOAD;
    if (userspace_tso_enabled()) {
        if (info->tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO) {
            common->hw_ol_features |= NETDEV_TX_TSO_OFFLOAD;
        } else {
            VLOG_WARN("%s: Tx TSO offload is not supported.",
                      netdev_get_name(&common->up));
        }

        if (info->tx_offload_capa & RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO) {
            common->hw_ol_features |= NETDEV_TX_VXLAN_TNL_TSO_OFFLOAD;
        } else {
            VLOG_WARN("%s: Tx Vxlan tunnel TSO offload is not supported.",
                      netdev_get_name(&common->up));
        }

        if (info->tx_offload_capa & RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO) {
            common->hw_ol_features |= NETDEV_TX_GENEVE_TNL_TSO_OFFLOAD;
        } else {
            VLOG_WARN("%s: Tx Geneve tunnel TSO offload is not supported.",
                      netdev_get_name(&common->up));
        }

        if (info->tx_offload_capa & RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO) {
            common->hw_ol_features |= NETDEV_TX_GRE_TNL_TSO_OFFLOAD;
        } else {
            VLOG_WARN("%s: Tx GRE tunnel TSO offload is not supported.",
                      netdev_get_name(&common->up));
        }
    }
}

void
netdev_dpdk_build_port_conf(struct netdev_dpdk_common *common,
                            const struct rte_eth_dev_info *info,
                            struct rte_eth_conf *conf)
{
    /* As of DPDK 17.11.1 a few PMDs require to explicitly enable
     * scatter to support jumbo RX.
     * Setting scatter for the device is done after checking for
     * scatter support in the device capabilites. */
    if (common->mtu > RTE_ETHER_MTU) {
        if (common->hw_ol_features & NETDEV_RX_HW_SCATTER) {
            conf->rxmode.offloads |= RTE_ETH_RX_OFFLOAD_SCATTER;
        }
    }

    conf->intr_conf.lsc = common->lsc_interrupt_mode;

    if (common->hw_ol_features & NETDEV_RX_CHECKSUM_OFFLOAD) {
        conf->rxmode.offloads |= RTE_ETH_RX_OFFLOAD_CHECKSUM;
    }

    if (!(common->hw_ol_features & NETDEV_RX_HW_CRC_STRIP)
        && info->rx_offload_capa & RTE_ETH_RX_OFFLOAD_KEEP_CRC) {
        conf->rxmode.offloads |= RTE_ETH_RX_OFFLOAD_KEEP_CRC;
    }

    if (common->hw_ol_features & NETDEV_TX_IPV4_CKSUM_OFFLOAD) {
        conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    }

    if (common->hw_ol_features & NETDEV_TX_TCP_CKSUM_OFFLOAD) {
        conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
    }

    if (common->hw_ol_features & NETDEV_TX_UDP_CKSUM_OFFLOAD) {
        conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
    }

    if (common->hw_ol_features & NETDEV_TX_SCTP_CKSUM_OFFLOAD) {
        conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_SCTP_CKSUM;
    }

    if (common->hw_ol_features & NETDEV_TX_TSO_OFFLOAD) {
        conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_TSO;
    }

    if (common->hw_ol_features & NETDEV_TX_VXLAN_TNL_TSO_OFFLOAD) {
        conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO;
    }

    if (common->hw_ol_features & NETDEV_TX_GENEVE_TNL_TSO_OFFLOAD) {
        conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO;
    }

    if (common->hw_ol_features & NETDEV_TX_GRE_TNL_TSO_OFFLOAD) {
        conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO;
    }

    if (common->hw_ol_features & NETDEV_TX_OUTER_IP_CKSUM_OFFLOAD) {
        conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM;
    }

    if (common->hw_ol_features & NETDEV_TX_OUTER_UDP_CKSUM_OFFLOAD) {
        conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM;
    }

    /* Limit configured rss hash functions to only those supported
     * by the eth device. */
    conf->rx_adv_conf.rss_conf.rss_hf &= info->flow_type_rss_offloads;
    if (conf->rx_adv_conf.rss_conf.rss_hf == 0) {
        conf->rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    } else {
        conf->rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    }
}

struct netdev_dpdk_tx_queue *
netdev_dpdk_alloc_txq(unsigned int n_txqs)
{
    struct netdev_dpdk_tx_queue *txqs;
    unsigned i;

    txqs = dpdk_rte_mzalloc(n_txqs * sizeof *txqs);
    if (txqs) {
        for (i = 0; i < n_txqs; i++) {
            /* Initialize map for vhost devices. */
            txqs[i].map = OVS_VHOST_QUEUE_MAP_UNKNOWN;
            rte_spinlock_init(&txqs[i].tx_lock);
        }
    }

    return txqs;
}

void
netdev_dpdk_clear_xstats(struct netdev_dpdk_common *common)
{
    free(common->rte_xstats_names);
    common->rte_xstats_names = NULL;
    common->rte_xstats_names_size = 0;
    free(common->rte_xstats_ids);
    common->rte_xstats_ids = NULL;
    common->rte_xstats_ids_size = 0;
}

const char *
netdev_dpdk_get_xstat_name(struct netdev_dpdk_common *common, uint64_t id)
    OVS_REQUIRES(common->mutex)
{
    if (id >= common->rte_xstats_names_size) {
        return "UNKNOWN";
    }

    return common->rte_xstats_names[id].name;
}

static bool
is_queue_stat(const char *s)
{
    uint16_t tmp;

    return (s[0] == 'r' || s[0] == 't') &&
            (ovs_scan(s + 1, "x_q%"SCNu16"_packets", &tmp) ||
             ovs_scan(s + 1, "x_q%"SCNu16"_bytes", &tmp));
}

void
netdev_dpdk_configure_xstats(struct netdev_dpdk_common *common)
    OVS_REQUIRES(common->mutex)
{
    struct rte_eth_xstat_name *rte_xstats_names = NULL;
    struct rte_eth_xstat *rte_xstats = NULL;
    int rte_xstats_names_size;
    int rte_xstats_len;
    const char *name;
    uint64_t id;

    netdev_dpdk_clear_xstats(common);

    rte_xstats_names_size =
        rte_eth_xstats_get_names(common->port_id, NULL, 0);
    if (rte_xstats_names_size < 0) {
        VLOG_WARN("Cannot get XSTATS names for port: "DPDK_PORT_ID_FMT,
                  common->port_id);
        goto out;
    }

    rte_xstats_names = xcalloc(rte_xstats_names_size,
                               sizeof *rte_xstats_names);
    rte_xstats_len = rte_eth_xstats_get_names(common->port_id,
                                              rte_xstats_names,
                                              rte_xstats_names_size);
    if (rte_xstats_len < 0 || rte_xstats_len != rte_xstats_names_size) {
        VLOG_WARN("Cannot get XSTATS names for port: "DPDK_PORT_ID_FMT,
                  common->port_id);
        goto out;
    }

    rte_xstats = xcalloc(rte_xstats_names_size, sizeof *rte_xstats);
    rte_xstats_len = rte_eth_xstats_get(common->port_id, rte_xstats,
                                        rte_xstats_names_size);
    if (rte_xstats_len < 0 || rte_xstats_len != rte_xstats_names_size) {
        VLOG_WARN("Cannot get XSTATS for port: "DPDK_PORT_ID_FMT,
                  common->port_id);
        goto out;
    }

    common->rte_xstats_names = rte_xstats_names;
    rte_xstats_names = NULL;
    common->rte_xstats_names_size = rte_xstats_names_size;

    common->rte_xstats_ids = xcalloc(rte_xstats_names_size,
                                     sizeof *common->rte_xstats_ids);
    for (unsigned int i = 0; i < rte_xstats_names_size; i++) {
        id = rte_xstats[i].id;
        name = netdev_dpdk_get_xstat_name(common, id);

        /* For custom stats, we filter out everything except per rxq/txq basic
         * stats, and dropped, error and management counters. */
        if (is_queue_stat(name) ||
            string_ends_with(name, "_errors") ||
            strstr(name, "_management_") ||
            string_ends_with(name, "_dropped")) {

            common->rte_xstats_ids[common->rte_xstats_ids_size] = id;
            common->rte_xstats_ids_size++;
        }
    }

out:
    free(rte_xstats);
    free(rte_xstats_names);
}

void
netdev_dpdk_get_config_common(struct netdev_dpdk_common *common,
                              struct smap *args)
    OVS_REQUIRES(common->mutex)
{
    if (common->devargs && common->devargs[0]) {
        smap_add_format(args, "dpdk-devargs", "%s", common->devargs);
    }

    smap_add_format(args, "n_rxq", "%d", common->user_n_rxq);

    if (common->fc_conf.mode == RTE_ETH_FC_TX_PAUSE ||
        common->fc_conf.mode == RTE_ETH_FC_FULL) {
        smap_add(args, "rx-flow-ctrl", "true");
    }

    if (common->fc_conf.mode == RTE_ETH_FC_RX_PAUSE ||
        common->fc_conf.mode == RTE_ETH_FC_FULL) {
        smap_add(args, "tx-flow-ctrl", "true");
    }

    if (common->fc_conf.autoneg) {
        smap_add(args, "flow-ctrl-autoneg", "true");
    }

    smap_add_format(args, "n_rxq_desc", "%d", common->rxq_size);
    smap_add_format(args, "n_txq_desc", "%d", common->txq_size);

    smap_add(args, "dpdk-lsc-interrupt",
             common->lsc_interrupt_mode ? "true" : "false");

    if (common->is_representor) {
        smap_add_format(args, "dpdk-vf-mac", ETH_ADDR_FMT,
                        ETH_ADDR_ARGS(common->requested_hwaddr));
    }
}

struct netdev_dpdk_common *
netdev_dpdk_lookup_common_by_port_id(dpdk_port_t port_id,
                                     struct ovs_list *list)
    OVS_REQUIRES(dpdk_common_mutex)
{
    struct netdev_dpdk_common *common;

    LIST_FOR_EACH (common, list_node, list) {
        if (common->port_id == port_id) {
            return common;
        }
    }

    return NULL;
}

dpdk_port_t
netdev_dpdk_get_port_by_devargs(const char *devargs)
    OVS_REQUIRES(dpdk_common_mutex)
{
    dpdk_port_t port_id;
    struct rte_dev_iterator iterator;

    RTE_ETH_FOREACH_MATCHING_DEV (port_id, devargs, &iterator) {
        /* If a break is done - must call rte_eth_iterator_cleanup. */
        rte_eth_iterator_cleanup(&iterator);
        break;
    }

    return port_id;
}

void
netdev_dpdk_set_rxq_config(struct netdev_dpdk_common *common,
                    const struct smap *args)
    OVS_REQUIRES(common->mutex)
{
    int new_n_rxq;

    new_n_rxq = MAX(smap_get_int(args, "n_rxq", NR_QUEUE), 1);
    if (new_n_rxq != common->user_n_rxq) {
        common->user_n_rxq = new_n_rxq;
        netdev_request_reconfigure(&common->up);
    }
}

int
netdev_dpdk_get_numa_id(const struct netdev *netdev)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);

    return common->socket_id;
}

/* Sets the number of tx queues for the dpdk interface. */
int
netdev_dpdk_set_tx_multiq(struct netdev *netdev, unsigned int n_txq)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);

    ovs_mutex_lock(&common->mutex);

    if (common->requested_n_txq == n_txq) {
        goto out;
    }

    common->requested_n_txq = n_txq;
    netdev_request_reconfigure(netdev);

out:
    ovs_mutex_unlock(&common->mutex);
    return 0;
}

struct netdev_rxq *
netdev_dpdk_rxq_alloc(void)
{
    struct netdev_rxq_dpdk *rx = dpdk_rte_mzalloc(sizeof *rx);

    if (rx) {
        return &rx->up;
    }

    return NULL;
}

int
netdev_dpdk_rxq_construct(struct netdev_rxq *rxq)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(rxq->netdev);
    struct netdev_rxq_dpdk *rx = netdev_rxq_dpdk_cast(rxq);

    ovs_mutex_lock(&common->mutex);
    rx->port_id = common->port_id;
    ovs_mutex_unlock(&common->mutex);

    return 0;
}

void
netdev_dpdk_rxq_destruct(struct netdev_rxq *rxq OVS_UNUSED)
{
}

void
netdev_dpdk_rxq_dealloc(struct netdev_rxq *rxq)
{
    struct netdev_rxq_dpdk *rx = netdev_rxq_dpdk_cast(rxq);

    rte_free(rx);
}

static bool
netdev_dpdk_prep_hwol_packet(struct netdev_dpdk_common *common,
                             struct rte_mbuf *mbuf)
{
    struct dp_packet *pkt = CONTAINER_OF(mbuf, struct dp_packet, mbuf);
    uint64_t unexpected = mbuf->ol_flags & RTE_MBUF_F_TX_OFFLOAD_MASK;
    const struct ip_header *ip;
    bool is_sctp;
    bool l3_csum;
    bool l4_csum;
    bool is_tcp;
    bool is_udp;
    void *l2;
    void *l3;
    void *l4;

    if (OVS_UNLIKELY(unexpected)) {
        VLOG_WARN_RL(&rl, "%s: Unexpected Tx offload flags: %#"PRIx64,
                     netdev_get_name(&common->up), unexpected);
        netdev_dpdk_mbuf_dump(netdev_get_name(&common->up),
                              "Packet with unexpected ol_flags", mbuf);
        return false;
    }

    if (!dp_packet_ip_checksum_partial(pkt)
        && !dp_packet_inner_ip_checksum_partial(pkt)
        && !dp_packet_l4_checksum_partial(pkt)
        && !dp_packet_inner_l4_checksum_partial(pkt)
        && !mbuf->tso_segsz) {

        return true;
    }

    if (dp_packet_tunnel(pkt)) {
        mbuf->outer_l2_len = (char *) dp_packet_l3(pkt) -
                             (char *) dp_packet_eth(pkt);
        mbuf->outer_l3_len = (char *) dp_packet_l4(pkt) -
                             (char *) dp_packet_l3(pkt);

        if (dp_packet_tunnel_geneve(pkt)) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_TUNNEL_GENEVE;
        } else if (dp_packet_tunnel_vxlan(pkt)) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_TUNNEL_VXLAN;
        } else {
            ovs_assert(dp_packet_tunnel_gre(pkt));
            mbuf->ol_flags |= RTE_MBUF_F_TX_TUNNEL_GRE;
        }

        if (dp_packet_ip_checksum_partial(pkt)) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_OUTER_IP_CKSUM;
        }

        if (dp_packet_l4_checksum_partial(pkt)) {
            ovs_assert(dp_packet_l4_proto_udp(pkt));
            mbuf->ol_flags |= RTE_MBUF_F_TX_OUTER_UDP_CKSUM;
        }

        ip = dp_packet_l3(pkt);
        mbuf->ol_flags |= IP_VER(ip->ip_ihl_ver) == 4
                          ? RTE_MBUF_F_TX_OUTER_IPV4
                          : RTE_MBUF_F_TX_OUTER_IPV6;

        /* Inner L2 length must account for the tunnel header length. */
        l2 = dp_packet_l4(pkt);
        l3 = dp_packet_inner_l3(pkt);
        l3_csum = dp_packet_inner_ip_checksum_partial(pkt);
        l4 = dp_packet_inner_l4(pkt);
        l4_csum = dp_packet_inner_l4_checksum_partial(pkt);
        is_tcp = dp_packet_inner_l4_proto_tcp(pkt);
        is_udp = dp_packet_inner_l4_proto_udp(pkt);
        is_sctp = dp_packet_inner_l4_proto_sctp(pkt);
    } else {
        mbuf->outer_l2_len = 0;
        mbuf->outer_l3_len = 0;

        l2 = dp_packet_eth(pkt);
        l3 = dp_packet_l3(pkt);
        l3_csum = dp_packet_ip_checksum_partial(pkt);
        l4 = dp_packet_l4(pkt);
        l4_csum = dp_packet_l4_checksum_partial(pkt);
        is_tcp = dp_packet_l4_proto_tcp(pkt);
        is_udp = dp_packet_l4_proto_udp(pkt);
        is_sctp = dp_packet_l4_proto_sctp(pkt);
    }

    ovs_assert(l4);

    ip = l3;
    mbuf->ol_flags |= IP_VER(ip->ip_ihl_ver) == 4
                      ? RTE_MBUF_F_TX_IPV4 : RTE_MBUF_F_TX_IPV6;

    if (l3_csum) {
        mbuf->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
    }

    if (l4_csum) {
        if (is_tcp) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
        } else if (is_udp) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
        } else {
            ovs_assert(is_sctp);
            mbuf->ol_flags |= RTE_MBUF_F_TX_SCTP_CKSUM;
        }
    }

    mbuf->l2_len = (char *) l3 - (char *) l2;
    mbuf->l3_len = (char *) l4 - (char *) l3;

    if (mbuf->tso_segsz) {
        struct tcp_header *th = l4;
        int hdr_len;

        mbuf->l4_len = TCP_OFFSET(th->tcp_ctl) * 4;

        hdr_len = mbuf->l2_len + mbuf->l3_len + mbuf->l4_len;
        if (dp_packet_tunnel(pkt)) {
            hdr_len += mbuf->outer_l2_len + mbuf->outer_l3_len;
        }

        if (OVS_UNLIKELY((hdr_len + mbuf->tso_segsz) >
                         common->max_packet_len)) {
            VLOG_WARN_RL(&rl, "%s: Oversized TSO packet. hdr: %"PRIu32", "
                         "gso: %"PRIu32", max len: %"PRIu32"",
                         common->up.name, hdr_len, mbuf->tso_segsz,
                         common->max_packet_len);
            return false;
        }
        mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;

        /* DPDK API mandates IPv4 checksum when requesting TSO. */
        if (IP_VER(ip->ip_ihl_ver) == 4) {
            mbuf->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
        }
    }

    return true;
}

/* Prepare a batch for HWOL.
 * Return the number of good packets in the batch. */
int
netdev_dpdk_prep_hwol_batch(struct netdev_dpdk_common *common,
                            struct rte_mbuf **pkts, int pkt_cnt)
{
    struct rte_mbuf *pkt;
    int cnt = 0;
    int i = 0;

    /* Prepare and filter bad HWOL packets. */
    for (i = 0; i < pkt_cnt; i++) {
        pkt = pkts[i];
        if (!netdev_dpdk_prep_hwol_packet(common, pkt)) {
            rte_pktmbuf_free(pkt);
            continue;
        }

        if (OVS_UNLIKELY(i != cnt)) {
            pkts[cnt] = pkt;
        }

        cnt++;
    }

    return cnt;
}

void
netdev_dpdk_mbuf_dump(const char *prefix, const char *message,
                      const struct rte_mbuf *mbuf)
{
    static struct vlog_rate_limit dump_rl = VLOG_RATE_LIMIT_INIT(5, 5);
    char *response = NULL;
    FILE *stream;
    size_t size;

    if (VLOG_DROP_DBG(&dump_rl)) {
        return;
    }

    stream = open_memstream(&response, &size);
    if (!stream) {
        VLOG_ERR("Unable to open memstream for mbuf dump: %s.",
                 ovs_strerror(errno));
        return;
    }

    rte_pktmbuf_dump(stream, mbuf, rte_pktmbuf_pkt_len(mbuf));

    fclose(stream);

    VLOG_DBG(prefix ? "%s: %s:\n%s" : "%s%s:\n%s",
             prefix ? prefix : "", message, response);
    free(response);
}

/* Tries to transmit 'pkts' to txq 'qid' of device 'dev'.  Takes ownership of
 * 'pkts', even in case of failure.
 *
 * Returns the number of packets that weren't transmitted. */
int
netdev_dpdk_eth_tx_burst(struct netdev_dpdk_common *common,
                         dpdk_port_t port_id, int qid,
                         struct rte_mbuf **pkts, int cnt)
{
    uint32_t nb_tx = 0;
    uint16_t nb_tx_prep = cnt;

    if (OVS_UNLIKELY(!dpdk_dev_is_started(common))) {
        goto out;
    }

    nb_tx_prep = rte_eth_tx_prepare(port_id, qid, pkts, cnt);
    if (nb_tx_prep != cnt) {
        VLOG_WARN_RL(&rl, "%s: Output batch contains invalid packets. "
                     "Only %u/%u are valid: %s",
                     netdev_get_name(&common->up),
                     nb_tx_prep, cnt, rte_strerror(rte_errno));
        netdev_dpdk_mbuf_dump(netdev_get_name(&common->up),
                              "First invalid packet", pkts[nb_tx_prep]);
    }

    while (nb_tx != nb_tx_prep) {
        uint32_t ret;

        ret = rte_eth_tx_burst(port_id, qid, pkts + nb_tx, nb_tx_prep - nb_tx);
        if (!ret) {
            break;
        }

        nb_tx += ret;
    }

out:
    if (OVS_UNLIKELY(nb_tx != cnt)) {
        /* Free buffers, which we couldn't transmit. */
        rte_pktmbuf_free_bulk(&pkts[nb_tx], cnt - nb_tx);
    }

    return cnt - nb_tx;
}
int
netdev_dpdk_filter_packet_len(struct netdev_dpdk_common *common,
                              struct rte_mbuf **pkts, int pkt_cnt)
{
    struct rte_mbuf *pkt;
    int cnt = 0;
    int i = 0;

    /* Filter oversized packets.  The TSO packets are filtered out
     * during the offloading preparation for performance reasons. */
    for (i = 0; i < pkt_cnt; i++) {
        pkt = pkts[i];
        if (OVS_UNLIKELY((pkt->pkt_len > common->max_packet_len)
            && !pkt->tso_segsz)) {
            VLOG_WARN_RL(&rl, "%s: Too big size %" PRIu32 " max_packet_len %d",
                         common->up.name, pkt->pkt_len,
                         common->max_packet_len);
            rte_pktmbuf_free(pkt);
            continue;
        }

        if (OVS_UNLIKELY(i != cnt)) {
            pkts[cnt] = pkt;
        }
        cnt++;
    }

    return cnt;
}

uint32_t
netdev_dpdk_extbuf_size(uint32_t data_len)
{
    uint32_t buf_len = data_len;

    buf_len += sizeof(struct rte_mbuf_ext_shared_info) + sizeof(uintptr_t);
    buf_len = RTE_ALIGN_CEIL(buf_len, sizeof(uintptr_t));

    return buf_len;
}

void *
netdev_dpdk_extbuf_allocate(uint32_t buf_len)
{
    return rte_malloc(NULL, buf_len, RTE_CACHE_LINE_SIZE);
}

static void
netdev_dpdk_extbuf_free(void *addr OVS_UNUSED, void *opaque)
{
    rte_free(opaque);
}

void
netdev_dpdk_extbuf_replace(struct dp_packet *b, void *buf, uint32_t data_len)
{
    struct rte_mbuf *pkt = (struct rte_mbuf *) b;
    struct rte_mbuf_ext_shared_info *shinfo;
    uint16_t buf_len = data_len;

    shinfo = rte_pktmbuf_ext_shinfo_init_helper(buf, &buf_len,
                                                netdev_dpdk_extbuf_free,
                                                buf);
    ovs_assert(shinfo);

    if (RTE_MBUF_HAS_EXTBUF(pkt)) {
        rte_pktmbuf_detach_extbuf(pkt);
    }

    rte_pktmbuf_attach_extbuf(pkt, buf, rte_malloc_virt2iova(buf), buf_len,
                              shinfo);
    /* OVS only supports mono segment.
     * Packet size did not change, restore the current segment length. */
    pkt->data_len = pkt->pkt_len;
}

static struct rte_mbuf *
dpdk_pktmbuf_attach_extbuf(struct rte_mbuf *pkt, uint32_t data_len)
{
    uint32_t total_len = RTE_PKTMBUF_HEADROOM + data_len;
    struct rte_mbuf_ext_shared_info *shinfo = NULL;
    uint16_t buf_len;
    void *buf;

    total_len = netdev_dpdk_extbuf_size(total_len);
    if (OVS_UNLIKELY(total_len > UINT16_MAX)) {
        VLOG_ERR("Can't copy packet: too big %u", total_len);
        return NULL;
    }

    buf_len = total_len;
    buf = netdev_dpdk_extbuf_allocate(buf_len);
    if (OVS_UNLIKELY(buf == NULL)) {
        VLOG_ERR("Failed to allocate memory using rte_malloc: %u", buf_len);
        return NULL;
    }

    /* Initialize 'shinfo'. */
    shinfo = rte_pktmbuf_ext_shinfo_init_helper(buf, &buf_len,
                                                netdev_dpdk_extbuf_free,
                                                buf);
    if (OVS_UNLIKELY(shinfo == NULL)) {
        netdev_dpdk_extbuf_free(NULL, buf);
        VLOG_ERR("Failed to initialize shared info for mbuf while "
                 "attempting to attach an external buffer.");
        return NULL;
    }

    rte_pktmbuf_attach_extbuf(pkt, buf, rte_malloc_virt2iova(buf), buf_len,
                              shinfo);
    rte_pktmbuf_reset_headroom(pkt);

    return pkt;
}

static struct rte_mbuf *
dpdk_pktmbuf_alloc(struct rte_mempool *mp, uint32_t data_len)
{
    struct rte_mbuf *pkt = rte_pktmbuf_alloc(mp);

    if (OVS_UNLIKELY(!pkt)) {
        return NULL;
    }

    if (rte_pktmbuf_tailroom(pkt) >= data_len) {
        return pkt;
    }

    if (dpdk_pktmbuf_attach_extbuf(pkt, data_len)) {
        return pkt;
    }

    rte_pktmbuf_free(pkt);

    return NULL;
}

static struct dp_packet *
dpdk_copy_dp_packet_to_mbuf(struct rte_mempool *mp, struct dp_packet *pkt_orig)
{
    struct rte_mbuf *mbuf_dest;
    struct dp_packet *pkt_dest;
    uint32_t pkt_len;

    pkt_len = dp_packet_size(pkt_orig);
    mbuf_dest = dpdk_pktmbuf_alloc(mp, pkt_len);
    if (OVS_UNLIKELY(mbuf_dest == NULL)) {
            return NULL;
    }

    pkt_dest = CONTAINER_OF(mbuf_dest, struct dp_packet, mbuf);
    memcpy(dp_packet_data(pkt_dest), dp_packet_data(pkt_orig), pkt_len);
    dp_packet_set_size(pkt_dest, pkt_len);

    mbuf_dest->tx_offload = pkt_orig->mbuf.tx_offload;
    mbuf_dest->packet_type = pkt_orig->mbuf.packet_type;
    mbuf_dest->ol_flags |= (pkt_orig->mbuf.ol_flags &
                            ~(RTE_MBUF_F_EXTERNAL | RTE_MBUF_F_INDIRECT));
    mbuf_dest->tso_segsz = pkt_orig->mbuf.tso_segsz;

    memcpy(&pkt_dest->l2_pad_size, &pkt_orig->l2_pad_size,
           sizeof(struct dp_packet) - offsetof(struct dp_packet, l2_pad_size));

    if (dp_packet_l3(pkt_dest)) {
        if (dp_packet_eth(pkt_dest)) {
            mbuf_dest->l2_len = (char *) dp_packet_l3(pkt_dest)
                                - (char *) dp_packet_eth(pkt_dest);
        } else {
            mbuf_dest->l2_len = 0;
        }
        if (dp_packet_l4(pkt_dest)) {
            mbuf_dest->l3_len = (char *) dp_packet_l4(pkt_dest)
                                - (char *) dp_packet_l3(pkt_dest);
        } else {
            mbuf_dest->l3_len = 0;
        }
    }

    return pkt_dest;
}

/* Replace packets in a 'batch' with their corresponding copies using
 * DPDK memory.
 *
 * Returns the number of good packets in the batch. */
size_t
netdev_dpdk_copy_batch_to_mbuf(struct netdev_dpdk_common *common,
                               struct dp_packet_batch *batch)
{
    size_t i, size = dp_packet_batch_size(batch);
    struct dp_packet *packet;

    DP_PACKET_BATCH_REFILL_FOR_EACH (i, size, packet, batch) {
        if (OVS_UNLIKELY(packet->source == DPBUF_DPDK)) {
            dp_packet_batch_refill(batch, packet, i);
        } else {
            struct dp_packet *pktcopy;

            pktcopy = dpdk_copy_dp_packet_to_mbuf(
                common->dpdk_mp->mp, packet);
            if (pktcopy) {
                dp_packet_batch_refill(batch, pktcopy, i);
            }

            dp_packet_delete(packet);
        }
    }

    return dp_packet_batch_size(batch);
}

int
netdev_dpdk_set_dev_etheraddr(struct netdev_dpdk_common *common,
                              const struct eth_addr mac)
    OVS_REQUIRES(common->mutex)
{
    int err = 0;

    if (!netdev_dpdk_is_vhost(&common->up)) {
        struct rte_ether_addr ea;

        memcpy(ea.addr_bytes, mac.ea, ETH_ADDR_LEN);
        err = -rte_eth_dev_default_mac_addr_set(common->port_id, &ea);
    }
    if (!err) {
        common->hwaddr = mac;
    } else {
        VLOG_WARN("%s: Failed to set requested mac("ETH_ADDR_FMT"): %s",
                  netdev_get_name(&common->up), ETH_ADDR_ARGS(mac),
                  rte_strerror(err));
    }

    return err;
}

int
netdev_dpdk_set_etheraddr(struct netdev *netdev, const struct eth_addr mac)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);
    int err = 0;

    ovs_mutex_lock(&common->mutex);
    if (!eth_addr_equals(common->hwaddr, mac)) {
        err = netdev_dpdk_set_dev_etheraddr(common, mac);
        if (!err) {
            netdev_change_seq_changed(netdev);
        }
    }
    ovs_mutex_unlock(&common->mutex);

    return err;
}

int
netdev_dpdk_get_etheraddr(const struct netdev *netdev, struct eth_addr *mac)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);

    ovs_mutex_lock(&common->mutex);
    *mac = common->hwaddr;
    ovs_mutex_unlock(&common->mutex);

    return 0;
}

int
netdev_dpdk_get_mtu(const struct netdev *netdev, int *mtup)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);

    ovs_mutex_lock(&common->mutex);
    *mtup = common->mtu;
    ovs_mutex_unlock(&common->mutex);

    return 0;
}

void
netdev_dpdk_convert_xstats(struct netdev_stats *stats,
                           const struct rte_eth_xstat *xstats,
                           const struct rte_eth_xstat_name *names,
                           const unsigned int size)
{
/* DPDK XSTATS Counter names definition. */
#define DPDK_XSTATS \
    DPDK_XSTAT(multicast,               "rx_multicast_packets"            ) \
    DPDK_XSTAT(tx_multicast_packets,    "tx_multicast_packets"            ) \
    DPDK_XSTAT(rx_broadcast_packets,    "rx_broadcast_packets"            ) \
    DPDK_XSTAT(tx_broadcast_packets,    "tx_broadcast_packets"            ) \
    DPDK_XSTAT(rx_undersized_errors,    "rx_undersized_errors"            ) \
    DPDK_XSTAT(rx_oversize_errors,      "rx_oversize_errors"              ) \
    DPDK_XSTAT(rx_fragmented_errors,    "rx_fragmented_errors"            ) \
    DPDK_XSTAT(rx_jabber_errors,        "rx_jabber_errors"                ) \
    DPDK_XSTAT(rx_1_to_64_packets,      "rx_size_64_packets"              ) \
    DPDK_XSTAT(rx_65_to_127_packets,    "rx_size_65_to_127_packets"       ) \
    DPDK_XSTAT(rx_128_to_255_packets,   "rx_size_128_to_255_packets"      ) \
    DPDK_XSTAT(rx_256_to_511_packets,   "rx_size_256_to_511_packets"      ) \
    DPDK_XSTAT(rx_512_to_1023_packets,  "rx_size_512_to_1023_packets"     ) \
    DPDK_XSTAT(rx_1024_to_1522_packets, "rx_size_1024_to_1522_packets"    ) \
    DPDK_XSTAT(rx_1523_to_max_packets,  "rx_size_1523_to_max_packets"     ) \
    DPDK_XSTAT(tx_1_to_64_packets,      "tx_size_64_packets"              ) \
    DPDK_XSTAT(tx_65_to_127_packets,    "tx_size_65_to_127_packets"       ) \
    DPDK_XSTAT(tx_128_to_255_packets,   "tx_size_128_to_255_packets"      ) \
    DPDK_XSTAT(tx_256_to_511_packets,   "tx_size_256_to_511_packets"      ) \
    DPDK_XSTAT(tx_512_to_1023_packets,  "tx_size_512_to_1023_packets"     ) \
    DPDK_XSTAT(tx_1024_to_1522_packets, "tx_size_1024_to_1522_packets"    ) \
    DPDK_XSTAT(tx_1523_to_max_packets,  "tx_size_1523_to_max_packets"     )

    for (unsigned int i = 0; i < size; i++) {
#define DPDK_XSTAT(MEMBER, NAME) \
        if (strcmp(NAME, names[i].name) == 0) {   \
            stats->MEMBER = xstats[i].value;      \
            continue;                             \
        }
        DPDK_XSTATS;
#undef DPDK_XSTAT
    }
#undef DPDK_XSTATS
}

int
netdev_dpdk_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);
    struct rte_eth_stats rte_stats;
    bool gg;

    netdev_dpdk_get_carrier(netdev, &gg);
    ovs_mutex_lock(&common->mutex);

    if (!dpdk_dev_is_started(common)) {
        memset(stats, 0, sizeof *stats);
        ovs_mutex_unlock(&common->mutex);
        return 0;
    }

    struct rte_eth_xstat *rte_xstats = NULL;
    struct rte_eth_xstat_name *rte_xstats_names = NULL;
    int rte_xstats_len, rte_xstats_new_len, rte_xstats_ret;

    if (rte_eth_stats_get(common->port_id, &rte_stats)) {
        VLOG_ERR("Can't get ETH statistics for port: "DPDK_PORT_ID_FMT,
                 common->port_id);
        ovs_mutex_unlock(&common->mutex);
        return EPROTO;
    }

    /* Get length of statistics */
    rte_xstats_len = rte_eth_xstats_get_names(common->port_id, NULL, 0);
    if (rte_xstats_len < 0) {
        VLOG_WARN("Cannot get XSTATS values for port: "DPDK_PORT_ID_FMT,
                  common->port_id);
        goto out;
    }
    /* Reserve memory for 'xstats' names and values */
    rte_xstats_names = xcalloc(rte_xstats_len, sizeof *rte_xstats_names);
    rte_xstats = xcalloc(rte_xstats_len, sizeof *rte_xstats);

    /* Retrieve 'xstats' names. */
    rte_xstats_new_len = rte_eth_xstats_get_names(common->port_id,
                                                  rte_xstats_names,
                                                  rte_xstats_len);
    if (rte_xstats_new_len != rte_xstats_len) {
        VLOG_WARN("Cannot get XSTATS names for port: "DPDK_PORT_ID_FMT,
                  common->port_id);
        goto out;
    }
    /* Retrieve 'xstats' values. */
    memset(rte_xstats, 0xff, sizeof *rte_xstats * rte_xstats_len);
    rte_xstats_ret = rte_eth_xstats_get(common->port_id, rte_xstats,
                                        rte_xstats_len);
    if (rte_xstats_ret > 0 && rte_xstats_ret <= rte_xstats_len) {
        netdev_dpdk_convert_xstats(stats, rte_xstats, rte_xstats_names,
                                   rte_xstats_len);
    } else {
        VLOG_WARN("Cannot get XSTATS values for port: "DPDK_PORT_ID_FMT,
                  common->port_id);
    }

out:
    free(rte_xstats);
    free(rte_xstats_names);

    stats->rx_packets = rte_stats.ipackets;
    stats->tx_packets = rte_stats.opackets;
    stats->rx_bytes = rte_stats.ibytes;
    stats->tx_bytes = rte_stats.obytes;
    stats->rx_errors = rte_stats.ierrors;
    stats->tx_errors = rte_stats.oerrors;

    rte_spinlock_lock(&common->stats_lock);
    stats->tx_dropped = common->stats.tx_dropped;
    stats->rx_dropped = common->stats.rx_dropped;
    rte_spinlock_unlock(&common->stats_lock);

    /* These are the available DPDK counters for packets not received due to
     * local resource constraints in DPDK and NIC respectively. */
    stats->rx_dropped += rte_stats.rx_nombuf + rte_stats.imissed;
    stats->rx_missed_errors = rte_stats.imissed;

    ovs_mutex_unlock(&common->mutex);

    return 0;
}

int
netdev_dpdk_get_features(const struct netdev *netdev,
                         enum netdev_features *current,
                         enum netdev_features *advertised,
                         enum netdev_features *supported,
                         enum netdev_features *peer)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);
    struct rte_eth_link link;
    uint32_t feature = 0;

    ovs_mutex_lock(&common->mutex);
    link = common->link;
    ovs_mutex_unlock(&common->mutex);

    /* Match against OpenFlow defined link speed values. */
    if (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) {
        switch (link.link_speed) {
        case RTE_ETH_SPEED_NUM_10M:
            feature |= NETDEV_F_10MB_FD;
            break;
        case RTE_ETH_SPEED_NUM_100M:
            feature |= NETDEV_F_100MB_FD;
            break;
        case RTE_ETH_SPEED_NUM_1G:
            feature |= NETDEV_F_1GB_FD;
            break;
        case RTE_ETH_SPEED_NUM_10G:
            feature |= NETDEV_F_10GB_FD;
            break;
        case RTE_ETH_SPEED_NUM_40G:
            feature |= NETDEV_F_40GB_FD;
            break;
        case RTE_ETH_SPEED_NUM_100G:
            feature |= NETDEV_F_100GB_FD;
            break;
        default:
            feature |= NETDEV_F_OTHER;
        }
    } else if (link.link_duplex == RTE_ETH_LINK_HALF_DUPLEX) {
        switch (link.link_speed) {
        case RTE_ETH_SPEED_NUM_10M:
            feature |= NETDEV_F_10MB_HD;
            break;
        case RTE_ETH_SPEED_NUM_100M:
            feature |= NETDEV_F_100MB_HD;
            break;
        case RTE_ETH_SPEED_NUM_1G:
            feature |= NETDEV_F_1GB_HD;
            break;
        default:
            feature |= NETDEV_F_OTHER;
        }
    }

    if (link.link_autoneg) {
        feature |= NETDEV_F_AUTONEG;
    }

    *current = feature;
    *advertised = *supported = *peer = 0;

    return 0;
}

int
netdev_dpdk_get_speed(const struct netdev *netdev, uint32_t *current,
                      uint32_t *max)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);
    struct rte_eth_dev_info dev_info;
    struct rte_eth_link link;
    int diag;

    ovs_mutex_lock(&common->mutex);

    link = common->link;
    if (dpdk_dev_is_started(common)) {
        diag = rte_eth_dev_info_get(common->port_id, &dev_info);
    } else {
        diag = -ENODEV;
    }

    ovs_mutex_unlock(&common->mutex);

    *current = link.link_speed != RTE_ETH_SPEED_NUM_UNKNOWN
               ? link.link_speed : 0;

    if (diag < 0) {
        *max = 0;
        goto out;
    }

    if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_200G) {
        *max = RTE_ETH_SPEED_NUM_200G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_100G) {
        *max = RTE_ETH_SPEED_NUM_100G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_56G) {
        *max = RTE_ETH_SPEED_NUM_56G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_50G) {
        *max = RTE_ETH_SPEED_NUM_50G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_40G) {
        *max = RTE_ETH_SPEED_NUM_40G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_25G) {
        *max = RTE_ETH_SPEED_NUM_25G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_20G) {
        *max = RTE_ETH_SPEED_NUM_20G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_10G) {
        *max = RTE_ETH_SPEED_NUM_10G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_5G) {
        *max = RTE_ETH_SPEED_NUM_5G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_2_5G) {
        *max = RTE_ETH_SPEED_NUM_2_5G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_1G) {
        *max = RTE_ETH_SPEED_NUM_1G;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_100M ||
        dev_info.speed_capa & RTE_ETH_LINK_SPEED_100M_HD) {
        *max = RTE_ETH_SPEED_NUM_100M;
    } else if (dev_info.speed_capa & RTE_ETH_LINK_SPEED_10M ||
        dev_info.speed_capa & RTE_ETH_LINK_SPEED_10M_HD) {
        *max = RTE_ETH_SPEED_NUM_10M;
    } else {
        *max = 0;
    }

out:
    return 0;
}

int
netdev_dpdk_get_ifindex(const struct netdev *netdev)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);

    ovs_mutex_lock(&common->mutex);
    /* Calculate hash from the netdev name. Ensure that ifindex is a 24-bit
     * postive integer to meet RFC 2863 recommendations.
     */
    int ifindex = hash_string(netdev->name, 0) % 0xfffffe + 1;
    ovs_mutex_unlock(&common->mutex);

    return ifindex;
}

int
netdev_dpdk_get_carrier(const struct netdev *netdev, bool *carrier)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);

    ovs_mutex_lock(&common->mutex);
    netdev_dpdk_check_link_status(common);
    *carrier = common->link.link_status;
    ovs_mutex_unlock(&common->mutex);

    return 0;
}

long long int
netdev_dpdk_get_carrier_resets(const struct netdev *netdev)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);
    long long int carrier_resets;

    ovs_mutex_lock(&common->mutex);
    carrier_resets = common->link_reset_cnt;
    ovs_mutex_unlock(&common->mutex);

    return carrier_resets;
}

int
netdev_dpdk_set_miimon(struct netdev *netdev OVS_UNUSED,
                       long long int interval OVS_UNUSED)
{
    return EOPNOTSUPP;
}

int
netdev_dpdk_update_dev_flags(struct netdev_dpdk_common *common,
                             enum netdev_flags off, enum netdev_flags on,
                             enum netdev_flags *old_flagsp)
    OVS_REQUIRES(common->mutex)
{
    if ((off | on) & ~(NETDEV_UP | NETDEV_PROMISC)) {
        return EINVAL;
    }

    *old_flagsp = common->flags;
    common->flags |= on;
    common->flags &= ~off;

    if (common->flags == *old_flagsp) {
        return 0;
    }

    if (!netdev_dpdk_is_vhost(&common->up)) {
        if ((common->flags ^ *old_flagsp) & NETDEV_UP) {
            int err;

            if (common->flags & NETDEV_UP) {
                err = rte_eth_dev_set_link_up(common->port_id);
            } else {
                err = rte_eth_dev_set_link_down(common->port_id);
            }

            if (err == -ENOTSUP) {
                VLOG_INFO("Interface %s does not support link state "
                          "configuration", netdev_get_name(&common->up));
            } else if (err < 0) {
                VLOG_ERR("Interface %s link change error: %s",
                         netdev_get_name(&common->up), rte_strerror(-err));
                common->flags = *old_flagsp;
                return -err;
            }
        }

        if (common->flags & NETDEV_PROMISC) {
            rte_eth_promiscuous_enable(common->port_id);
        }

        netdev_change_seq_changed(&common->up);
    } else {
        netdev_dpdk_vhost_update_dev_flags(common, *old_flagsp, off, on);
    }

    return 0;
}

int
netdev_dpdk_update_flags(struct netdev *netdev,
                         enum netdev_flags off, enum netdev_flags on,
                         enum netdev_flags *old_flagsp)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);
    int error;

    ovs_mutex_lock(&common->mutex);
    error = netdev_dpdk_update_dev_flags(common, off, on, old_flagsp);
    ovs_mutex_unlock(&common->mutex);

    return error;
}

const char *
netdev_dpdk_link_speed_to_str(uint32_t link_speed)
{
    switch (link_speed) {
    case RTE_ETH_SPEED_NUM_10M:    return "10Mbps";
    case RTE_ETH_SPEED_NUM_100M:   return "100Mbps";
    case RTE_ETH_SPEED_NUM_1G:     return "1Gbps";
    case RTE_ETH_SPEED_NUM_2_5G:   return "2.5Gbps";
    case RTE_ETH_SPEED_NUM_5G:     return "5Gbps";
    case RTE_ETH_SPEED_NUM_10G:    return "10Gbps";
    case RTE_ETH_SPEED_NUM_20G:    return "20Gbps";
    case RTE_ETH_SPEED_NUM_25G:    return "25Gbps";
    case RTE_ETH_SPEED_NUM_40G:    return "40Gbps";
    case RTE_ETH_SPEED_NUM_50G:    return "50Gbps";
    case RTE_ETH_SPEED_NUM_56G:    return "56Gbps";
    case RTE_ETH_SPEED_NUM_100G:   return "100Gbps";
    default:                       return "Not Defined";
    }
}

int
netdev_dpdk_get_eth_dev_status(const struct netdev *netdev,
                               struct smap *args)
    OVS_EXCLUDED(dpdk_common_mutex,
                 netdev_dpdk_common_cast(netdev)->mutex)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);
    struct rte_eth_dev_info dev_info;
    uint32_t link_speed;
    int diag;

    if (!rte_eth_dev_is_valid_port(common->port_id)) {
        return ENODEV;
    }

    ovs_mutex_lock(&dpdk_common_mutex);
    ovs_mutex_lock(&common->mutex);
    diag = rte_eth_dev_info_get(common->port_id, &dev_info);
    link_speed = common->link.link_speed;
    ovs_mutex_unlock(&common->mutex);
    ovs_mutex_unlock(&dpdk_common_mutex);

    smap_add_format(args, "port_no", DPDK_PORT_ID_FMT, common->port_id);
    smap_add_format(args, "numa_id", "%d",
                    rte_eth_dev_socket_id(common->port_id));
    if (!diag) {
        smap_add_format(args, "driver_name", "%s", dev_info.driver_name);
        smap_add_format(args, "min_rx_bufsize", "%u", dev_info.min_rx_bufsize);
    }
    smap_add_format(args, "max_rx_pktlen", "%u", common->max_packet_len);
    if (!diag) {
        smap_add_format(args, "max_rx_queues", "%u", dev_info.max_rx_queues);
        smap_add_format(args, "max_tx_queues", "%u", dev_info.max_tx_queues);
        smap_add_format(args, "max_mac_addrs", "%u", dev_info.max_mac_addrs);
        smap_add_format(args, "max_hash_mac_addrs", "%u",
                        dev_info.max_hash_mac_addrs);
        smap_add_format(args, "max_vfs", "%u", dev_info.max_vfs);
        smap_add_format(args, "max_vmdq_pools", "%u", dev_info.max_vmdq_pools);
    }

    smap_add_format(args, "n_rxq", "%d", netdev->n_rxq);
    smap_add_format(args, "n_txq", "%d", netdev->n_txq);

    smap_add(args, "rx_csum_offload",
             common->hw_ol_features & NETDEV_RX_CHECKSUM_OFFLOAD
             ? "true" : "false");

    /* Querying the DPDK library for 'iftype' may be done in future, pending
     * support; cf. RFC 3635 Section 3.2.4. */
    enum { IF_TYPE_ETHERNETCSMACD = 6 };

    smap_add_format(args, "if_type", "%"PRIu32, IF_TYPE_ETHERNETCSMACD);
    smap_add_format(args, "if_descr", "%s %s", rte_version(),
                    diag < 0 ? "<unknown>" : dev_info.driver_name);
    if (!diag) {
        const char *bus_info = rte_dev_bus_info(dev_info.device);

        smap_add_format(args, "bus_info", "bus_name=%s%s%s",
                        rte_bus_name(rte_dev_bus(dev_info.device)),
                        bus_info != NULL ? ", " : "",
                        bus_info != NULL ? bus_info : "");
    }

    /* Not all link speeds are defined in the OpenFlow specs (25 Gbps).
     * In that case the speed will not be reported as part of the usual
     * call to get_features().  Get the link speed of the device and add it
     * to the device status in an easy to read string format. */
    smap_add(args, "link_speed",
             netdev_dpdk_link_speed_to_str(link_speed));

    if (common->is_representor) {
        smap_add_format(args, "dpdk-vf-mac", ETH_ADDR_FMT,
                        ETH_ADDR_ARGS(common->hwaddr));
    }

    return 0;
}

int
netdev_dpdk_common_construct(struct netdev_dpdk_common *common,
                             struct ovs_list *list,
                             dpdk_port_t port_no,
                             int socket_id,
                             uint64_t tx_retries_init)
    OVS_REQUIRES(dpdk_common_mutex)
{
    ovs_mutex_init(&common->mutex);

    rte_spinlock_init(&common->stats_lock);

    /* If the 'sid' is negative, it means that the kernel fails
     * to obtain the pci numa info.  In that situation, always
     * use 'SOCKET0'. */
    common->socket_id = socket_id < 0 ? SOCKET0 : socket_id;
    common->requested_socket_id = common->socket_id;
    common->port_id = port_no;
    common->flags = 0;
    common->requested_mtu = RTE_ETHER_MTU;
    common->max_packet_len = MTU_TO_FRAME_LEN(common->mtu);
    common->requested_lsc_interrupt_mode = 0;
    common->attached = false;
    atomic_init(&common->started, false);

    common->up.n_rxq = 0;
    common->up.n_txq = 0;
    common->user_n_rxq = NR_QUEUE;
    common->requested_n_rxq = NR_QUEUE;
    common->requested_n_txq = NR_QUEUE;
    common->requested_rxq_size = NIC_PORT_DEFAULT_RXQ_SIZE;
    common->requested_txq_size = NIC_PORT_DEFAULT_TXQ_SIZE;

    /* Initialize the flow control to NULL */
    memset(&common->fc_conf, 0, sizeof common->fc_conf);

    /* Initilize the hardware offload flags to 0 */
    common->hw_ol_features = 0;

    common->rx_metadata_delivery_configured = false;

    common->flags = NETDEV_UP | NETDEV_PROMISC;

    common->rte_xstats_names = NULL;
    common->rte_xstats_names_size = 0;

    common->rte_xstats_ids = NULL;
    common->rte_xstats_ids_size = 0;

    common->sw_stats = xzalloc(sizeof *common->sw_stats);
    common->sw_stats->tx_retries = tx_retries_init;

    ovs_list_push_back(list, &common->list_node);

    netdev_request_reconfigure(&common->up);

    return 0;
}

void
netdev_dpdk_common_destruct(struct netdev_dpdk_common *common)
    OVS_REQUIRES(dpdk_common_mutex)
    OVS_EXCLUDED(common->mutex)
{
    rte_free(common->tx_q);
    ovs_list_remove(&common->list_node);
    free(common->sw_stats);
    ovs_mutex_destroy(&common->mutex);
}

int
netdev_dpdk_common_get_config(const struct netdev *netdev, struct smap *args)
{
    struct netdev_dpdk_common *common = netdev_dpdk_common_cast(netdev);

    ovs_mutex_lock(&common->mutex);
    netdev_dpdk_get_config_common(common, args);
    ovs_mutex_unlock(&common->mutex);

    return 0;
}
