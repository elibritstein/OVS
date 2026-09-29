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

#include <errno.h>
#include <stdarg.h>

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
#include "sset.h"
#include "unaligned.h"
#include "userspace-tso.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(netdev_dpdk_common);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static bool per_port_memory = false; /* Status of per port memory support */

/* MAX_NB_MBUF can be divided by 2 many times, until MIN_NB_MBUF */
BUILD_ASSERT_DECL(MAX_NB_MBUF % ROUND_DOWN_POW2(MAX_NB_MBUF / MIN_NB_MBUF)
                  == 0);

/* The smallest possible NB_MBUF that we're going to try should be a multiple
 * of MP_CACHE_SZ. This is advised by DPDK documentation. */
BUILD_ASSERT_DECL((MAX_NB_MBUF / ROUND_DOWN_POW2(MAX_NB_MBUF / MIN_NB_MBUF))
                  % MP_CACHE_SZ == 0);

struct ovs_mutex dpdk_mp_mutex
    OVS_ACQ_AFTER(dpdk_eth_mutex, dpdk_vhost_mutex)
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

/* Quality of Service */

struct dpdk_qos_conf {
    const struct dpdk_qos_ops *ops;
    rte_spinlock_t lock;
};

/* QoS queue information used by the netdev queue dump functions. */
struct dpdk_qos_queue_state {
    uint32_t *queues;
    size_t cur_queue;
    size_t n_queues;
};

struct dpdk_qos_ingress_policer {
    struct rte_meter_srtcm_params app_srtcm_params;
    struct rte_meter_srtcm in_policer;
    struct rte_meter_srtcm_profile in_prof;
    rte_spinlock_t policer_lock;
};

/* A particular implementation of dpdk QoS operations.
 *
 * The functions below return 0 if successful or a positive errno value on
 * failure, except where otherwise noted. All of them must be provided, except
 * where otherwise noted.
 */
struct dpdk_qos_ops {

    /* Name of the QoS type */
    const char *qos_name;

    /* Called to construct a qos_conf object. The implementation should make
     * the appropriate calls to configure QoS according to 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     *
     * This function must return 0 if and only if it sets '*conf' to an
     * initialized 'struct dpdk_qos_conf'.
     *
     * For all QoS implementations it should always be non-null.
     */
    int (*qos_construct)(const struct smap *details,
                         struct dpdk_qos_conf **conf);

    /* Destroys the data structures allocated by the implementation as part of
     * 'qos_conf'.
     *
     * For all QoS implementations it should always be non-null.
     */
    void (*qos_destruct)(struct dpdk_qos_conf *conf);

    /* Retrieves details of 'conf' configuration into 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     */
    int (*qos_get)(const struct dpdk_qos_conf *conf, struct smap *details);

    /* Returns true if 'conf' is already configured according to 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     *
     * For all QoS implementations it should always be non-null.
     */
    bool (*qos_is_equal)(const struct dpdk_qos_conf *conf,
                         const struct smap *details);

    /* Modify an array of rte_mbufs. The modification is specific to
     * each qos implementation.
     *
     * The function should take and array of mbufs and an int representing
     * the current number of mbufs present in the array.
     *
     * After the function has performed a qos modification to the array of
     * mbufs it returns an int representing the number of mbufs now present in
     * the array. This value is can then be passed to the port send function
     * along with the modified array for transmission.
     *
     * For all QoS implementations it should always be non-null.
     */
    int (*qos_run)(struct dpdk_qos_conf *qos_conf, struct rte_mbuf **pkts,
                   int pkt_cnt, bool should_steal);

    /* Called to construct a QoS Queue. The implementation should make
     * the appropriate calls to configure QoS Queue according to 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     *
     * This function must return 0 if and only if it constructs
     * QoS queue successfully.
     */
    int (*qos_queue_construct)(const struct smap *details,
                               uint32_t queue_id,
                               struct dpdk_qos_conf *conf);

    /* Destroys the QoS Queue. */
    void (*qos_queue_destruct)(struct dpdk_qos_conf *conf, uint32_t queue_id);

    /* Retrieves details of QoS Queue configuration into 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     */
    int (*qos_queue_get)(struct smap *details, uint32_t queue_id,
                         const struct dpdk_qos_conf *conf);

    /* Retrieves statistics of QoS Queue configuration into 'stats'. */
    int (*qos_queue_get_stats)(const struct dpdk_qos_conf *conf,
                               uint32_t queue_id,
                               struct netdev_queue_stats *stats);

    /* Setup the 'dpdk_qos_queue_state' structure used by the dpdk queue
     * dump functions.
     */
    int (*qos_queue_dump_state_init)(const struct dpdk_qos_conf *conf,
                                     struct dpdk_qos_queue_state *state);
};

/* dpdk_qos_ops for each type of user space QoS implementation. */
static const struct dpdk_qos_ops egress_policer_ops;
static const struct dpdk_qos_ops trtcm_policer_ops;

/*
 * Array of dpdk_qos_ops, contains pointer to all supported QoS
 * operations.
 */
static const struct dpdk_qos_ops *const qos_confs[] = {
    &egress_policer_ops,
    &trtcm_policer_ops,
    NULL
};

void
netdev_dpdk_common_vlog_rl(enum vlog_level level, const char *format, ...)
{
    va_list args;

    if (vlog_should_drop(&this_module, level, &rl)) {
        return;
    }

    va_start(args, format);
    vlog_valist(&this_module, level, format, args);
    va_end(args);
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

static bool
srtcm_policer_pkt_handle(struct rte_meter_srtcm *meter,
                         struct rte_meter_srtcm_profile *profile,
                         struct rte_mbuf *pkt, uint64_t time)
{
    uint32_t pkt_len = rte_pktmbuf_pkt_len(pkt) - sizeof(struct rte_ether_hdr);

    return rte_meter_srtcm_color_blind_check(meter, profile, time, pkt_len) ==
                                             RTE_COLOR_GREEN;
}

static int
srtcm_policer_run_single_packet(struct rte_meter_srtcm *meter,
                                struct rte_meter_srtcm_profile *profile,
                                struct rte_mbuf **pkts, int pkt_cnt,
                                bool should_steal)
{
    int i = 0;
    int cnt = 0;
    struct rte_mbuf *pkt = NULL;
    uint64_t current_time = rte_rdtsc();

    for (i = 0; i < pkt_cnt; i++) {
        pkt = pkts[i];
        /* Handle current packet */
        if (srtcm_policer_pkt_handle(meter, profile,
                                     pkt, current_time)) {
            if (cnt != i) {
                pkts[cnt] = pkt;
            }
            cnt++;
        } else {
            if (should_steal) {
                rte_pktmbuf_free(pkt);
            }
        }
    }

    return cnt;
}

int
dpdk_qos_ingress_policer_run(struct dpdk_qos_ingress_policer *policer,
                             struct rte_mbuf **pkts, int pkt_cnt,
                             bool should_steal)
{
    int cnt = 0;

    rte_spinlock_lock(&policer->policer_lock);
    cnt = srtcm_policer_run_single_packet(&policer->in_policer,
                                          &policer->in_prof,
                                          pkts, pkt_cnt, should_steal);
    rte_spinlock_unlock(&policer->policer_lock);

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
    ovs_assert(shinfo != NULL);

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

    /* Initialize shinfo. */
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

struct rte_mbuf *
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

struct dp_packet *
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
dpdk_copy_batch_to_mbuf(struct netdev_dpdk_common *common,
                        struct dp_packet_batch *batch)
{
    size_t i, size = dp_packet_batch_size(batch);
    struct dp_packet *packet;

    DP_PACKET_BATCH_REFILL_FOR_EACH (i, size, packet, batch) {
        if (OVS_UNLIKELY(packet->source == DPBUF_DPDK)) {
            dp_packet_batch_add(batch, packet);
        } else {
            struct dp_packet *pktcopy;

            pktcopy = dpdk_copy_dp_packet_to_mbuf(common->dpdk_mp->mp, packet);
            if (pktcopy) {
                dp_packet_batch_add(batch, pktcopy);
            }

            dp_packet_delete(packet);
        }
    }

    return dp_packet_batch_size(batch);
}

struct dpdk_qos_ingress_policer *
dpdk_qos_ingress_policer_construct(uint32_t rate, uint32_t burst)
{
    struct dpdk_qos_ingress_policer *policer = NULL;
    uint64_t rate_bytes;
    uint64_t burst_bytes;
    int err = 0;

    policer = xmalloc(sizeof *policer);
    rte_spinlock_init(&policer->policer_lock);

    /* rte_meter requires bytes so convert kbits rate and burst to bytes. */
    rate_bytes = rate * 1000ULL / 8;
    burst_bytes = burst * 1000ULL / 8;

    policer->app_srtcm_params.cir = rate_bytes;
    policer->app_srtcm_params.cbs = burst_bytes;
    policer->app_srtcm_params.ebs = 0;
    err = rte_meter_srtcm_profile_config(&policer->in_prof,
                                         &policer->app_srtcm_params);
    if (!err) {
        err = rte_meter_srtcm_config(&policer->in_policer,
                                     &policer->in_prof);
    }
    if (err) {
        VLOG_ERR("Could not create rte meter for ingress policer");
        free(policer);
        return NULL;
    }

    return policer;
}

void
dpdk_qos_ingress_policer_destruct(struct dpdk_qos_ingress_policer *policer)
{
    free(policer);
}

/*
 * Initialize QoS configuration operations.
 */
static void
qos_conf_init(struct dpdk_qos_conf *conf, const struct dpdk_qos_ops *ops)
{
    conf->ops = ops;
    rte_spinlock_init(&conf->lock);
}

static const struct dpdk_qos_ops *
qos_lookup_name(const char *name)
{
    const struct dpdk_qos_ops *const *opsp;

    for (opsp = qos_confs; *opsp != NULL; opsp++) {
        const struct dpdk_qos_ops *ops = *opsp;
        if (!strcmp(name, ops->qos_name)) {
            return ops;
        }
    }
    return NULL;
}

int
dpdk_qos_run(struct dpdk_qos_conf *qos_conf, struct rte_mbuf **pkts,
             int pkt_cnt, bool should_steal)
{
    int cnt;

    rte_spinlock_lock(&qos_conf->lock);
    cnt = qos_conf->ops->qos_run(qos_conf, pkts, pkt_cnt, should_steal);
    rte_spinlock_unlock(&qos_conf->lock);

    return cnt;
}

/* egress-policer details */

struct egress_policer {
    struct dpdk_qos_conf qos_conf;
    struct rte_meter_srtcm_params app_srtcm_params;
    struct rte_meter_srtcm egress_meter;
    struct rte_meter_srtcm_profile egress_prof;
};

static void
egress_policer_details_to_param(const struct smap *details,
                                struct rte_meter_srtcm_params *params)
{
    memset(params, 0, sizeof *params);
    params->cir = smap_get_ullong(details, "cir", 0);
    params->cbs = smap_get_ullong(details, "cbs", 0);
    params->ebs = 0;
}

static int
egress_policer_qos_construct(const struct smap *details,
                             struct dpdk_qos_conf **conf)
{
    struct egress_policer *policer;
    int err = 0;

    policer = xmalloc(sizeof *policer);
    qos_conf_init(&policer->qos_conf, &egress_policer_ops);
    egress_policer_details_to_param(details, &policer->app_srtcm_params);
    err = rte_meter_srtcm_profile_config(&policer->egress_prof,
                                         &policer->app_srtcm_params);
    if (!err) {
        err = rte_meter_srtcm_config(&policer->egress_meter,
                                     &policer->egress_prof);
    }

    if (!err) {
        *conf = &policer->qos_conf;
    } else {
        VLOG_ERR("Could not create rte meter for egress policer");
        free(policer);
        *conf = NULL;
        err = -err;
    }

    return err;
}

static void
egress_policer_qos_destruct(struct dpdk_qos_conf *conf)
{
    struct egress_policer *policer = CONTAINER_OF(conf, struct egress_policer,
                                                  qos_conf);
    free(policer);
}

static int
egress_policer_qos_get(const struct dpdk_qos_conf *conf, struct smap *details)
{
    struct egress_policer *policer =
        CONTAINER_OF(conf, struct egress_policer, qos_conf);

    smap_add_format(details, "cir", "%"PRIu64, policer->app_srtcm_params.cir);
    smap_add_format(details, "cbs", "%"PRIu64, policer->app_srtcm_params.cbs);

    return 0;
}

static bool
egress_policer_qos_is_equal(const struct dpdk_qos_conf *conf,
                            const struct smap *details)
{
    struct egress_policer *policer =
        CONTAINER_OF(conf, struct egress_policer, qos_conf);
    struct rte_meter_srtcm_params params;

    egress_policer_details_to_param(details, &params);

    return !memcmp(&params, &policer->app_srtcm_params, sizeof params);
}

static int
egress_policer_run(struct dpdk_qos_conf *conf, struct rte_mbuf **pkts,
                   int pkt_cnt, bool should_steal)
{
    int cnt = 0;
    struct egress_policer *policer =
        CONTAINER_OF(conf, struct egress_policer, qos_conf);

    cnt = srtcm_policer_run_single_packet(&policer->egress_meter,
                                          &policer->egress_prof, pkts,
                                          pkt_cnt, should_steal);

    return cnt;
}

static const struct dpdk_qos_ops egress_policer_ops = {
    .qos_name = "egress-policer",    /* qos_name */
    .qos_construct = egress_policer_qos_construct,
    .qos_destruct = egress_policer_qos_destruct,
    .qos_get = egress_policer_qos_get,
    .qos_is_equal = egress_policer_qos_is_equal,
    .qos_run = egress_policer_run
};

/* trtcm-policer details */

struct trtcm_policer {
    struct dpdk_qos_conf qos_conf;
    struct rte_meter_trtcm_rfc4115_params meter_params;
    struct rte_meter_trtcm_rfc4115_profile meter_profile;
    struct rte_meter_trtcm_rfc4115 meter;
    struct netdev_queue_stats stats;
    struct hmap queues;
};

struct trtcm_policer_queue {
    struct hmap_node hmap_node;
    uint32_t queue_id;
    struct rte_meter_trtcm_rfc4115_params meter_params;
    struct rte_meter_trtcm_rfc4115_profile meter_profile;
    struct rte_meter_trtcm_rfc4115 meter;
    struct netdev_queue_stats stats;
};

static void
trtcm_policer_details_to_param(const struct smap *details,
                               struct rte_meter_trtcm_rfc4115_params *params)
{
    memset(params, 0, sizeof *params);
    params->cir = smap_get_ullong(details, "cir", 0);
    params->eir = smap_get_ullong(details, "eir", 0);
    params->cbs = smap_get_ullong(details, "cbs", 0);
    params->ebs = smap_get_ullong(details, "ebs", 0);
}

static void
trtcm_policer_param_to_detail(
    const struct rte_meter_trtcm_rfc4115_params *params,
    struct smap *details)
{
    smap_add_format(details, "cir", "%"PRIu64, params->cir);
    smap_add_format(details, "eir", "%"PRIu64, params->eir);
    smap_add_format(details, "cbs", "%"PRIu64, params->cbs);
    smap_add_format(details, "ebs", "%"PRIu64, params->ebs);
}


static int
trtcm_policer_qos_construct(const struct smap *details,
                            struct dpdk_qos_conf **conf)
{
    struct trtcm_policer *policer;
    int err = 0;

    policer = xmalloc(sizeof *policer);
    qos_conf_init(&policer->qos_conf, &trtcm_policer_ops);
    trtcm_policer_details_to_param(details, &policer->meter_params);
    err = rte_meter_trtcm_rfc4115_profile_config(&policer->meter_profile,
                                                 &policer->meter_params);
    if (!err) {
        err = rte_meter_trtcm_rfc4115_config(&policer->meter,
                                             &policer->meter_profile);
    }

    if (!err) {
        *conf = &policer->qos_conf;
        memset(&policer->stats, 0, sizeof policer->stats);
        hmap_init(&policer->queues);
    } else {
        free(policer);
        *conf = NULL;
        err = -err;
    }

    return err;
}

static void
trtcm_policer_qos_destruct(struct dpdk_qos_conf *conf)
{
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    HMAP_FOR_EACH_SAFE (queue, hmap_node, &policer->queues) {
        hmap_remove(&policer->queues, &queue->hmap_node);
        free(queue);
    }
    hmap_destroy(&policer->queues);
    free(policer);
}

static int
trtcm_policer_qos_get(const struct dpdk_qos_conf *conf, struct smap *details)
{
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    trtcm_policer_param_to_detail(&policer->meter_params, details);
    return 0;
}

static bool
trtcm_policer_qos_is_equal(const struct dpdk_qos_conf *conf,
                           const struct smap *details)
{
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);
    struct rte_meter_trtcm_rfc4115_params params;

    trtcm_policer_details_to_param(details, &params);

    return !memcmp(&params, &policer->meter_params, sizeof params);
}

static struct trtcm_policer_queue *
trtcm_policer_qos_find_queue(struct trtcm_policer *policer, uint32_t queue_id)
{
    struct trtcm_policer_queue *queue;
    HMAP_FOR_EACH_WITH_HASH (queue, hmap_node, hash_2words(queue_id, 0),
                             &policer->queues) {
        if (queue->queue_id == queue_id) {
            return queue;
        }
    }
    return NULL;
}

static bool
trtcm_policer_run_single_packet(struct trtcm_policer *policer,
                                struct rte_mbuf *pkt, uint64_t time)
{
    enum rte_color pkt_color;
    struct trtcm_policer_queue *queue;
    uint32_t pkt_len = rte_pktmbuf_pkt_len(pkt) - sizeof(struct rte_ether_hdr);
    struct dp_packet *dpkt = CONTAINER_OF(pkt, struct dp_packet, mbuf);

    queue = trtcm_policer_qos_find_queue(policer, dpkt->md.skb_priority);
    if (!queue) {
        /* If no queue is found, use the default queue, which MUST exist. */
        queue = trtcm_policer_qos_find_queue(policer, 0);
        if (!queue) {
            return false;
        }
    }

    pkt_color =
        rte_meter_trtcm_rfc4115_color_blind_check(&queue->meter,
                                                  &queue->meter_profile,
                                                  time, pkt_len);

    if (pkt_color == RTE_COLOR_RED) {
        queue->stats.tx_errors++;
    } else {
        queue->stats.tx_bytes += pkt_len;
        queue->stats.tx_packets++;
    }

    pkt_color =
        rte_meter_trtcm_rfc4115_color_aware_check(&policer->meter,
                                                  &policer->meter_profile,
                                                  time, pkt_len, pkt_color);

    if (pkt_color == RTE_COLOR_RED) {
        policer->stats.tx_errors++;
        return false;
    }

    policer->stats.tx_bytes += pkt_len;
    policer->stats.tx_packets++;
    return true;
}

static int
trtcm_policer_run(struct dpdk_qos_conf *conf, struct rte_mbuf **pkts,
                  int pkt_cnt, bool should_steal)
{
    int i = 0;
    int cnt = 0;
    struct rte_mbuf *pkt = NULL;
    uint64_t current_time = rte_rdtsc();

    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    for (i = 0; i < pkt_cnt; i++) {
        pkt = pkts[i];

        if (trtcm_policer_run_single_packet(policer, pkt, current_time)) {
            if (cnt != i) {
                pkts[cnt] = pkt;
            }
            cnt++;
        } else {
            if (should_steal) {
                rte_pktmbuf_free(pkt);
            }
        }
    }
    return cnt;
}

static int
trtcm_policer_qos_queue_construct(const struct smap *details,
                                  uint32_t queue_id,
                                  struct dpdk_qos_conf *conf)
{
    int err = 0;
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    queue = trtcm_policer_qos_find_queue(policer, queue_id);
    if (!queue) {
        queue = xmalloc(sizeof *queue);
        queue->queue_id = queue_id;
        memset(&queue->stats, 0, sizeof queue->stats);
        queue->stats.created = time_msec();
        hmap_insert(&policer->queues, &queue->hmap_node,
                    hash_2words(queue_id, 0));
    }
    if (queue_id == 0 && smap_is_empty(details)) {
        /* No default queue configured, use port values */
        memcpy(&queue->meter_params, &policer->meter_params,
               sizeof queue->meter_params);
    } else {
        trtcm_policer_details_to_param(details, &queue->meter_params);
    }

    err = rte_meter_trtcm_rfc4115_profile_config(&queue->meter_profile,
                                                 &queue->meter_params);

    if (!err) {
        err = rte_meter_trtcm_rfc4115_config(&queue->meter,
                                             &queue->meter_profile);
    }
    if (err) {
        hmap_remove(&policer->queues, &queue->hmap_node);
        free(queue);
        err = -err;
    }
    return err;
}

static void
trtcm_policer_qos_queue_destruct(struct dpdk_qos_conf *conf, uint32_t queue_id)
{
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    queue = trtcm_policer_qos_find_queue(policer, queue_id);
    if (queue) {
        hmap_remove(&policer->queues, &queue->hmap_node);
        free(queue);
    }
}

static int
trtcm_policer_qos_queue_get(struct smap *details, uint32_t queue_id,
                            const struct dpdk_qos_conf *conf)
{
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    queue = trtcm_policer_qos_find_queue(policer, queue_id);
    if (!queue) {
        return EINVAL;
    }

    trtcm_policer_param_to_detail(&queue->meter_params, details);
    return 0;
}

static int
trtcm_policer_qos_queue_get_stats(const struct dpdk_qos_conf *conf,
                                  uint32_t queue_id,
                                  struct netdev_queue_stats *stats)
{
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    queue = trtcm_policer_qos_find_queue(policer, queue_id);
    if (!queue) {
        return EINVAL;
    }
    memcpy(stats, &queue->stats, sizeof *stats);
    return 0;
}

static int
trtcm_policer_qos_queue_dump_state_init(const struct dpdk_qos_conf *conf,
                                        struct dpdk_qos_queue_state *state)
{
    uint32_t i = 0;
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    state->n_queues = hmap_count(&policer->queues);
    state->cur_queue = 0;
    state->queues = xmalloc(state->n_queues * sizeof *state->queues);

    HMAP_FOR_EACH (queue, hmap_node, &policer->queues) {
        state->queues[i++] = queue->queue_id;
    }
    return 0;
}

static const struct dpdk_qos_ops trtcm_policer_ops = {
    .qos_name = "trtcm-policer",
    .qos_construct = trtcm_policer_qos_construct,
    .qos_destruct = trtcm_policer_qos_destruct,
    .qos_get = trtcm_policer_qos_get,
    .qos_is_equal = trtcm_policer_qos_is_equal,
    .qos_run = trtcm_policer_run,
    .qos_queue_construct = trtcm_policer_qos_queue_construct,
    .qos_queue_destruct = trtcm_policer_qos_queue_destruct,
    .qos_queue_get = trtcm_policer_qos_queue_get,
    .qos_queue_get_stats = trtcm_policer_qos_queue_get_stats,
    .qos_queue_dump_state_init = trtcm_policer_qos_queue_dump_state_init
};

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

int
netdev_dpdk_common_set_policing(struct netdev_dpdk_common *common,
                                uint32_t policer_rate, uint32_t policer_burst)
{
    struct dpdk_qos_ingress_policer *policer;

    /* Force to 0 if no rate specified,
     * default to 8000 kbits if burst is 0,
     * else stick with user-specified value.
     */
    policer_burst = (!policer_rate ? 0
                     : !policer_burst ? 8000
                     : policer_burst);

    policer = ovsrcu_get_protected(struct dpdk_qos_ingress_policer *,
                                   &common->ingress_policer);

    if (common->policer_rate == policer_rate &&
        common->policer_burst == policer_burst) {
        /* Assume that settings haven't changed since we last set them. */
        return 0;
    }

    /* Destroy any existing ingress policer for the device if one exists */
    if (policer) {
        ovsrcu_postpone__((void (*)(void *)) dpdk_qos_ingress_policer_destruct,
                          policer);
    }

    if (policer_rate != 0) {
        policer = dpdk_qos_ingress_policer_construct(policer_rate,
                                                     policer_burst);
    } else {
        policer = NULL;
    }
    ovsrcu_set(&common->ingress_policer, policer);
    common->policer_rate = policer_rate;
    common->policer_burst = policer_burst;

    return 0;
}

/* QoS Functions */

int
netdev_dpdk_common_get_qos_types(const struct netdev *netdev OVS_UNUSED,
                                 struct sset *types)
{
    const struct dpdk_qos_ops *const *opsp;

    for (opsp = qos_confs; *opsp != NULL; opsp++) {
        const struct dpdk_qos_ops *ops = *opsp;
        if (ops->qos_construct && ops->qos_name[0] != '\0') {
            sset_add(types, ops->qos_name);
        }
    }
    return 0;
}

int
netdev_dpdk_common_get_qos(const struct netdev_dpdk_common *common,
                           const char **typep, struct smap *details)
{
    struct dpdk_qos_conf *qos_conf;
    int error = 0;

    qos_conf = ovsrcu_get_protected(struct dpdk_qos_conf *, &common->qos_conf);
    if (qos_conf) {
        *typep = qos_conf->ops->qos_name;
        error = (qos_conf->ops->qos_get
                 ? qos_conf->ops->qos_get(qos_conf, details) : 0);
    } else {
        /* No QoS configuration set, return an empty string */
        *typep = "";
    }

    return error;
}

int
netdev_dpdk_common_set_qos(struct netdev_dpdk_common *common,
                           const char *type, const struct smap *details)
{
    struct netdev *netdev = &common->up;
    const struct dpdk_qos_ops *new_ops = NULL;
    struct dpdk_qos_conf *qos_conf, *new_qos_conf = NULL;
    int error = 0;

    qos_conf = ovsrcu_get_protected(struct dpdk_qos_conf *, &common->qos_conf);

    new_ops = qos_lookup_name(type);

    if (!new_ops || !new_ops->qos_construct) {
        new_qos_conf = NULL;
        if (type && type[0]) {
            error = EOPNOTSUPP;
        }
    } else if (qos_conf && qos_conf->ops == new_ops
               && qos_conf->ops->qos_is_equal(qos_conf, details)) {
        new_qos_conf = qos_conf;
    } else {
        error = new_ops->qos_construct(details, &new_qos_conf);
    }

    if (error) {
        VLOG_ERR("Failed to set QoS type %s on port %s: %s",
                 type, netdev->name, rte_strerror(error));
    }

    if (new_qos_conf != qos_conf) {
        ovsrcu_set(&common->qos_conf, new_qos_conf);
        if (qos_conf) {
            ovsrcu_postpone(qos_conf->ops->qos_destruct, qos_conf);
        }
    }

    return error;
}

int
netdev_dpdk_common_get_queue(const struct netdev_dpdk_common *common,
                             uint32_t queue_id, struct smap *details)
{
    struct dpdk_qos_conf *qos_conf;
    int error = 0;

    qos_conf = ovsrcu_get_protected(struct dpdk_qos_conf *, &common->qos_conf);
    if (!qos_conf || !qos_conf->ops || !qos_conf->ops->qos_queue_get) {
        error = EOPNOTSUPP;
    } else {
        error = qos_conf->ops->qos_queue_get(details, queue_id, qos_conf);
    }

    return error;
}

int
netdev_dpdk_common_set_queue(struct netdev_dpdk_common *common,
                             uint32_t queue_id, const struct smap *details)
{
    struct netdev *netdev = &common->up;
    struct dpdk_qos_conf *qos_conf;
    int error = 0;

    qos_conf = ovsrcu_get_protected(struct dpdk_qos_conf *, &common->qos_conf);
    if (!qos_conf || !qos_conf->ops || !qos_conf->ops->qos_queue_construct) {
        error = EOPNOTSUPP;
    } else {
        error = qos_conf->ops->qos_queue_construct(details, queue_id,
                                                   qos_conf);
    }

    if (error && error != EOPNOTSUPP) {
        VLOG_ERR("Failed to set QoS queue %d on port %s: %s",
                 queue_id, netdev->name, rte_strerror(error));
    }

    return error;
}

int
netdev_dpdk_common_delete_queue(struct netdev_dpdk_common *common,
                                uint32_t queue_id)
{
    struct dpdk_qos_conf *qos_conf;
    int error = 0;

    qos_conf = ovsrcu_get_protected(struct dpdk_qos_conf *, &common->qos_conf);
    if (qos_conf && qos_conf->ops && qos_conf->ops->qos_queue_destruct) {
        qos_conf->ops->qos_queue_destruct(qos_conf, queue_id);
    } else {
        error = EOPNOTSUPP;
    }

    return error;
}

int
netdev_dpdk_common_get_queue_stats(const struct netdev_dpdk_common *common,
                                   uint32_t queue_id,
                                   struct netdev_queue_stats *stats)
{
    struct dpdk_qos_conf *qos_conf;
    int error = 0;

    qos_conf = ovsrcu_get_protected(struct dpdk_qos_conf *, &common->qos_conf);
    if (qos_conf && qos_conf->ops && qos_conf->ops->qos_queue_get_stats) {
        qos_conf->ops->qos_queue_get_stats(qos_conf, queue_id, stats);
    } else {
        error = EOPNOTSUPP;
    }

    return error;
}

int
netdev_dpdk_common_queue_dump_start(const struct netdev_dpdk_common *common,
                                    void **statep)
{
    struct dpdk_qos_conf *qos_conf;
    int error = 0;

    qos_conf = ovsrcu_get_protected(struct dpdk_qos_conf *, &common->qos_conf);
    if (qos_conf && qos_conf->ops
        && qos_conf->ops->qos_queue_dump_state_init) {
        struct dpdk_qos_queue_state *state;

        *statep = state = xmalloc(sizeof *state);
        error = qos_conf->ops->qos_queue_dump_state_init(qos_conf, state);
    } else {
        error = EOPNOTSUPP;
    }

    return error;
}

int
netdev_dpdk_common_queue_dump_next(const struct netdev_dpdk_common *common,
                                   void *state_, uint32_t *queue_idp,
                                   struct smap *details)
{
    struct dpdk_qos_conf *qos_conf;
    struct dpdk_qos_queue_state *state = state_;
    int error = EOF;

    qos_conf = ovsrcu_get_protected(struct dpdk_qos_conf *, &common->qos_conf);
    if (qos_conf) {
        while (state->cur_queue < state->n_queues) {
            uint32_t queue_id = state->queues[state->cur_queue++];

            if (qos_conf->ops && qos_conf->ops->qos_queue_get) {
                *queue_idp = queue_id;
                error = qos_conf->ops->qos_queue_get(details, queue_id,
                                                     qos_conf);
                break;
            }
        }
    }

    return error;
}

int
netdev_dpdk_common_queue_dump_done(const struct netdev *netdev OVS_UNUSED,
                                   void *state_)
{
    struct dpdk_qos_queue_state *state = state_;

    free(state->queues);
    free(state);
    return 0;
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
