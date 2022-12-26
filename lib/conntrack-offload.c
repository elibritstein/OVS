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

#include "conntrack.h"
#include "conntrack-offload.h"
#include "conntrack-private.h"
#include "conntrack-tp.h"
#include "dp-packet.h"
#include "netdev-offload.h"
#include "ovs-rcu.h"
#include "timeval.h"

static bool ct_e2e_cache_enabled = false;

static uintptr_t
conntrack_offload_get_ctid_key(struct conn *conn)
{
    return (uintptr_t) (conn->master_conn ? conn->master_conn : conn);
}

static bool
conntrack_offload_fill_item_common(struct ct_flow_offload_item *item,
                                   struct conn *conn,
                                   int dir)
{
    item->ufid = conn->offloads.dir_info[dir].ufid;
    item->ct_match.odp_port = conn->offloads.dir_info[dir].port;
    item->dp = conn->offloads.dir_info[dir].dp;
    item->ctid_key = conntrack_offload_get_ctid_key(conn);
    item->ct_actions_set = false;
    item->actions = NULL;
    item->actions_size = 0;

    return dir == CT_DIR_REP
           ? !!(conn->offloads.flags & CT_OFFLOAD_REP)
           : !!(conn->offloads.flags & CT_OFFLOAD_INIT);
}

void
conntrack_offload_del_conn(struct conntrack *ct,
                           struct conn *conn)
    OVS_REQUIRES(conn->lock, ct->ct_lock)
{
    struct conntrack_offload_class *offload_class;
    struct ct_flow_offload_item item[CT_DIR_NUM];
    struct conn *conn_dir;
    long long int now = time_usec();
    void *dp;
    int dir;

    if (!netdev_is_flow_api_enabled()) {
        return;
    }

    offload_class = ovsrcu_get(struct conntrack_offload_class *,
                               &ct->offload_class);
    if (!offload_class || !offload_class->conn_del) {
        return;
    }

    if (!ct_e2e_cache_enabled &&
        (!conn->offloads.refcnt ||
         ovs_refcount_unref(conn->offloads.refcnt) > 1)) {
        return;
    }

    for (dir = 0; dir < CT_DIR_NUM; dir ++) {
        if (conn->nat_conn &&
            conn->nat_conn->offloads.dir_info[dir].dp) {
            conn_dir = conn->nat_conn;
        } else {
            conn_dir = conn;
        }
        if (!conntrack_offload_fill_item_common(&item[dir], conn_dir, dir)) {
            continue;
        }
        if (ct_e2e_cache_enabled) {
            dp = conn_dir->offloads.dir_info[dir].dp;
            offload_class->conn_e2e_del(&item[dir].ufid, dp, now);
        }
        /* Set connection's status to terminated to indicate that the offload
         * of the connection is deleted, but should still bypass tcp seq
         * checking.
         */
        conn_dir->offloads.flags |= CT_OFFLOAD_TERMINATED | CT_OFFLOAD_SKIP;
        conn_dir->offloads.flags &= ~CT_OFFLOAD_BOTH;
    }
    item[CT_DIR_INIT].timestamp = now;
    item[CT_DIR_INIT].refcnt = conn->offloads.refcnt;
    item[CT_DIR_REP].refcnt = NULL;
    offload_class->conn_del(item);
}

static void
conntrack_swap_conn_key(const struct conn_key *key,
                        struct conn_key *swapped)
{
    memcpy(swapped, key, sizeof *swapped);
    swapped->src = key->dst;
    swapped->dst = key->src;
}

static void
conntrack_offload_fill_item_add(struct ct_flow_offload_item *item,
                                struct conn *conn,
                                int dir,
                                long long int now)
{
    /* nat_conn has opposite directions. */
    bool reply = !!conn->master_conn ^ dir;

    if (reply) {
        item->ct_match.key = conn->rev_key;
        conntrack_swap_conn_key(&conn->key, &item->nat.key);
    } else {
        item->ct_match.key = conn->key;
        conntrack_swap_conn_key(&conn->rev_key, &item->nat.key);
    }

    item->nat.mod_flags = 0;
    if (memcmp(&item->nat.key.src.addr, &item->ct_match.key.src.addr,
               sizeof item->nat.key.src)) {
        item->nat.mod_flags |= NAT_ACTION_SRC;
    }
    if (item->nat.key.src.port != item->ct_match.key.src.port) {
        item->nat.mod_flags |= NAT_ACTION_SRC_PORT;
    }
    if (memcmp(&item->nat.key.dst.addr, &item->ct_match.key.dst.addr,
               sizeof item->nat.key.dst)) {
        item->nat.mod_flags |= NAT_ACTION_DST;
    }
    if (item->nat.key.dst.port != item->ct_match.key.dst.port) {
        item->nat.mod_flags |= NAT_ACTION_DST_PORT;
    }

    conntrack_offload_fill_item_common(item, conn, dir);
    item->ct_state = conn->offloads.dir_info[dir].pkt_ct_state;
    item->mark_key = conn->offloads.dir_info[dir].pkt_ct_mark;
    item->label_key = conn->offloads.dir_info[dir].pkt_ct_label;
    item->timestamp = now;
}

static void
conntrack_offload_prepare_add(struct conn *conn,
                              struct dp_packet *packet,
                              void *dp,
                              bool reply)
{
    int dir = ct_get_packet_dir(reply);

    conn->offloads.dir_info[dir].port = packet->md.orig_in_port;
    conn->offloads.dir_info[dir].dp = dp;
    conn->offloads.dir_info[dir].pkt_ct_state = packet->md.ct_state;
}

static inline void
e2e_cache_trace_add_ct(struct conntrack *ct,
                       struct dp_packet *p,
                       struct conn *conn,
                       bool reply,
                       long long int now)
{
    struct conntrack_offload_class *offload_class;
    uint32_t e2e_trace_size = p->e2e_trace_size;
    struct ct_flow_offload_item item;
    struct ct_dir_info *dir_info;
    uint8_t e2e_seen_pkts;
    int dir;

    offload_class = ovsrcu_get(struct conntrack_offload_class *,
                               &ct->offload_class);
    if (!offload_class || !offload_class->conn_get_ufid ||
        !offload_class->conn_e2e_add) {
        return;
    }

    if (OVS_UNLIKELY(e2e_trace_size >= E2E_CACHE_MAX_TRACE)) {
        p->e2e_trace_flags |= E2E_CACHE_TRACE_FLAG_OVERFLOW;
        return;
    }

    dir = ct_get_packet_dir(reply);
    if (conn->nat_conn &&
        conn->nat_conn->offloads.dir_info[dir].dp) {
        conn = conn->nat_conn;
    } else if (conn->master_conn &&
               conn->master_conn->offloads.dir_info[dir].dp) {
        conn = conn->master_conn;
    }
    conntrack_offload_fill_item_add(&item, conn, dir, now);
    item.ct_match.odp_port = p->md.in_port.odp_port;
    item.ct_match.orig_in_port = p->md.orig_in_port;

    dir_info = &conn->offloads.dir_info[dir];
    dir = ct_get_packet_dir(!reply);
    if (conn->nat_conn &&
        conn->nat_conn->offloads.dir_info[dir].dp) {
        conn = conn->nat_conn;
    } else if (conn->master_conn &&
               conn->master_conn->offloads.dir_info[dir].dp) {
        conn = conn->master_conn;
    }
    if (!dir_info->e2e_flow) {
        dir_info->e2e_flow = true;
        offload_class->conn_get_ufid(&dir_info->ufid);
        item.ufid = dir_info->ufid;
        offload_class->conn_e2e_add(&item);
    }

    /* Prevent sending E2E trace messages for every packet. Send only
     * when number of seen packets is equal to 2^x.
     */
    e2e_seen_pkts = dir_info->e2e_seen_pkts++;
    if ((e2e_seen_pkts & (e2e_seen_pkts - 1u)) != 0) {
        p->e2e_trace_flags |= E2E_CACHE_TRACE_FLAG_THROTTLED;
        return;
    }

    p->e2e_trace_ct_ufids |= 1 << e2e_trace_size;
    p->e2e_trace[e2e_trace_size] = dir_info->ufid;
    p->e2e_trace_size = e2e_trace_size + 1;

    if (!conn->offloads.dir_info[dir].e2e_flow) {
        p->e2e_trace_flags |= E2E_CACHE_TRACE_FLAG_ABORT;
        return;
    }
    e2e_trace_size++;
    p->e2e_trace_ct_ufids |= 1 << e2e_trace_size;
    p->e2e_trace[e2e_trace_size] = conn->offloads.dir_info[dir].ufid;
    p->e2e_trace_size = e2e_trace_size + 1;
}

static void
conntrack_offload_add_conn(struct conntrack *ct,
                           struct dp_packet *packet,
                           struct conn *conn,
                           bool reply, long long now_us)
{
    struct conntrack_offload_class *offload_class;
    struct ct_flow_offload_item item[CT_DIR_NUM];
    uint8_t flags;
    int dir;

    /* CT doesn't handle alg */
    offload_class = ovsrcu_get(struct conntrack_offload_class *,
                               &ct->offload_class);
    if (conn->alg || conn->alg_related || !offload_class ||
        !offload_class->conn_add || !offload_class->conn_get_ufid ||
        !offload_class->queue_full) {
        conn->offloads.flags |= CT_OFFLOAD_SKIP;
        return;
    }

    if (offload_class->queue_full()) {
        /* Try again later. */
        return;
    }

    if ((reply && !(conn->offloads.flags & CT_OFFLOAD_REP)) ||
        (!reply && !(conn->offloads.flags & CT_OFFLOAD_INIT))) {
        conntrack_offload_prepare_add(conn, packet, ct->dp, reply);
        conn->offloads.flags |= reply ? CT_OFFLOAD_REP : CT_OFFLOAD_INIT;
        if (conn->master_conn) {
            conn->master_conn->offloads.flags |= reply
                ? CT_OFFLOAD_REP : CT_OFFLOAD_INIT;
        }
    }

    flags = conn->offloads.flags;
    if (conn->nat_conn) {
        flags |= conn->nat_conn->offloads.flags;
    } else if (conn->master_conn) {
        flags |= conn->master_conn->offloads.flags;
    }
    if ((flags & CT_OFFLOAD_BOTH) == CT_OFFLOAD_BOTH) {
        struct ovs_refcount *refcnt;

        for (dir = 0; dir < CT_DIR_NUM; dir ++) {
            if (conn->nat_conn &&
                conn->nat_conn->offloads.dir_info[dir].dp) {
                conn = conn->nat_conn;
            } else if (conn->master_conn &&
                       conn->master_conn->offloads.dir_info[dir].dp) {
                conn = conn->master_conn;
            }
            conntrack_offload_fill_item_add(&item[dir], conn, dir, now_us);
            offload_class->conn_get_ufid(&conn->offloads.dir_info[dir].ufid);
            item[dir].ufid = conn->offloads.dir_info[dir].ufid;
        }
        refcnt = xmalloc(sizeof *refcnt);
        ovs_refcount_init(refcnt);
        ovs_refcount_ref(refcnt);
        item[CT_DIR_INIT].refcnt = refcnt;
        item[CT_DIR_REP].refcnt = NULL;
        offload_class->conn_add(item);
        conn->offloads.flags |= CT_OFFLOAD_SKIP;
        if (conn->nat_conn) {
            conn->nat_conn->offloads.flags |= CT_OFFLOAD_SKIP;
            conn->offloads.refcnt = refcnt;
        } else if (conn->master_conn) {
            conn->master_conn->offloads.flags |= CT_OFFLOAD_SKIP;
            conn->master_conn->offloads.refcnt = refcnt;
        } else {
            conn->offloads.refcnt = refcnt;
        }
    }
}

void
process_one_ct_offload(struct conntrack *ct,
                       struct dp_packet *packet,
                       struct conn *conn,
                       bool reply,
                       long long now_us)
{
    if (!conn || (conn->key.nw_proto != IPPROTO_UDP &&
                  conn->key.nw_proto != IPPROTO_TCP) ||
        !(packet->md.ct_state & CS_ESTABLISHED)) {
        return;
    }

    if (netdev_is_flow_api_enabled() &&
        !(conn->offloads.flags & CT_OFFLOAD_SKIP)) {
        int dir = reply ? CT_DIR_REP : CT_DIR_INIT;
        struct conn *actual_conn = conn;

        if (conn->nat_conn &&
            conn->nat_conn->offloads.dir_info[dir].dp) {
            actual_conn = conn->nat_conn;
        } else if (conn->master_conn &&
                   conn->master_conn->offloads.dir_info[dir].dp) {
            actual_conn = conn->master_conn;
        }

        actual_conn->offloads.dir_info[dir].pkt_ct_mark = packet->md.ct_mark;
        actual_conn->offloads.dir_info[dir].pkt_ct_label = packet->md.ct_label;

        conntrack_offload_add_conn(ct, packet, conn, reply, now_us);
    }
    if (ct_e2e_cache_enabled) {
        e2e_cache_trace_add_ct(ct, packet, conn, reply, now_us);
    }
}

int
conn_hw_update(struct conntrack *ct,
               struct conntrack_offload_class *offload_class,
               struct conn *conn,
               enum ct_timeout *ptm,
               long long now)
{
    struct ct_flow_offload_item item;
    enum ct_timeout tm = *ptm;
    bool updated = false;
    int ret = 0;
    int dir;

    for (dir = 0; dir < CT_DIR_NUM; dir++) {
        if (!updated &&
            conn->offloads.dir_info[dir].dp &&
            conntrack_offload_fill_item_common(&item, conn, dir)) {
            ret = offload_class->conn_active(&item, now,
                                             conn->prev_query);
            if (!ret) {
                conn_lock(conn);
                conn_update_expiration(ct, conn, tm, now);
                conn_unlock(conn);
                updated = true;
                break;
            }
        }
        if (!updated && conn->nat_conn &&
            conn->nat_conn->offloads.dir_info[dir].dp &&
            conntrack_offload_fill_item_common(&item, conn->nat_conn,
                                               dir)) {
            ret = offload_class->conn_active(&item, now,
                                             conn->prev_query);
            if (!ret) {
                conn_lock(conn);
                conn_update_expiration(ct, conn, tm, now);
                conn_unlock(conn);
                updated = true;
                break;
            }
        }
    }
    atomic_flag_test_and_set(&conn->exp.reschedule);
    conn->prev_query = now;
    return ret;
}

void
conntrack_set_offload_class(struct conntrack *ct,
                            struct conntrack_offload_class *cls)
{
    ovsrcu_set(&ct->offload_class, cls);
    ct_e2e_cache_enabled = netdev_is_e2e_cache_enabled();
}
