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

#include "conntrack.c"

static void
ctd_process_one(struct dp_packet *pkt)
{
    const struct nat_action_info_t *nat_action_info;
    const struct ovs_key_ct_labels *setlabel;
    struct conn_lookup_ctx *ctx;
    const uint32_t *setmark;
    struct conntrack *ct;
    const char *helper;
    struct ct_exec *e;
    ovs_be16 tp_src;
    ovs_be16 tp_dst;
    uint32_t tp_id;
    uint16_t zone;
    long long now;
    bool commit;
    bool force;

    e = &pkt->ct_exec;
    ct = e->ct;
    zone = e->zone;
    force = e->force;
    commit = e->commit;
    now = pkt->timestamp_ms;
    setmark = e->setmark;
    setlabel = e->setlabel;
    nat_action_info = e->nat_action_info_ref;
    tp_src = e->tp_src;
    tp_dst = e->tp_dst;
    helper = e->helper;
    tp_id = e->tp_id;
    ctx = &e->ct_lookup_ctx;

    /* Reset ct_state whenever entering a new zone. */
    if (pkt->md.ct_state && pkt->md.ct_zone != zone) {
        pkt->md.ct_state = 0;
    }

    bool create_new_conn = false;
    initial_conn_lookup(ct, ctx, now, !!(pkt->md.ct_state &
                                         (CS_SRC_NAT | CS_DST_NAT)));
    struct conn *conn = ctx->conn;

    /* Delete found entry if in wrong direction. 'force' implies commit. */
    if (OVS_UNLIKELY(force && ctx->reply && conn)) {
        if (conn_lookup(ct, &conn->key, now, NULL, NULL)) {
            conn_force_expire(conn);
        }
        conn = NULL;
    }

    if (OVS_LIKELY(conn)) {
        if (conn->conn_type == CT_CONN_TYPE_UN_NAT) {

            ctx->reply = true;
            struct conn *rev_conn = conn;  /* Save for debugging. */
            uint32_t hash = conn_key_hash(&conn->rev_key, ct->hash_basis);
            conn_key_lookup(ct, &ctx->key, hash, now, &conn, &ctx->reply);

            if (!conn) {
                pkt->md.ct_state |= CS_INVALID;
                write_ct_md_alg_exp(pkt, zone, NULL, NULL);
                char *log_msg = xasprintf("Missing parent conn %p", rev_conn);
                ct_print_conn_info(rev_conn, log_msg, VLL_INFO, true, true);
                free(log_msg);
                return;
            }
        }
    }

    enum ct_alg_ctl_type ct_alg_ctl = get_alg_ctl_type(pkt, tp_src, tp_dst,
                                                       helper);

    if (OVS_LIKELY(conn)) {
        if (OVS_LIKELY(!conn_update_state_alg(ct, pkt, ctx, conn,
                                              nat_action_info,
                                              ct_alg_ctl, now,
                                              &create_new_conn))) {
            create_new_conn = conn_update_state(ct, pkt, ctx, conn, now);
        }
        if (nat_action_info && !create_new_conn) {
            handle_nat(pkt, conn, zone, ctx->reply, ctx->icmp_related);
        }

    } else if (check_orig_tuple(ct, pkt, ctx, now, &conn, nat_action_info)) {
        create_new_conn = conn_update_state(ct, pkt, ctx, conn, now);
    } else {
        if (ctx->icmp_related) {
            /* An icmp related conn should always be found; no new
               connection is created based on an icmp related packet. */
            pkt->md.ct_state = CS_INVALID;
        } else {
            create_new_conn = true;
        }
    }

    const struct alg_exp_node *alg_exp = NULL;
    struct alg_exp_node alg_exp_entry;

    if (OVS_UNLIKELY(create_new_conn)) {

        ovs_rwlock_rdlock(&ct->resources_lock);
        alg_exp = expectation_lookup(&ct->alg_expectations, &ctx->key,
                                     ct->hash_basis,
                                     alg_src_ip_wc(ct_alg_ctl));
        if (alg_exp) {
            memcpy(&alg_exp_entry, alg_exp, sizeof alg_exp_entry);
            alg_exp = &alg_exp_entry;
        }
        ovs_rwlock_unlock(&ct->resources_lock);

        if (!conn_lookup(ct, &ctx->key, now, NULL, NULL)) {
            conn = conn_not_found(ct, pkt, ctx, commit, now, nat_action_info,
                                  helper, alg_exp, ct_alg_ctl, tp_id);
        }
    }

    if (conn) {
        conn_lock(conn);

        write_ct_md_conn(pkt, zone, conn);
        if (setmark) {
            set_mark(pkt, conn, setmark[0], setmark[1]);
        }
        if (setlabel) {
            set_label(pkt, conn, &setlabel[0], &setlabel[1]);
        }

        conn_unlock(conn);
    } else {
        write_ct_md_alg_exp(pkt, zone, &ctx->key, alg_exp);
    }

    handle_alg_ctl(ct, ctx, pkt, ct_alg_ctl, conn, now, !!nat_action_info);

    set_cached_conn(nat_action_info, ctx, conn, pkt);
}

/* Sends the packets in '*pkt_batch' through the connection tracker 'ct'.  All
 * the packets must have the same 'dl_type' (IPv4 or IPv6) and should have
 * the l3 and and l4 offset properly set.  Performs fragment reassembly with
 * the help of ipf_preprocess_conntrack().
 *
 * If 'commit' is true, the packets are allowed to create new entries in the
 * connection tables.  'setmark', if not NULL, should point to a two
 * elements array containing a value and a mask to set the connection mark.
 * 'setlabel' behaves similarly for the connection label.*/
int
ctd_conntrack_execute(struct dp_packet *pkt)
{
    const struct nat_action_info_t *nat_action_info;
    const struct ovs_key_ct_labels *setlabel;
    struct dp_packet_batch pkt_batch;
    struct conn_lookup_ctx *ctx;
    const uint32_t *setmark;
    struct conntrack *ct;
    const char *helper;
    struct conn *conn;
    struct ct_exec *e;
    long long now_us;
    long long now_ms;
    ovs_be16 dl_type;
    ovs_be16 tp_src;
    ovs_be16 tp_dst;
    uint16_t zone;
    bool force;

    e = &pkt->ct_exec;
    ct = e->ct;
    dp_packet_batch_init_packet(&pkt_batch, pkt);
    dl_type = e->dl_type;
    zone = e->zone;
    force = e->force;
    setmark = e->setmark;
    setlabel = e->setlabel;
    tp_src = e->tp_src;
    tp_dst = e->tp_dst;
    helper = e->helper;
    nat_action_info = e->nat_action_info_ref;
    now_ms = pkt->timestamp_ms;

    now_us = now_ms * 1000;
    ipf_preprocess_conntrack(ct->ipf, &pkt_batch, now_ms, dl_type, zone,
                             ct->hash_basis);

    conn = pkt->md.conn;

    ctx = &pkt->ct_exec.ct_lookup_ctx;
    ctx->conn = NULL;
    if (OVS_UNLIKELY(pkt->md.ct_state == CS_INVALID)) {
        write_ct_md_alg_exp(pkt, zone, NULL, NULL);
    } else if (conn && conn->key.zone == zone && !force
               && !get_alg_ctl_type(pkt, tp_src, tp_dst, helper)) {
        process_one_fast(zone, setmark, setlabel, nat_action_info,
                         conn, pkt);
    } else if (OVS_UNLIKELY(!ctx->valid)) {
        pkt->md.ct_state = CS_INVALID;
        write_ct_md_alg_exp(pkt, zone, NULL, NULL);
    } else {
        ctd_process_one(pkt);
    }
    conn = pkt->md.conn ? pkt->md.conn : ctx->conn;
    process_one_ct_offload(ct, pkt, conn, ctx->reply, now_us);

    ipf_postprocess_conntrack(ct->ipf, &pkt_batch, now_ms, dl_type);

    return 0;
}
