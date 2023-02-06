/*
 * Copyright (c) 2023 NVIDIA Corporation.
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

#ifndef CT_DIST_MSG_H
#define CT_DIST_MSG_H

#include "conntrack.h"

#ifdef  __cplusplus
extern "C" {
#endif

enum ctd_msg_type {
    CTD_MSG_EXEC,
    CTD_MSG_EXEC_NAT,
    CTD_MSG_CLEAN,
    CTD_MSG_NAT_CANDIDATE_RESPONSE,
    CTD_MSG_NAT_CANDIDATE,
};

static const char * const ctd_msg_type_str[] = {
    [CTD_MSG_EXEC] = "EXEC",
    [CTD_MSG_EXEC_NAT] = "EXEC_NAT",
    [CTD_MSG_CLEAN] = "CLEAN",
    [CTD_MSG_NAT_CANDIDATE_RESPONSE] = "NAT_CANDIDATE_RESPONSE",
    [CTD_MSG_NAT_CANDIDATE] = "NAT_CANDIDATE",
};

enum ctd_msg_fate_type {
    CTD_MSG_FATE_TBD,
    CTD_MSG_FATE_PMD,
    CTD_MSG_FATE_CTD,
    CTD_MSG_FATE_SELF,
    CTD_MSG_FATE_FREE,
};

static const char * const ctd_msg_fate_type_str[] = {
    [CTD_MSG_FATE_TBD] = "FATE_TBD",
    [CTD_MSG_FATE_PMD] = "FATE_PMD",
    [CTD_MSG_FATE_CTD] = "FATE_CTD",
    [CTD_MSG_FATE_SELF] = "FATE_SELF",
    [CTD_MSG_FATE_FREE] = "FATE_FREE",
};

struct ctd_msg {
    struct mpsc_queue_node node;
    long long timestamp_ms;
    enum ctd_msg_type msg_type;
    enum ctd_msg_fate_type msg_fate;
    struct conntrack *ct;
    uint32_t dest_hash;
};

static inline void
ctd_msg_type_set_at(struct ctd_msg *m,
                    enum ctd_msg_type type,
                    const char *where)
{
    (void) where;
    m->msg_type = type;
}

#define ctd_msg_type_set(msg, type) \
    ctd_msg_type_set_at(msg, type, OVS_SOURCE_LOCATOR)

static inline void
ctd_msg_fate_set_at(struct ctd_msg *m,
                    enum ctd_msg_fate_type type,
                    const char *where)
{
    (void) where;
    m->msg_fate = type;
}

#define ctd_msg_fate_set(msg, type) \
    ctd_msg_fate_set_at(msg, type, OVS_SOURCE_LOCATOR)

static inline void
ctd_msg_dest_set_at(struct ctd_msg *m,
                    uint32_t hash,
                    const char *where)
{
    (void) where;
    m->dest_hash = hash;
}

#define ctd_msg_dest_set(msg, hash) \
    ctd_msg_dest_set_at(msg, hash, OVS_SOURCE_LOCATOR)

struct nat_lookup_info {
    struct conn_key rev_key;
    ovs_be16 *port;
    struct conn *nat_conn;
    struct {
        uint16_t min;
        uint16_t max;
        uint16_t curr;
    } sport, dport;
    uint16_t attempts;
    uint16_t port_iter;
    uint32_t hash;
};

struct ctd_msg_exec {
    struct ctd_msg hdr;
    ovs_be16 dl_type;
    bool force;
    bool commit;
    uint16_t zone;
    const uint32_t *setmark;
    const struct ovs_key_ct_labels *setlabel;
    ovs_be16 tp_src;
    ovs_be16 tp_dst;
    const char *helper;
    struct nat_action_info_t nat_action_info;
    struct nat_action_info_t *nat_action_info_ref;
    uint32_t tp_id;
    struct conn_lookup_ctx ct_lookup_ctx;
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_flow *flow;
    uint64_t actions_buf[512 / 8];
    size_t actions_len;
    uint32_t depth;
    struct nat_lookup_info nli;
};
BUILD_ASSERT_DECL(offsetof(struct ctd_msg_exec, hdr) == 0);

struct ctd_msg_conn_clean {
    struct ctd_msg hdr;
    struct conn *conn;
};
BUILD_ASSERT_DECL(offsetof(struct ctd_msg_conn_clean, hdr) == 0);

void ctd_msg_conn_clean_send(struct conntrack *ct, struct conn *conn,
                             uint32_t hash);

#ifdef  __cplusplus
}
#endif

#endif /* CT_DIST_MSG_H */
