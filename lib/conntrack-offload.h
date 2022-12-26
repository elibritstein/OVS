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

#ifndef CONNTRACK_OFFLOAD_H
#define CONNTRACK_OFFLOAD_H

#include "conntrack.h"
#include "openvswitch/types.h"

enum ct_timeout;
struct conn;
struct conntrack;
struct conntrack_offload_class;
struct dp_packet;

struct ct_flow_offload_item {
    int  op;
    ovs_u128 ufid;
    void *dp;
    uintptr_t ctid_key;
    long long int timestamp;

    /* matches */
    struct ct_match ct_match;

    /* actions */
    uint8_t ct_state;
    ovs_u128 label_key;
    uint32_t mark_key;

    /* Pre-created CT actions */
    bool ct_actions_set;
    struct nlattr *actions;
    size_t actions_size;

    struct {
        uint8_t mod_flags;
        struct conn_key  key;
    } nat;

    /* refcnt is used to handle a scenario in which a connection issued an
     * offload request and was removed before the offload request is processed.
     */
    struct ovs_refcount *refcnt;
};

/* hw-offload callbacks */
struct conntrack_offload_class {
    void (*conn_get_ufid)(ovs_u128 *);
    void (*conn_add)(struct ct_flow_offload_item *);
    void (*conn_del)(struct ct_flow_offload_item *);
    int (*conn_active)(struct ct_flow_offload_item *, long long now,
                       long long prev_now);
    void (*conn_e2e_add)(struct ct_flow_offload_item *);
    void (*conn_e2e_del)(ovs_u128 *, void *dp, long long int now);
    bool (*queue_full)(void);
};

void
process_one_ct_offload(struct conntrack *ct,
                       struct dp_packet *packet,
                       struct conn *conn,
                       bool reply,
                       long long now_us);
int
conn_hw_update(struct conntrack *ct,
               struct conntrack_offload_class *offload_class,
               struct conn *conn,
               enum ct_timeout *ptm,
               long long now);
void
conntrack_set_offload_class(struct conntrack *,
                            struct conntrack_offload_class *);
void
conntrack_offload_del_conn(struct conntrack *ct,
                           struct conn *conn);

#endif /* CONNTRACK_OFFLOAD_H */
