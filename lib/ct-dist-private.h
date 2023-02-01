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

#ifndef CT_DIST_PRIVATE_H
#define CT_DIST_PRIVATE_H

#include <stdint.h>

#include "conntrack.h"
#include "ct-dist.h"
#include "ct-dist-msg.h"
#include "smap.h"

#ifdef  __cplusplus
extern "C" {
#endif

void ctd_conn_clean(struct ctd_msg_conn_clean *msg);

int ctd_conntrack_execute(struct dp_packet *pkt);
void *ctd_clean_thread_main(void *f_);
void ctd_nat_candidate(struct dp_packet *pkt);

uint32_t conn_key_hash(const struct conn_key *, uint32_t basis);
long long int conn_expiration(const struct conn *conn);
bool conn_unref(struct conn *conn);

#ifdef  __cplusplus
}
#endif

#endif /* CT_DIST_PRIVATE_H */
