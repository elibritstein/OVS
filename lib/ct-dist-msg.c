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

#include <config.h>
#include <stdint.h>

#include "conntrack.h"
#include "ct-dist-msg.h"
#include "ct-dist-thread.h"

void
ctd_msg_conn_clean_send(struct conntrack *ct, struct conn *conn, uint32_t hash)
{
    struct ctd_msg_conn_clean *msg;

    msg = xmalloc(sizeof *msg);
    msg->hdr.ct = ct;
    msg->conn = conn;
    ctd_msg_type_set(&msg->hdr, CTD_MSG_CLEAN);

    ctd_msg_dest_set(&msg->hdr, hash);
    ctd_msg_fate_set(&msg->hdr, CTD_MSG_FATE_CTD);
    ctd_send_msg_to_thread(&msg->hdr, ctd_h2tid(hash));
}
