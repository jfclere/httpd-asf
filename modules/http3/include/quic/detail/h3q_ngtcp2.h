/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef H3Q_DETAIL_NGTCP2_H
#define H3Q_DETAIL_NGTCP2_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/ssl.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#include "quic/h3q.h"

#define H3Q_CID_LEN        8
#define H3Q_STREAM_BUF_CAP 65536
#define H3Q_MAX_PKT_SIZE   1280
#define H3Q_RECV_BUDGET     64

struct h3q_stream
{
    int64_t id;
    h3q_conn *conn;

    uint8_t *read_buf;
    size_t read_len;
    size_t read_cap;
    int read_fin;

    uint8_t *write_buf;
    size_t write_len;
    size_t write_cap;
    int write_fin_pending;

    int read_finished;
    int write_finished;
    int reset_sent;

    h3q_stream *next;
    h3q_stream *accept_next;
};

struct h3q_conn
{
    ngtcp2_conn *qconn;
    ngtcp2_crypto_conn_ref conn_ref;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;
    SSL *ssl;

    h3q_engine *engine;

    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;

    int udp_fd;

    h3q_stream *stream_head;
    h3q_stream *stream_accept_head;
    h3q_stream *stream_accept_tail;

    int handshake_done;
    int closed;
    int draining;
    uint64_t last_error;
    char close_reason_buf[H3Q_ERRLEN];

    h3q_conn *next;
    h3q_conn *accept_next;
};

struct h3q_engine
{
    SSL_CTX *ssl_ctx;
    int udp_fd;
    uint32_t idle_timeout_secs;

    h3q_conn *conn_head;

    h3q_conn *accept_head;
    h3q_conn *accept_tail;

    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
};

ngtcp2_tstamp h3q_timestamp(void);
h3q_stream *h3q_stream_find(h3q_conn *conn, int64_t stream_id);
h3q_stream *h3q_stream_get_or_create(h3q_conn *conn, int64_t stream_id);
void h3q_stream_push_read(h3q_stream *st, const uint8_t *data, size_t len, int fin);
int h3q_conn_write_to_wire(h3q_conn *conn);

#endif /* H3Q_DETAIL_NGTCP2_H */
