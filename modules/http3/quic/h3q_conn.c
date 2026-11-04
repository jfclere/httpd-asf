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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#include "h3_check.h"
#include "h3_os.h"
#include "quic/detail/h3q_ngtcp2.h"
#include "quic/h3q_conn.h"

int h3q_conn_prepare(h3q_conn *conn, uint32_t idle_timeout_secs)
{
    (void)idle_timeout_secs;
    if (!conn)
    {
        return 0;
    }
    return 1;
}

h3q_stream *h3q_conn_open_uni_stream(h3q_conn *conn, int64_t *out_id)
{
    h3q_stream *st;
    int64_t stream_id;
    int rv;

    CHECK(conn);
    CHECK(out_id);

    rv = ngtcp2_conn_open_uni_stream(conn->qconn, &stream_id, NULL);
    if (rv != 0)
    {
        return NULL;
    }

    st = h3q_stream_get_or_create(conn, stream_id);
    if (!st)
    {
        return NULL;
    }
    *out_id = stream_id;
    return st;
}

h3q_stream *h3q_conn_accept_stream(h3q_conn *conn)
{
    h3q_stream *st;
    if (!conn || !conn->stream_accept_head)
    {
        return NULL;
    }
    st = conn->stream_accept_head;
    conn->stream_accept_head = st->accept_next;
    if (!conn->stream_accept_head)
    {
        conn->stream_accept_tail = NULL;
    }
    st->accept_next = NULL;
    return st;
}

int h3q_conn_is_handshake_done(h3q_conn *conn)
{
    if (!conn)
    {
        return 0;
    }
    return conn->handshake_done;
}

int h3q_conn_tls_info(h3q_conn *conn, h3q_tls_info *out)
{
    const SSL_CIPHER *cipher;
    int alg_bits;
    const char *version;

    if (!conn || !conn->ssl || !out)
    {
        return 0;
    }
    cipher = SSL_get_current_cipher(conn->ssl);
    if (!cipher)
    {
        return 0;
    }
    alg_bits = 0;
    out->cipher_bits = SSL_CIPHER_get_bits(cipher, &alg_bits);
    out->cipher_alg_bits = alg_bits;
    out->cipher = SSL_CIPHER_get_name(cipher);
    version = SSL_get_version(conn->ssl);
    out->protocol = (version && strncmp(version, "TLS", 3) == 0) ? version : "TLSv1.3";
    out->resumed = SSL_session_reused(conn->ssl) ? 1u : 0u;
    return 1;
}

int h3q_conn_is_closed(h3q_conn *conn)
{
    if (!conn)
    {
        return 1;
    }
    return conn->closed;
}

int h3q_conn_shutdown(h3q_conn *conn, int is_rapid, uint64_t app_error, const char *reason)
{
    uint8_t pkt[H3Q_MAX_PKT_SIZE];
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite;
    ngtcp2_ccerr ccerr;

    (void)reason;

    if (!conn || !conn->qconn)
    {
        return 1;
    }
    if (conn->draining)
    {
        return 1;
    }

    ngtcp2_ccerr_set_application_error(&ccerr, app_error, NULL, 0);
    ngtcp2_path_storage_zero(&ps);

    nwrite = ngtcp2_conn_write_connection_close(conn->qconn, &ps.path, &pi, pkt, sizeof(pkt), &ccerr, h3q_timestamp());
    if (nwrite > 0)
    {
        sendto(conn->udp_fd, pkt, (size_t)nwrite, 0, (struct sockaddr *)&conn->remote_addr, conn->remote_addrlen);
    }

    conn->closed = 1;
    (void)is_rapid;
    return 1;
}

void h3q_conn_extend_max_streams_bidi(h3q_conn *conn, size_t n)
{
    if (conn && conn->qconn)
    {
        ngtcp2_conn_extend_max_streams_bidi(conn->qconn, n);
    }
}

void h3q_conn_free(h3q_conn *conn)
{
    h3q_stream *st;
    h3q_stream *next;

    if (!conn)
    {
        return;
    }

    /* Remove from engine's connection list */
    if (conn->engine)
    {
        h3q_conn **pp = &conn->engine->conn_head;
        while (*pp)
        {
            if (*pp == conn)
            {
                *pp = conn->next;
                break;
            }
            pp = &(*pp)->next;
        }
        conn->engine = NULL;
    }

    /* Detach any streams still attached — do NOT free them.
     * Worker threads may still hold h3q_stream pointers; the session
     * layer frees each stream via h3q_stream_free when done. */
    for (st = conn->stream_head; st; st = next)
    {
        next = st->next;
        st->conn = NULL;
    }
    conn->stream_head = NULL;

    if (conn->ossl_ctx)
    {
        ngtcp2_crypto_ossl_ctx_del(conn->ossl_ctx);
    }
    if (conn->ssl)
    {
        SSL_set_app_data(conn->ssl, NULL);
        SSL_free(conn->ssl);
    }
    if (conn->qconn)
    {
        ngtcp2_conn_del(conn->qconn);
    }
    free(conn);
}

void h3q_conn_close_reason(h3q_conn *conn, char *buf, size_t buflen)
{
    if (!buf || buflen == 0)
    {
        return;
    }
    buf[0] = '\0';
    if (conn && conn->close_reason_buf[0])
    {
        snprintf(buf, buflen, "%s", conn->close_reason_buf);
        return;
    }
    if (conn && conn->qconn)
    {
        snprintf(buf, buflen, "ngtcp2 connection closed");
    }
}
