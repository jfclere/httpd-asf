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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#include "h3_check.h"
#include "h3_os.h"
#include "quic/detail/h3q_ngtcp2.h"
#include "quic/detail/h3q_tls.h"
#include "quic/h3q.h"

ngtcp2_tstamp h3q_timestamp(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)ts.tv_nsec;
}

static ngtcp2_conn *h3q_get_conn_cb(ngtcp2_crypto_conn_ref *ref)
{
    h3q_conn *conn = (h3q_conn *)ref->user_data;
    return conn->qconn;
}

static void h3q_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
    (void)rand_ctx;
    RAND_bytes(dest, (int)destlen);
}

static int h3q_get_new_cid_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data)
{
    (void)conn;
    (void)user_data;
    RAND_bytes(cid->data, (int)cidlen);
    cid->datalen = cidlen;
    RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

static int h3q_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data)
{
    h3q_conn *c = (h3q_conn *)user_data;
    int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
    (void)conn;
    (void)offset;
    (void)stream_user_data;

    h3q_stream *st = h3q_stream_get_or_create(c, stream_id);
    if (st)
    {
        h3q_stream_push_read(st, data, datalen, fin);
    }
    ngtcp2_conn_extend_max_stream_offset(c->qconn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(c->qconn, datalen);
    return 0;
}

static int h3q_stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
    h3q_conn *c = (h3q_conn *)user_data;
    (void)conn;

    h3q_stream *st = h3q_stream_get_or_create(c, stream_id);
    if (!st)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    /* Queue for accept */
    st->accept_next = NULL;
    if (c->stream_accept_tail)
    {
        c->stream_accept_tail->accept_next = st;
    }
    else
    {
        c->stream_accept_head = st;
    }
    c->stream_accept_tail = st;
    return 0;
}

static int h3q_stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t app_error_code, void *user_data, void *stream_user_data)
{
    h3q_conn *c = (h3q_conn *)user_data;
    (void)conn;
    (void)flags;
    (void)app_error_code;
    (void)stream_user_data;

    h3q_stream *st = h3q_stream_find(c, stream_id);
    if (st)
    {
        st->read_finished = 1;
        st->write_finished = 1;
    }
    return 0;
}

static int h3q_acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset, uint64_t datalen, void *user_data, void *stream_user_data)
{
    (void)conn;
    (void)stream_id;
    (void)offset;
    (void)datalen;
    (void)user_data;
    (void)stream_user_data;
    return 0;
}

static int h3q_extend_max_stream_data_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t max_data, void *user_data, void *stream_user_data)
{
    h3q_conn *c = (h3q_conn *)user_data;
    (void)conn;
    (void)max_data;
    (void)stream_user_data;

    h3q_stream *st = h3q_stream_find(c, stream_id);
    if (st)
    {
        /* Unblock pending writes since flow control window grew. */
    }
    return 0;
}

static void h3q_init_callbacks(ngtcp2_callbacks *cb)
{
    memset(cb, 0, sizeof(*cb));
    cb->recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    cb->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    cb->encrypt = ngtcp2_crypto_encrypt_cb;
    cb->decrypt = ngtcp2_crypto_decrypt_cb;
    cb->hp_mask = ngtcp2_crypto_hp_mask_cb;
    cb->update_key = ngtcp2_crypto_update_key_cb;
    cb->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb->delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb->get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    cb->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    cb->recv_stream_data = h3q_recv_stream_data_cb;
    cb->acked_stream_data_offset = h3q_acked_stream_data_offset_cb;
    cb->stream_open = h3q_stream_open_cb;
    cb->stream_close = h3q_stream_close_cb;
    cb->extend_max_stream_data = h3q_extend_max_stream_data_cb;
    cb->rand = h3q_rand_cb;
    cb->get_new_connection_id = h3q_get_new_cid_cb;
}

static h3q_conn *h3q_conn_create(h3q_engine *engine, const ngtcp2_pkt_hd *hd, const struct sockaddr_storage *remote, socklen_t remotelen, ngtcp2_tstamp now)
{
    h3q_conn *conn = calloc(1, sizeof(*conn));
    ngtcp2_callbacks cb;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_cid scid;
    ngtcp2_path_storage ps;
    int rv;

    if (!conn)
    {
        return NULL;
    }

    conn->engine = engine;
    conn->udp_fd = engine->udp_fd;
    memcpy(&conn->local_addr, &engine->local_addr, engine->local_addrlen);
    conn->local_addrlen = engine->local_addrlen;
    memcpy(&conn->remote_addr, remote, remotelen);
    conn->remote_addrlen = remotelen;

    scid.datalen = H3Q_CID_LEN;
    RAND_bytes(scid.data, (int)scid.datalen);

    ngtcp2_path_storage_zero(&ps);
    ps.path.local.addr = (struct sockaddr *)&conn->local_addr;
    ps.path.local.addrlen = conn->local_addrlen;
    ps.path.remote.addr = (struct sockaddr *)&conn->remote_addr;
    ps.path.remote.addrlen = conn->remote_addrlen;

    h3q_init_callbacks(&cb);

    ngtcp2_settings_default(&settings);
    settings.initial_ts = now;

    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_uni = 3;
    params.initial_max_streams_bidi = engine->max_streams_bidi;
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.initial_max_data = 1024 * 1024;
    params.original_dcid = hd->dcid;
    params.original_dcid_present = 1;
    if (engine->idle_timeout_secs > 0)
    {
        params.max_idle_timeout = (uint64_t)engine->idle_timeout_secs * NGTCP2_SECONDS;
    }

    rv = ngtcp2_conn_server_new(&conn->qconn, &hd->scid, &scid, &ps.path, hd->version, &cb, &settings, &params, NULL, conn);
    if (rv != 0)
    {
        free(conn);
        return NULL;
    }

    conn->ssl = SSL_new(engine->ssl_ctx);
    if (!conn->ssl)
    {
        ngtcp2_conn_del(conn->qconn);
        free(conn);
        return NULL;
    }
    SSL_set_accept_state(conn->ssl);

    conn->conn_ref.get_conn = h3q_get_conn_cb;
    conn->conn_ref.user_data = conn;

    rv = ngtcp2_crypto_ossl_configure_server_session(conn->ssl);
    if (rv != 0)
    {
        SSL_free(conn->ssl);
        ngtcp2_conn_del(conn->qconn);
        free(conn);
        return NULL;
    }
    SSL_set_app_data(conn->ssl, &conn->conn_ref);

    rv = ngtcp2_crypto_ossl_ctx_new(&conn->ossl_ctx, conn->ssl);
    if (rv != 0)
    {
        SSL_set_app_data(conn->ssl, NULL);
        SSL_free(conn->ssl);
        ngtcp2_conn_del(conn->qconn);
        free(conn);
        return NULL;
    }
    ngtcp2_conn_set_tls_native_handle(conn->qconn, conn->ossl_ctx);

    return conn;
}

static h3q_conn *h3q_find_conn_by_dcid(h3q_engine *engine, const ngtcp2_cid *dcid)
{
    h3q_conn *c;
    for (c = engine->conn_head; c; c = c->next)
    {
        size_t num = ngtcp2_conn_get_scid(c->qconn, NULL);
        ngtcp2_cid scids[16];
        size_t i;
        if (num > 16)
        {
            num = 16;
        }
        ngtcp2_conn_get_scid(c->qconn, scids);
        for (i = 0; i < num; i++)
        {
            if (ngtcp2_cid_eq(dcid, &scids[i]))
            {
                return c;
            }
        }
    }
    return NULL;
}

static void h3q_engine_add_conn(h3q_engine *engine, h3q_conn *conn)
{
    conn->next = engine->conn_head;
    engine->conn_head = conn;
}

static void h3q_engine_queue_accept(h3q_engine *engine, h3q_conn *conn)
{
    conn->accept_next = NULL;
    if (engine->accept_tail)
    {
        engine->accept_tail->accept_next = conn;
    }
    else
    {
        engine->accept_head = conn;
    }
    engine->accept_tail = conn;
}

h3q_engine *h3q_engine_create(const h3q_config *cfg, int udp_fd, char *err, size_t errlen)
{
    h3q_engine *engine;

    CHECK(cfg);
    engine = calloc(1, sizeof(*engine));
    if (!engine)
    {
        h3q_tls_error(err, errlen, "allocating the engine failed");
        return NULL;
    }

    engine->ssl_ctx = h3q_tls_ctx_create(cfg, err, errlen);
    if (!engine->ssl_ctx)
    {
        free(engine);
        return NULL;
    }

    engine->udp_fd = udp_fd;
    engine->idle_timeout_secs = 30;
    engine->max_streams_bidi = cfg->max_streams_bidi ? cfg->max_streams_bidi : 100;

    engine->local_addrlen = sizeof(engine->local_addr);
    if (getsockname(udp_fd, (struct sockaddr *)&engine->local_addr, &engine->local_addrlen) < 0)
    {
        h3q_tls_error(err, errlen, "getsockname failed");
        SSL_CTX_free(engine->ssl_ctx);
        free(engine);
        return NULL;
    }

    return engine;
}

void h3q_engine_destroy(h3q_engine *engine)
{
    h3q_conn *c;
    h3q_conn *next;

    if (!engine)
    {
        return;
    }
    for (c = engine->conn_head; c; c = next)
    {
        next = c->next;
        if (c->ossl_ctx)
        {
            ngtcp2_crypto_ossl_ctx_del(c->ossl_ctx);
        }
        if (c->ssl)
        {
            SSL_set_app_data(c->ssl, NULL);
            SSL_free(c->ssl);
        }
        if (c->qconn)
        {
            ngtcp2_conn_del(c->qconn);
        }
        /* Free all streams */
        {
            h3q_stream *st = c->stream_head;
            while (st)
            {
                h3q_stream *snext = st->next;
                free(st->read_buf);
                free(st->write_buf);
                free(st);
                st = snext;
            }
        }
        free(c);
    }
    if (engine->ssl_ctx)
    {
        SSL_CTX_free(engine->ssl_ctx);
    }
    free(engine);
}

static int h3q_conn_write_to_wire_ts(h3q_conn *conn, ngtcp2_tstamp now);

int h3q_engine_pump(h3q_engine *engine)
{
    uint8_t buf[65536];
    struct sockaddr_storage remote;
    socklen_t remotelen;
    ssize_t nread;
    int received = 0;
    int wrote = 0;
    int rounds = 0;
    ngtcp2_tstamp now;
    h3q_conn *c;

    if (!engine)
    {
        return 0;
    }

    now = h3q_timestamp();

    /* Read datagrams and route to connections */
    while (rounds < H3Q_RECV_BUDGET)
    {
        ngtcp2_pkt_info pi;
        ngtcp2_path_storage ps;

        remotelen = sizeof(remote);
        nread = recvfrom(engine->udp_fd, buf, sizeof(buf), 0, (struct sockaddr *)&remote, &remotelen);
        if (nread < 0)
        {
            break;
        }
        rounds++;
        received = 1;

        /* Extract DCID and find connection */
        {
            h3q_conn *target = NULL;
            if (buf[0] & 0x80)
            {
                /* Long header: try ngtcp2_accept for Initial */
                ngtcp2_pkt_hd hd;
                int rv = ngtcp2_accept(&hd, buf, (size_t)nread);
                if (rv == 0)
                {
                    /* Initial packet — find existing or create new */
                    target = h3q_find_conn_by_dcid(engine, &hd.dcid);
                    if (!target)
                    {
                        target = h3q_conn_create(engine, &hd, &remote, remotelen, now);
                        if (target)
                        {
                            h3q_engine_add_conn(engine, target);
                            h3q_engine_queue_accept(engine, target);
                        }
                    }
                }
                else
                {
                    /* Non-Initial long header — parse DCID manually */
                    if ((size_t)nread >= 6)
                    {
                        ngtcp2_cid dcid;
                        size_t dcid_len = buf[5];
                        if (dcid_len <= NGTCP2_MAX_CIDLEN && (size_t)nread >= 6 + dcid_len)
                        {
                            ngtcp2_cid_init(&dcid, buf + 6, dcid_len);
                            target = h3q_find_conn_by_dcid(engine, &dcid);
                        }
                    }
                }
            }
            else
            {
                /* Short header: DCID at byte 1, fixed length */
                if ((size_t)nread >= 1 + H3Q_CID_LEN)
                {
                    ngtcp2_cid dcid;
                    ngtcp2_cid_init(&dcid, buf + 1, H3Q_CID_LEN);
                    target = h3q_find_conn_by_dcid(engine, &dcid);
                }
            }

            if (target && !target->closed && !target->draining)
            {
                int rv;
                memset(&pi, 0, sizeof(pi));
                ngtcp2_path_storage_zero(&ps);
                ps.path.local.addr = (struct sockaddr *)&target->local_addr;
                ps.path.local.addrlen = target->local_addrlen;
                ps.path.remote.addr = (struct sockaddr *)&remote;
                ps.path.remote.addrlen = remotelen;

                rv = ngtcp2_conn_read_pkt(target->qconn, &ps.path, &pi, buf, (size_t)nread, now);
                if (rv == NGTCP2_ERR_DRAINING)
                {
                    target->draining = 1;
                    target->closed = 1;
                }
                else if (rv != 0 && rv != NGTCP2_ERR_CLOSING)
                {
                    target->closed = 1;
                    snprintf(target->close_reason_buf, sizeof(target->close_reason_buf), "read_pkt: %s", ngtcp2_strerror(rv));
                }

                if (!target->handshake_done && ngtcp2_conn_get_handshake_completed(target->qconn))
                {
                    target->handshake_done = 1;
                }
            }
        }
    }

    /* Process timers and write for all connections */
    for (c = engine->conn_head; c; c = c->next)
    {
        int rv;
        if (c->closed)
        {
            continue;
        }

        rv = ngtcp2_conn_handle_expiry(c->qconn, now);
        if (rv != 0)
        {
            c->closed = 1;
            snprintf(c->close_reason_buf, sizeof(c->close_reason_buf), "handle_expiry: %s", ngtcp2_strerror(rv));
            continue;
        }

        if (h3q_conn_write_to_wire_ts(c, now) > 0)
        {
            wrote = 1;
        }
    }

    return (received || wrote) ? 1 : 0;
}

void h3q_engine_want(h3q_engine *engine, int *want_read, int *want_write, int *timeout_ms)
{
    h3q_conn *c;
    ngtcp2_tstamp now;
    ngtcp2_tstamp earliest;

    if (!engine)
    {
        *want_read = 0;
        *want_write = 0;
        *timeout_ms = 1000;
        return;
    }

    *want_read = 1;
    *want_write = 0;

    now = h3q_timestamp();
    earliest = UINT64_MAX;

    for (c = engine->conn_head; c; c = c->next)
    {
        ngtcp2_tstamp expiry;
        if (c->closed)
        {
            continue;
        }
        expiry = ngtcp2_conn_get_expiry(c->qconn);
        if (expiry < earliest)
        {
            earliest = expiry;
        }
    }

    if (earliest != UINT64_MAX && earliest > now)
    {
        int64_t ms = (int64_t)((earliest - now) / NGTCP2_MILLISECONDS);
        if (ms >= 0 && ms < (int64_t)*timeout_ms)
        {
            *timeout_ms = (int)(ms > 0 ? ms : 1);
        }
    }
    else if (earliest != UINT64_MAX)
    {
        *timeout_ms = 1;
    }

    if (*timeout_ms < 1)
    {
        *timeout_ms = 1;
    }
}

h3q_conn *h3q_engine_accept_conn(h3q_engine *engine)
{
    h3q_conn *conn;
    if (!engine || !engine->accept_head)
    {
        return NULL;
    }
    conn = engine->accept_head;
    engine->accept_head = conn->accept_next;
    if (!engine->accept_head)
    {
        engine->accept_tail = NULL;
    }
    conn->accept_next = NULL;
    return conn;
}

int h3q_engine_peer_addr(h3q_engine *engine, h3q_conn *conn, struct sockaddr_storage *addr, socklen_t *addr_len)
{
    (void)engine;
    if (!conn || !addr || !addr_len)
    {
        return 0;
    }
    memcpy(addr, &conn->remote_addr, conn->remote_addrlen);
    *addr_len = conn->remote_addrlen;
    return 1;
}

static int h3q_conn_write_to_wire_ts(h3q_conn *conn, ngtcp2_tstamp now)
{
    uint8_t pkt[H3Q_MAX_PKT_SIZE];
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    int wrote = 0;
    h3q_stream *st;

    ngtcp2_path_storage_zero(&ps);

    /* Write stream data */
    for (st = conn->stream_head; st; st = st->next)
    {
        while (st->write_len > 0 || st->write_fin_pending)
        {
            ngtcp2_vec vec;
            ngtcp2_ssize nwrite;
            ngtcp2_ssize ndatalen = 0;
            uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

            if (st->write_len > 0)
            {
                vec.base = st->write_buf;
                vec.len = st->write_len;
            }
            else
            {
                vec.base = NULL;
                vec.len = 0;
            }

            if (st->write_fin_pending && st->write_len == 0)
            {
                flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
            }

            nwrite = ngtcp2_conn_writev_stream(conn->qconn, &ps.path, &pi, pkt, sizeof(pkt), &ndatalen, flags, st->id, &vec, vec.len > 0 ? 1 : 0, now);

            if (nwrite == NGTCP2_ERR_WRITE_MORE)
            {
                if (ndatalen > 0 && (size_t)ndatalen <= st->write_len)
                {
                    memmove(st->write_buf, st->write_buf + ndatalen, st->write_len - (size_t)ndatalen);
                    st->write_len -= (size_t)ndatalen;
                }
                continue;
            }
            if (nwrite < 0)
            {
                break;
            }
            if (ndatalen > 0 && (size_t)ndatalen <= st->write_len)
            {
                memmove(st->write_buf, st->write_buf + ndatalen, st->write_len - (size_t)ndatalen);
                st->write_len -= (size_t)ndatalen;
            }
            if (st->write_fin_pending && st->write_len == 0 && (flags & NGTCP2_WRITE_STREAM_FLAG_FIN))
            {
                st->write_fin_pending = 0;
                st->write_finished = 1;
            }
            if (nwrite > 0)
            {
                sendto(conn->udp_fd, pkt, (size_t)nwrite, 0, (struct sockaddr *)&conn->remote_addr, conn->remote_addrlen);
                wrote = 1;
            }
            if (nwrite == 0)
            {
                break;
            }
        }
    }

    /* Write any remaining packets (acks, handshake, keepalive) */
    for (;;)
    {
        ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(conn->qconn, &ps.path, &pi, pkt, sizeof(pkt), now);
        if (nwrite <= 0)
        {
            break;
        }
        sendto(conn->udp_fd, pkt, (size_t)nwrite, 0, (struct sockaddr *)&conn->remote_addr, conn->remote_addrlen);
        wrote = 1;
    }

    return wrote;
}

int h3q_conn_write_to_wire(h3q_conn *conn)
{
    return h3q_conn_write_to_wire_ts(conn, h3q_timestamp());
}
