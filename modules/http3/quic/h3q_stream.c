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

#include <stdlib.h>
#include <string.h>

#include "quic/detail/h3q_ngtcp2.h"
#include "quic/h3q_stream.h"

h3q_stream *h3q_stream_find(h3q_conn *conn, int64_t stream_id)
{
    h3q_stream *st;
    if (!conn)
    {
        return NULL;
    }
    for (st = conn->stream_head; st; st = st->next)
    {
        if (st->id == stream_id)
        {
            return st;
        }
    }
    return NULL;
}

h3q_stream *h3q_stream_get_or_create(h3q_conn *conn, int64_t stream_id)
{
    h3q_stream *st;
    if (!conn)
    {
        return NULL;
    }

    st = h3q_stream_find(conn, stream_id);
    if (st)
    {
        return st;
    }

    st = calloc(1, sizeof(*st));
    if (!st)
    {
        return NULL;
    }
    st->id = stream_id;
    st->conn = conn;
    st->next = conn->stream_head;
    conn->stream_head = st;
    return st;
}

void h3q_stream_push_read(h3q_stream *st, const uint8_t *data, size_t len, int fin)
{
    if (!st)
    {
        return;
    }
    if (len > 0)
    {
        size_t needed = st->read_len + len;
        if (needed > st->read_cap)
        {
            size_t newcap = st->read_cap ? st->read_cap * 2 : H3Q_STREAM_BUF_CAP;
            uint8_t *newbuf;
            while (newcap < needed)
            {
                newcap *= 2;
            }
            newbuf = realloc(st->read_buf, newcap);
            if (!newbuf)
            {
                return;
            }
            st->read_buf = newbuf;
            st->read_cap = newcap;
        }
        memcpy(st->read_buf + st->read_len, data, len);
        st->read_len += len;
    }
    if (fin)
    {
        st->read_fin = 1;
    }
}

h3q_write_result h3q_stream_write(h3q_stream *st, const h3q_vec *vec, size_t nvec, int fin)
{
    h3q_write_result res = {0};
    size_t k;
    size_t total = 0;

    if (!st)
    {
        res.broken = 1;
        return res;
    }

    for (k = 0; k < nvec; k++)
    {
        total += vec[k].len;
    }

    for (k = 0; k < nvec; k++)
    {
        size_t needed;
        if (vec[k].len == 0)
        {
            continue;
        }
        needed = st->write_len + vec[k].len;
        if (needed > st->write_cap)
        {
            size_t newcap = st->write_cap ? st->write_cap * 2 : H3Q_STREAM_BUF_CAP;
            uint8_t *newbuf;
            while (newcap < needed)
            {
                newcap *= 2;
            }
            newbuf = realloc(st->write_buf, newcap);
            if (!newbuf)
            {
                res.blocked = 1;
                break;
            }
            st->write_buf = newbuf;
            st->write_cap = newcap;
        }
        memcpy(st->write_buf + st->write_len, vec[k].base, vec[k].len);
        st->write_len += vec[k].len;
        res.accepted += vec[k].len;
    }

    if (fin && !res.blocked && !res.broken && res.accepted == total)
    {
        st->write_fin_pending = 1;
    }
    return res;
}

int h3q_stream_is_write_blocked(h3q_stream *st)
{
    if (!st)
    {
        return 0;
    }
    /* With ngtcp2, flow control blocking is detected during write_to_wire.
     * For now, report blocked when the write buffer is large. */
    return (st->write_len > H3Q_STREAM_BUF_CAP) ? 1 : 0;
}

int h3q_stream_read(h3q_stream *st, unsigned char *buf, size_t read_size, size_t *nread, int *fin)
{
    size_t avail;
    *fin = 0;
    *nread = 0;

    if (!st)
    {
        return 0;
    }

    avail = st->read_len;
    if (avail == 0)
    {
        if (st->read_fin)
        {
            *fin = 1;
        }
        return 0;
    }

    if (avail > read_size)
    {
        avail = read_size;
    }
    memcpy(buf, st->read_buf, avail);
    *nread = avail;

    if (avail < st->read_len)
    {
        memmove(st->read_buf, st->read_buf + avail, st->read_len - avail);
    }
    st->read_len -= avail;

    if (st->read_len == 0 && st->read_fin)
    {
        *fin = 1;
    }
    return 1;
}

void h3q_stream_is_read_finished(h3q_stream *st, int *read_finished, int *write_finished)
{
    if (!st)
    {
        *read_finished = 1;
        *write_finished = 1;
        return;
    }
    *read_finished = st->read_finished || (st->read_fin && st->read_len == 0);
    *write_finished = st->write_finished;
}

void h3q_stream_reset(h3q_stream *st, uint64_t err)
{
    if (!st || !st->conn || !st->conn->qconn)
    {
        return;
    }
    ngtcp2_conn_shutdown_stream_write(st->conn->qconn, 0, st->id, err);
    st->reset_sent = 1;
    st->write_finished = 1;
}

void h3q_stream_free(h3q_stream *st)
{
    if (!st)
    {
        return;
    }

    /* Remove from connection's stream list */
    if (st->conn)
    {
        h3q_stream **pp = &st->conn->stream_head;
        while (*pp)
        {
            if (*pp == st)
            {
                *pp = st->next;
                break;
            }
            pp = &(*pp)->next;
        }
    }

    free(st->read_buf);
    free(st->write_buf);
    free(st);
}

int64_t h3q_stream_id(h3q_stream *st)
{
    return st ? st->id : -1;
}
