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

/* BPF_PROG_TYPE_SK_REUSEPORT program for QUIC connection-ID-based routing.
 *
 * Extracts the DCID from incoming QUIC packets and routes them to the
 * child process that owns the connection, using a SOCKHASH map keyed by
 * the first 8 bytes of the CID.  Initial packets from new clients miss
 * the map lookup and fall through to the kernel's default hash routing.
 *
 * Compile:
 *   clang -O2 -g -target bpf -c h3q_reuseport_kern.c -o h3q_reuseport_kern.o
 *
 * Load and pin (bpftool):
 *   bpftool prog load h3q_reuseport_kern.o /sys/fs/bpf/h3q_reuseport \
 *     pinmaps /sys/fs/bpf
 *
 * mod_http3 attaches the program via SO_ATTACH_REUSEPORT_EBPF and
 * registers server CIDs in h3q_cid_map from userspace.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define QUIC_CID_LEN 8

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u32);
} h3q_cid_map SEC(".maps");

SEC("sk_reuseport")
int quic_select_reuseport(struct sk_reuseport_md *ctx)
{
    __u8 *data     = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;
    __u64 cid = 0;

    if (data + 1 > data_end)
        return SK_PASS;

    if (data[0] & 0x80) {
        /* Long header: flags(1) + version(4) + dcid_len(1) + dcid...
         * For Handshake/0-RTT the DCID is the server's 8-byte CID.
         * For Initial packets the DCID is 20 random bytes — the first
         * 8 bytes will miss the map, giving default kernel routing
         * (any child can accept a new connection). */
        __u8 dcid_len;

        if (data + 6 > data_end)
            return SK_PASS;

        dcid_len = data[5];
        if (dcid_len < QUIC_CID_LEN || data + 6 + QUIC_CID_LEN > data_end)
            return SK_PASS;

        __builtin_memcpy(&cid, data + 6, QUIC_CID_LEN);
    } else {
        /* Short header: flags(1) + dcid(8 bytes, OpenSSL default). */
        if (data + 1 + QUIC_CID_LEN > data_end)
            return SK_PASS;

        __builtin_memcpy(&cid, data + 1, QUIC_CID_LEN);
    }

    /* Route to the socket that registered this CID.  On lookup failure
     * (new connection or unknown CID) the kernel's default hash routing
     * picks a socket from the reuseport group. */
    bpf_sk_select_reuseport(ctx, &h3q_cid_map, &cid, 0);
    return SK_PASS;
}

char _license[] SEC("license") = "Apache-2.0";
