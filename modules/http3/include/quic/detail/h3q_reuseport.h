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

#ifndef H3Q_DETAIL_REUSEPORT_H
#define H3Q_DETAIL_REUSEPORT_H

#include <stdint.h>

#define H3Q_BPF_PROG_PIN_PATH "/sys/fs/bpf/h3q_reuseport"
#define H3Q_BPF_MAP_PIN_PATH  "/sys/fs/bpf/h3q_cid_map"

/** BPF fds opened in post_config (as root), inherited by children via fork. */
extern int h3_bpf_prog_fd;
extern int h3_bpf_map_fd;

/**
 * Open the pinned QUIC CID BPF map.  Requires CAP_BPF; call from a
 * privileged context (e.g. post_config) and let children inherit the fd.
 * @param map_path Path to the pinned map, e.g. /sys/fs/bpf/h3q_cid_map.
 * @return Map fd on success, -1 if the map is not available.
 */
int h3q_reuseport_open_map(const char* map_path);

/**
 * Open the pinned BPF reuseport program.  Requires CAP_BPF; call from a
 * privileged context and let children inherit the fd.
 * @param prog_path Path to the pinned program, e.g. /sys/fs/bpf/h3q_reuseport.
 * @return Program fd on success, -1 if not available.
 */
int h3q_reuseport_open_prog(const char* prog_path);

/**
 * Attach a BPF reuseport program (by fd) to a socket.
 * @param sock_fd UDP socket fd (must have SO_REUSEPORT set and be bound).
 * @param prog_fd BPF program fd from h3q_reuseport_open_prog.
 * @return 0 on success, -1 on failure.
 */
int h3q_reuseport_attach(int sock_fd, int prog_fd);

/**
 * Register a server CID in the BPF map so that packets carrying this
 * CID are routed to @p sock_fd.  Idempotent: re-registering the same
 * CID with the same socket is a no-op.
 * @param map_fd  BPF map fd from h3q_reuseport_open_map.
 * @param cid     First 8 bytes of the server CID, as a uint64_t.
 * @param sock_fd UDP socket fd that should receive the traffic.
 * @return 0 on success, -1 on failure.
 */
int h3q_reuseport_register_cid(int map_fd, uint64_t cid, int sock_fd);

/**
 * Remove a server CID from the BPF map.
 * @param map_fd BPF map fd from h3q_reuseport_open_map.
 * @param cid    First 8 bytes of the server CID to remove.
 * @return 0 on success, -1 on failure.
 */
int h3q_reuseport_unregister_cid(int map_fd, uint64_t cid);

#endif /* H3Q_DETAIL_REUSEPORT_H */
