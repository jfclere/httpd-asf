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

#include "quic/detail/h3q_reuseport.h"

#if defined(__linux__)

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

static int sys_bpf(int cmd, union bpf_attr* attr, unsigned int size)
{
    return (int)syscall(__NR_bpf, cmd, attr, size);
}

int h3q_reuseport_open_map(const char* map_path)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(unsigned long)map_path;
    return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

int h3q_reuseport_open_prog(const char* prog_path)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(unsigned long)prog_path;
    return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

int h3q_reuseport_attach(int sock_fd, int prog_fd)
{
    int rv = setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
                        &prog_fd, sizeof(prog_fd));
    return rv == 0 ? 0 : -1;
}

int h3q_reuseport_register_cid(int map_fd, uint64_t cid, int sock_fd)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)map_fd;
    attr.key    = (uint64_t)(unsigned long)&cid;
    attr.value  = (uint64_t)(unsigned long)&sock_fd;
    attr.flags  = BPF_ANY;
    return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int h3q_reuseport_unregister_cid(int map_fd, uint64_t cid)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)map_fd;
    attr.key    = (uint64_t)(unsigned long)&cid;
    return sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

#else /* !__linux__ */

int h3q_reuseport_open_map(const char* map_path)
{
    (void)map_path;
    return -1;
}

int h3q_reuseport_open_prog(const char* prog_path)
{
    (void)prog_path;
    return -1;
}

int h3q_reuseport_attach(int sock_fd, int prog_fd)
{
    (void)sock_fd;
    (void)prog_fd;
    return -1;
}

int h3q_reuseport_register_cid(int map_fd, uint64_t cid, int sock_fd)
{
    (void)map_fd;
    (void)cid;
    (void)sock_fd;
    return -1;
}

int h3q_reuseport_unregister_cid(int map_fd, uint64_t cid)
{
    (void)map_fd;
    (void)cid;
    return -1;
}

#endif /* __linux__ */
