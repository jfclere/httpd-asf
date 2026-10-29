#!/bin/bash
# Compile and load the QUIC CID routing eBPF program.
#
# Prerequisites:
#   - clang with BPF target support
#   - bpftool
#   - libbpf-devel (for bpf/bpf_helpers.h)
#   - root privileges (for bpftool and /sys/fs/bpf)
#
# Usage:
#   sudo ./h3q_reuseport_setup.sh          # compile, load & pin
#   sudo ./h3q_reuseport_setup.sh unload   # unpin & unload

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="${SCRIPT_DIR}/h3q_reuseport_kern.c"
OBJ="${SCRIPT_DIR}/h3q_reuseport_kern.o"
PROG_PIN="/sys/fs/bpf/h3q_reuseport"
MAP_PIN="/sys/fs/bpf/h3q_cid_map"

unload() {
    echo "Removing pinned BPF objects..."
    rm -f "$PROG_PIN" "$MAP_PIN"
    echo "Done."
}

if [ "${1}" = "unload" ]; then
    unload
    exit 0
fi

echo "Compiling eBPF program..."
clang -O2 -g -target bpf -c "$SRC" -o "$OBJ"

# Remove stale pins before loading
rm -f "$PROG_PIN" "$MAP_PIN"

echo "Loading eBPF program into kernel..."
bpftool prog load "$OBJ" "$PROG_PIN" pinmaps /sys/fs/bpf
chmod 0644 "$PROG_PIN" "$MAP_PIN"

echo ""
echo "eBPF CID routing loaded:"
echo "  Program: ${PROG_PIN}"
echo "  Map:     ${MAP_PIN}"
echo ""
echo "Start httpd with SO_REUSEPORT — mod_http3 will attach the"
echo "program and register CIDs automatically."
