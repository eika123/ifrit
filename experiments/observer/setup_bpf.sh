#!/usr/bin/env bash
set -euo pipefail

# setup_bpf.sh: Prepares vmlinux.h for eBPF compilation on the host.
# Extracts BTF type information from the running kernel (/sys/kernel/btf/vmlinux)
# or symlinks it if already available in standard system locations.

## finds out where the currently executing script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BPF_DIR="${SCRIPT_DIR}/bpf"
TARGET_HEADER="${BPF_DIR}/vmlinux.h"

mkdir -p "${BPF_DIR}"

# 1. If vmlinux.h already exists, verify it is valid
if [ -s "${TARGET_HEADER}" ]; then
    echo "vmlinux.h already present at ${TARGET_HEADER}."
    exit 0
fi

# 2. Check if host has an installed vmlinux.h in standard include paths
SYS_VMLINUX=$(find /usr/include -name "vmlinux.h" 2>/dev/null | head -n 1 || true)
# checks that SYS_VMLINUX is non-empty AND that a file exists at that location
if [ -n "${SYS_VMLINUX}" ] && [ -f "${SYS_VMLINUX}" ]; then
    echo "Found host vmlinux.h at ${SYS_VMLINUX}. Creating symlink..."
    ln -sf "${SYS_VMLINUX}" "${TARGET_HEADER}"
    exit 0
fi

# 3. Dump from running kernel BTF using bpftool
if [ -f "/sys/kernel/btf/vmlinux" ]; then
    if ! command -v bpftool >/dev/null 2>&1; then
        echo "Error: /sys/kernel/btf/vmlinux exists but 'bpftool' is not installed."
        echo "Install it via: sudo apt-get install -y linux-tools-common linux-tools-\$(uname -r) or bpftool"
        exit 1
    fi
    echo "Dumping vmlinux.h from running kernel (/sys/kernel/btf/vmlinux) via bpftool..."
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${TARGET_HEADER}"
    echo "Successfully generated ${TARGET_HEADER}."
    exit 0
fi

echo "Error: Could not locate /sys/kernel/btf/vmlinux or system vmlinux.h."
echo "Ensure kernel has CONFIG_DEBUG_INFO_BTF=y."
exit 1
