#!/usr/bin/env bash
set -euo pipefail

# setup_bpf.sh: Automates eBPF dependency setup, vmlinux.h extraction,
# and Go code generation for the passive network observer.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BPF_DIR="${SCRIPT_DIR}/bpf"
TARGET_HEADER="${BPF_DIR}/vmlinux.h"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

INSTALL_DEPS=false

for arg in "$@"; do
    case "$arg" in
        -i|--install-deps)
            INSTALL_DEPS=true
            ;;
        -h|--help)
            cat << 'EOF'
Usage: ./setup_bpf.sh [OPTIONS]

Prepares eBPF environment and compiles BPF objects:
  1. Checks for required toolchain (clang, llvm-strip, libbpf-dev, bpftool)
  2. Generates vmlinux.h from kernel BTF
  3. Executes 'go generate' to produce filter_bpf.go and filter_bpf.o

Options:
  -i, --install-deps    Automatically install missing host packages using apt
  -h, --help            Show this help message
EOF
            exit 0
            ;;
    esac
done

echo "====================================================================="
echo "Ifrit eBPF Observer Setup & Code Generation"
echo "====================================================================="

# 1. Check required tools and libraries
MISSING_PKGS=()

if ! command -v clang >/dev/null 2>&1; then
    MISSING_PKGS+=("clang")
fi

if ! command -v llvm-strip >/dev/null 2>&1; then
    MISSING_PKGS+=("llvm")
fi

if ! command -v bpftool >/dev/null 2>&1; then
    # In some Debian/Ubuntu releases, bpftool is packaged under linux-tools-common
    # and linux-tools-$(uname -r) or linux-tools-generic rather than standalone 'bpftool'
    if apt-cache show bpftool >/dev/null 2>&1; then
        MISSING_PKGS+=("bpftool")
    elif apt-cache show "linux-tools-$(uname -r)" >/dev/null 2>&1; then
        MISSING_PKGS+=("linux-tools-common" "linux-tools-$(uname -r)")
    else
        MISSING_PKGS+=("linux-tools-common" "linux-tools-generic")
    fi
fi

if [ ! -f "/usr/include/bpf/bpf_endian.h" ]; then
    MISSING_PKGS+=("libbpf-dev")
fi

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    echo "Missing required eBPF packages: ${MISSING_PKGS[*]}"
    if [ "$INSTALL_DEPS" = true ]; then
        echo "Installing missing dependencies via apt..."
        sudo apt-get update
        sudo apt-get install -y "${MISSING_PKGS[@]}"
    else
        echo "Please install them via:"
        echo "  sudo apt-get update && sudo apt-get install -y ${MISSING_PKGS[*]}"
        echo "Or rerun this script with: $0 --install-deps"
        exit 1
    fi
fi

# 2. Extract or locate vmlinux.h
mkdir -p "${BPF_DIR}"

if [ -s "${TARGET_HEADER}" ]; then
    echo "[1/3] vmlinux.h already present at ${TARGET_HEADER}."
else
    SYS_VMLINUX=$(find /usr/include -name "vmlinux.h" 2>/dev/null | head -n 1 || true)
    if [ -n "${SYS_VMLINUX}" ] && [ -f "${SYS_VMLINUX}" ]; then
        echo "[1/3] Found host vmlinux.h at ${SYS_VMLINUX}. Creating symlink..."
        ln -sf "${SYS_VMLINUX}" "${TARGET_HEADER}"
    elif [ -f "/sys/kernel/btf/vmlinux" ]; then
        echo "[1/3] Dumping vmlinux.h from running kernel BTF (/sys/kernel/btf/vmlinux)..."
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${TARGET_HEADER}"
        echo "      Successfully generated ${TARGET_HEADER}."
    else
        echo "Error: Could not locate /sys/kernel/btf/vmlinux or system vmlinux.h."
        echo "Ensure the host kernel has CONFIG_DEBUG_INFO_BTF=y."
        exit 1
    fi
fi

# 3. Generate Go bindings and BPF bytecode
echo "[2/3] Generating eBPF Go bindings and bytecode via 'go generate'..."
(cd "${REPO_ROOT}" && go generate ./experiments/observer)

# 4. Verify outputs
echo "[3/3] Verifying generated artifacts..."
if [ -f "${SCRIPT_DIR}/filter_bpf.go" ] && [ -f "${SCRIPT_DIR}/filter_bpf.o" ]; then
    echo "Successfully generated:"
    echo "  - ${SCRIPT_DIR}/filter_bpf.go"
    echo "  - ${SCRIPT_DIR}/filter_bpf.o"
    echo "Done! The observer layer is ready to compile."
else
    echo "Error: Code generation completed but expected output files were not found."
    exit 1
fi
