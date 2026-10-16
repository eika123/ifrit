#!/usr/bin/env bash
set -e

export PATH="${PATH}:/usr/local/go/bin:${HOME}/go/bin"

# Find repo root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${REPO_ROOT}"

echo "=========================================="
echo " Starting Ifrit Gossip Example Setup"
echo "=========================================="

PIDS=()
cleanup() {
    echo ""
    echo "[*] Stopping cluster processes..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    echo "[+] Cleaned up all processes."
}
trap cleanup EXIT INT TERM

echo "[*] Building CA and Gossip Node binaries..."
go build -o /tmp/ifrit-ca ./cmd/ca
go build -o /tmp/ifrit-gossip-node ./_examples/gossipContentExample.go

echo "[*] Starting CA daemon on localhost:8321..."
/tmp/ifrit-ca --new &
CA_PID=$!
PIDS+=("$CA_PID")

# Wait for CA to start
sleep 2
if ! kill -0 "$CA_PID" 2>/dev/null; then
    echo "[-] CA daemon failed to start!"
    exit 1
fi
echo "[+] CA daemon running (PID: $CA_PID)."

echo "[*] Starting Gossip Node 1 (RPC: 9000, UDP: 9001)..."
IFRIT_HOSTNAME=localhost IFRIT_TCP_PORT=9000 IFRIT_UDP_PORT=9001 /tmp/ifrit-gossip-node &
NODE1_PID=$!
PIDS+=("$NODE1_PID")

sleep 1

echo "[*] Starting Gossip Node 2 (RPC: 9002, UDP: 9003)..."
IFRIT_HOSTNAME=localhost IFRIT_TCP_PORT=9002 IFRIT_UDP_PORT=9003 /tmp/ifrit-gossip-node &
NODE2_PID=$!
PIDS+=("$NODE2_PID")

echo "=========================================="
echo " Cluster running! Press Ctrl+C to stop."
echo "=========================================="

wait -n "${PIDS[@]}" 2>/dev/null || wait
