#!/usr/bin/env bash
set -e

# Find repo root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${REPO_ROOT}"

echo "=========================================="
echo " Starting Ifrit Gossip Example Setup"
echo "=========================================="

# Cleanup handler for CA process on exit
cleanup() {
    echo ""
    echo "[*] Cleaning up background processes..."
    if [ -n "${CA_PID}" ] && kill -0 "${CA_PID}" 2>/dev/null; then
        kill "${CA_PID}" 2>/dev/null || true
        wait "${CA_PID}" 2>/dev/null || true
        echo "[+] CA daemon (PID ${CA_PID}) stopped."
    fi
}
trap cleanup EXIT INT TERM

echo "[*] Starting CA daemon on localhost:8321..."
go run ./cmd/ca --new &
CA_PID=$!

# Wait for CA to initialize and start listening
echo "[*] Waiting for CA daemon to become ready..."
sleep 2

if ! kill -0 "${CA_PID}" 2>/dev/null; then
    echo "[-] CA daemon failed to start!"
    exit 1
fi

echo "[+] CA daemon is running (PID ${CA_PID})."
echo "=========================================="
echo " Running Gossip Content Example Application"
echo "=========================================="

go run ./_examples/gossipContentExample.go
