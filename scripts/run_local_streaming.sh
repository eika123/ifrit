#!/usr/bin/env bash
set -e

export PATH="${PATH}:/usr/local/go/bin:${HOME}/go/bin"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

echo "=========================================="
echo " Starting Local CA & Streaming Example"
echo "=========================================="

PIDS=()
CLEANUP_DIRS=()

cleanup() {
    echo ""
    echo "[*] Cleaning up processes and temp state..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true

    for dir in "${CLEANUP_DIRS[@]}"; do
        rm -rf "$dir" 2>/dev/null || true
    done
    echo "[+] Cleaned up."
}
trap cleanup EXIT INT TERM

# Build CA and streaming binaries
echo "[*] Building CA and Streaming Example binaries..."
go build -o /tmp/ifrit-ca ./cmd/ca
go build -o /tmp/ifrit-streaming ./examples/streaming/streamingExample.go

CA_DIR=$(mktemp -d /tmp/ifrit-ca-stream-XXXXXX)
CLEANUP_DIRS+=("$CA_DIR")

# Start CA daemon with fresh group state on port 8321
echo "[*] Starting CA daemon on 127.0.0.1:8321..."
/tmp/ifrit-ca --new --path "$CA_DIR" --host 127.0.0.1 --port 8321 > /dev/null 2>&1 &
CA_PID=$!
PIDS+=("$CA_PID")

# Wait for CA HTTP listener to become ready
echo -n "[*] Waiting for CA listener..."
READY=false
for i in {1..30}; do
    if nc -z 127.0.0.1 8321 2>/dev/null; then
        READY=true
        break
    fi
    sleep 0.1
done

if [ "$READY" = false ]; then
    echo " FAILED"
    echo "[-] CA daemon failed to bind 127.0.0.1:8321"
    exit 1
fi
echo " READY"

# Run the streaming example (exchanges 10 messages and echoed replies)
echo "=========================================="
echo " Running Streaming Exchange (10 messages)"
echo "=========================================="
/tmp/ifrit-streaming
echo "=========================================="
echo " Done!"
