#!/usr/bin/env bash
set -e

export PATH="${PATH}:/usr/local/go/bin:${HOME}/go/bin"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

MODE="tui"
for arg in "$@"; do
    case "$arg" in
        --stream|--raw)
            MODE="stream"
            ;;
        --tmux)
            MODE="tmux"
            ;;
        --help|-h)
            echo "Usage: ./scripts/run_local_gossip.sh [options]"
            echo ""
            echo "Options:"
            echo "  (default)    3-pane split terminal dashboard"
            echo "  --stream     Stream combined output with process timestamps"
            echo "  --tmux       Launch in 3 tmux split panes (if tmux is installed)"
            echo "  --help, -h   Show this help message"
            exit 0
            ;;
    esac
done

# If not running in an interactive terminal, fall back to stream mode
if [ ! -t 1 ] && [ "$MODE" = "tui" ]; then
    MODE="stream"
fi

# Mode 1: TMUX
if [ "$MODE" = "tmux" ]; then
    if ! command -v tmux >/dev/null 2>&1; then
        echo "[-] tmux is not installed on this system. Falling back to 3-pane TUI dashboard."
        MODE="tui"
    else
        echo "[*] Building binaries..."
        go build -o /tmp/ifrit-ca ./cmd/ca
        go build -o /tmp/ifrit-gossip-node ./examples/gossip/gossipContentExample.go

        SESSION="ifrit-cluster"
        tmux kill-session -t "$SESSION" 2>/dev/null || true
        tmux new-session -d -s "$SESSION" -n "cluster" "/tmp/ifrit-ca --new"
        tmux split-window -v -t "$SESSION:0" "IFRIT_HOSTNAME=localhost IFRIT_TCP_PORT=9000 IFRIT_UDP_PORT=9001 /tmp/ifrit-gossip-node"
        tmux split-window -v -t "$SESSION:0" "IFRIT_HOSTNAME=localhost IFRIT_TCP_PORT=9002 IFRIT_UDP_PORT=9003 /tmp/ifrit-gossip-node"
        tmux select-layout -t "$SESSION:0" even-vertical
        exec tmux attach-session -t "$SESSION"
    fi
fi

# Mode 2: 3-Pane TUI Dashboard (Standard Library Curses via UV / Python)
if [ "$MODE" = "tui" ]; then
    if command -v uv >/dev/null 2>&1 && [ -d "${REPO_ROOT}/experiments" ]; then
        exec uv run --directory "${REPO_ROOT}/experiments" python "${REPO_ROOT}/examples/scripts/local_cluster_tui.py"
    else
        exec python3 "${REPO_ROOT}/examples/scripts/local_cluster_tui.py"
    fi
fi

# Mode 3: Stream mode (flat log output)
echo "=========================================="
echo " Starting Local 2-Node Gossip Cluster"
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
go build -o /tmp/ifrit-gossip-node ./examples/gossip/gossipContentExample.go

echo "[*] Starting CA daemon on localhost:8321..."
/tmp/ifrit-ca --new &
CA_PID=$!
PIDS+=("$CA_PID")

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
