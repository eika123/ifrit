#!/usr/bin/env bash
set -e

# Ensure 'go' is available in PATH, falling back to standard install directories if they exist
if ! command -v go >/dev/null 2>&1; then
    for dir in "/usr/local/go/bin" "${HOME}/go/bin"; do
        if [ -d "$dir" ] && [[ ":$PATH:" != *":$dir:"* ]]; then
            export PATH="${PATH}:${dir}"
        fi
    done
fi

if ! command -v go >/dev/null 2>&1; then
    echo "[-] Error: 'go' binary not found in PATH." >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

HOSTFILE="${REPO_ROOT}/examples/http_dissemination/cluster_local.toml"
GENERATE_NODES=0
GENERATE_HOST="127.0.0.1"
ITEMS=""
TIMEOUT=""
RUN_TEST=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--items)
            if [ -z "${2:-}" ] || [[ "$2" == -* ]]; then
                echo "[-] Error: $1 requires an argument." >&2
                exit 1
            fi
            ITEMS="$2"
            shift 2
            ;;
        -i=*|--items=*)
            ITEMS="${1#*=}"
            shift
            ;;
        -t|--timeout)
            if [ -z "${2:-}" ] || [[ "$2" == -* ]]; then
                echo "[-] Error: $1 requires an argument." >&2
                exit 1
            fi
            TIMEOUT="$2"
            shift 2
            ;;
        -t=*|--timeout=*)
            TIMEOUT="${1#*=}"
            shift
            ;;
        -f|--hostfile)
            if [ -z "${2:-}" ] || [[ "$2" == -* ]]; then
                echo "[-] Error: $1 requires an argument." >&2
                exit 1
            fi
            HOSTFILE="$2"
            shift 2
            ;;
        -f=*|--hostfile=*)
            HOSTFILE="${1#*=}"
            shift
            ;;
        -n|--nodes)
            if [ -z "${2:-}" ] || [[ "$2" == -* ]]; then
                echo "[-] Error: $1 requires an argument." >&2
                exit 1
            fi
            GENERATE_NODES="$2"
            shift 2
            ;;
        -n=*|--nodes=*)
            GENERATE_NODES="${1#*=}"
            shift
            ;;
        -H|--host)
            if [ -z "${2:-}" ] || [[ "$2" == -* ]]; then
                echo "[-] Error: $1 requires an argument." >&2
                exit 1
            fi
            GENERATE_HOST="$2"
            shift 2
            ;;
        -H=*|--host=*)
            GENERATE_HOST="${1#*=}"
            shift
            ;;
        --test)
            RUN_TEST=true
            shift
            ;;
        -h|--help)
            cat << 'EOF'
Usage: ./scripts/run_local_http.sh [options]

Orchestrate a local multi-process Ifrit HTTP test cluster on this machine
using a TOML hostfile, and optionally run the black-box dissemination test suite.

NOTE: This script is strictly for local simulation/testing on a single machine.
Remote multi-host cluster deployment (via SSH / Docker / Kubernetes) is handled
separately.

Options:
  -f, --hostfile <FILE>   Path to local TOML hostfile defining [ca-authority] and [[nodes]]
                          (default: examples/http_dissemination/cluster_local.toml).
  -n, --nodes <N>         Dynamically generate an ephemeral local hostfile with N nodes.
  -H, --host <HOST>       Local bind address for dynamic hostfile generation (default: 127.0.0.1).
  -i, --items <N>         Number of unique items to inject per node during --test (default: 2).
  -t, --timeout <SEC>     Max seconds to wait for network convergence during --test (default: 25.0).
  --test                  Launch local cluster, execute black-box dissemination test, and exit.
  -h, --help              Display this help message and exit.

Hostfile Format Example (TOML):
  [ca-authority]
  host = "127.0.0.1"
  port = 8321

  [[nodes]]
  host = "127.0.0.1"
  http_port = 8081
  tcp_port = 9000
  udp_port = 9001

Examples:
  1. Launch and run black-box test against default hostfile:
     ./scripts/run_local_http.sh --test

  2. Launch and test against custom hostfile:
     ./scripts/run_local_http.sh --hostfile my_cluster.toml --test

  3. Launch 5 nodes dynamically and run test:
     ./scripts/run_local_http.sh -n 5 --test
EOF
            exit 0
            ;;
        *)
            echo "[-] Unknown option: $1" >&2
            echo "    Run './scripts/run_local_http.sh --help' for usage." >&2
            exit 1
            ;;
    esac
done

PIDS=()
CLEANUP_DIRS=()

cleanup() {
    echo ""
    echo "[*] Cleaning up cluster processes and temp state..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true

    for dir in "${CLEANUP_DIRS[@]}"; do
        rm -rf "$dir" 2>/dev/null || true
    done
    echo "[+] Cleaned up all processes."
}
trap cleanup EXIT INT TERM

# If dynamic node generation requested, create ephemeral TOML hostfile
if [ "$GENERATE_NODES" -ge 2 ]; then
    TMP_HOSTFILE=$(mktemp /tmp/ifrit-hostfile-XXXXXX.toml)
    CLEANUP_DIRS+=("$TMP_HOSTFILE")

    cat << EOF > "$TMP_HOSTFILE"
[ca-authority]
host = "${GENERATE_HOST}"
port = 8321

EOF

    for ((i = 1; i <= GENERATE_NODES; i++)); do
        H_PORT=$((8080 + i))
        T_PORT=$((9000 + (i - 1) * 2))
        U_PORT=$((9001 + (i - 1) * 2))
        cat << EOF >> "$TMP_HOSTFILE"
[[nodes]]
host = "${GENERATE_HOST}"
http_port = ${H_PORT}
tcp_port = ${T_PORT}
udp_port = ${U_PORT}

EOF
    done
    HOSTFILE="$TMP_HOSTFILE"
fi

if [ ! -f "$HOSTFILE" ]; then
    echo "[-] Error: Hostfile '$HOSTFILE' does not exist." >&2
    exit 1
fi

# 1. Parse CA config
read -r CA_HOST CA_PORT <<< "$("${REPO_ROOT}/scripts/parse_hostfile.py" "$HOSTFILE" --ca)"
CA_ADDR="${CA_HOST}:${CA_PORT}"

echo "=========================================="
echo " Starting Local Multi-Process Ifrit Cluster"
echo " Hostfile: ${HOSTFILE}"
echo " CA Address: ${CA_ADDR}"
echo "=========================================="

# 2. Build binaries
echo "[*] Building CA and HTTP Node binaries..."
go build -o /tmp/ifrit-ca ./cmd/ca
go build -o /tmp/ifrit-http-node ./examples/http_dissemination

CA_DIR=$(mktemp -d /tmp/ifrit-ca-http-XXXXXX)
CLEANUP_DIRS+=("$CA_DIR")

# 3. Start CA daemon
echo "[*] Starting CA daemon on ${CA_ADDR}..."
/tmp/ifrit-ca -new -path "$CA_DIR" -host "$CA_HOST" -port "$CA_PORT" > "$CA_DIR/ca.log" 2>&1 &
CA_PID=$!
PIDS+=("$CA_PID")

# Wait for CA listener to become ready
echo -n "[*] Waiting for CA listener..."
READY=false
for i in {1..50}; do
    if ! kill -0 "$CA_PID" 2>/dev/null; then
        echo " (CA process exited unexpectedly!)"
        break
    fi
    if python3 -c "import socket; socket.create_connection(('${CA_HOST}', int('${CA_PORT}')), timeout=0.1)" 2>/dev/null; then
        READY=true
        break
    fi
    sleep 0.1
done

if [ "$READY" = false ]; then
    echo " FAILED"
    echo "[-] CA daemon failed to bind ${CA_ADDR}"
    if [ -f "$CA_DIR/ca.log" ]; then
        echo "[-] CA log output:"
        cat "$CA_DIR/ca.log"
    fi
    exit 1
fi
echo " READY"

# 4. Parse nodes and launch processes
NODE_HTTP_ADDRS=()
NODE_INDEX=1

while read -r N_HOST N_HTTP N_TCP N_UDP; do
    [ -z "$N_HOST" ] && continue

    NODE_DIR=$(mktemp -d "/tmp/ifrit-node-${NODE_INDEX}-XXXXXX")
    CLEANUP_DIRS+=("$NODE_DIR")
    HTTP_ENDPOINT="${N_HOST}:${N_HTTP}"
    NODE_HTTP_ADDRS+=("$HTTP_ENDPOINT")

    echo "[*] Starting Node ${NODE_INDEX} (Host: ${N_HOST}, HTTP: ${N_HTTP}, RPC: ${N_TCP}, UDP: ${N_UDP})..."
    IFRIT_CONFIG="${NODE_DIR}/ifrit_config.yaml" /tmp/ifrit-http-node \
        -hostname "${N_HOST}" \
        -http-port "${N_HTTP}" \
        -tcp-port "${N_TCP}" \
        -udp-port "${N_UDP}" \
        -ca-addr "${CA_ADDR}" \
        -crypto-dir "${NODE_DIR}" \
        -gossip-interval 1 > /dev/null 2>&1 &
    PID=$!
    PIDS+=("$PID")

    NODE_INDEX=$((NODE_INDEX + 1))
done < <("${REPO_ROOT}/scripts/parse_hostfile.py" "$HOSTFILE" --nodes)

# 5. Wait for all HTTP nodes to become healthy
echo -n "[*] Waiting for all HTTP nodes to become healthy..."
ALL_HEALTHY=false
for attempt in {1..50}; do
    HEALTHY_COUNT=0
    for addr in "${NODE_HTTP_ADDRS[@]}"; do
        if curl -s -f "http://${addr}/health" > /dev/null 2>&1; then
            HEALTHY_COUNT=$((HEALTHY_COUNT + 1))
        fi
    done
    if [ "$HEALTHY_COUNT" -eq "${#NODE_HTTP_ADDRS[@]}" ]; then
        ALL_HEALTHY=true
        break
    fi
    sleep 0.2
done

if [ "$ALL_HEALTHY" = false ]; then
    echo " FAILED"
    echo "[-] One or more HTTP nodes failed to become healthy."
    exit 1
fi
echo " READY"

HTTP_CSV=$(IFS=,; echo "${NODE_HTTP_ADDRS[*]}")

if [ "$RUN_TEST" = true ]; then
    echo "=========================================="
    echo " Running Pluggable End-to-End Test"
    echo "=========================================="
    TEST_CMD=(python3 "${REPO_ROOT}/examples/http_dissemination/test_dissemination.py" --hostfile "${HOSTFILE}")
    if [ -n "$ITEMS" ]; then
        TEST_CMD+=("--items" "$ITEMS")
    fi
    if [ -n "$TIMEOUT" ]; then
        TEST_CMD+=("--timeout" "$TIMEOUT")
    fi
    "${TEST_CMD[@]}"
    TEST_EXIT=$?
    exit $TEST_EXIT
fi

echo "=========================================="
echo " Cluster is running and ready for testing!"
echo " Nodes: ${HTTP_CSV}"
echo ""
echo " Run black-box tests against the hostfile in another terminal:"
echo "   python3 examples/http_dissemination/test_dissemination.py --hostfile ${HOSTFILE}"
echo ""
echo " Or test via curl:"
echo "   curl -X POST http://${NODE_HTTP_ADDRS[0]}/items -H 'Content-Type: application/json' -d '{\"item\":\"uuid-01\"}'"
if [ "${#NODE_HTTP_ADDRS[@]}" -ge 2 ]; then
    echo "   curl http://${NODE_HTTP_ADDRS[1]}/items"
fi
echo " Press Ctrl+C to stop."
echo "=========================================="

wait -n "${PIDS[@]}" 2>/dev/null || wait
