#!/usr/bin/env bash
# experiments/pumba-chaos-manager.sh
# Standalone, pluggable chaos and fault injection manager using Pumba / Docker API.
# Can be run independently, called by run-experiments.sh, or driven by a GUI/API.

set -euo pipefail

# Supported options exported for dynamic introspection by parent runners
SUPPORTED_OPTIONS="delay:val jitter:val loss:val corrupt:val chaos-interval:val chaos-duration:val log-level:val pause-node:val pause-at:val pause-duration:val kill-node:val kill-signal:val kill-at:val stop-node:val stop-at:val target:val interface:val random:bool"

if [[ "${1:-}" == "--list-options" ]]; then
    echo "$SUPPORTED_OPTIONS"
    exit 0
fi

show_help() {
    cat << 'EOF'
Pumba Chaos Manager
================================================================================
Independent chaos injection daemon for Docker container networks.
Supports both network emulation (Netem) and container lifecycle faults (Crash/Revive).

Usage:
  ./pumba-chaos-manager.sh [options]

Network Chaos (Netem):
  --delay <ms>              Network latency to inject in milliseconds
  --jitter <ms>             Latency jitter in milliseconds
  --loss <%>                Packet loss percentage (e.g. 10)
  --corrupt <%>             Packet corruption percentage
  --chaos-interval <dur>    Interval between chaos periods (e.g. 1m, 30s; default: 1m)
  --chaos-duration <dur>    Duration of each chaos period (e.g. 55s, 25s; default: 55s)
  --interface <iface>       Interface to apply netem on inside containers (default: eth0)

Container Crash / Lifecycle Faults:
  --pause-node <target>     Target container to pause/freeze (e.g. gossip-node-1 or 'random')
  --pause-at <dur>          Delay before pausing container (e.g. 15s to allow cluster convergence)
  --pause-duration <dur>    How long container remains paused before auto-revival (default: 15s)
  --kill-node <target>      Target container to kill
  --kill-signal <sig>       Signal to send on kill (default: SIGKILL)
  --kill-at <dur>           Delay before killing container
  --stop-node <target>      Target container to stop gracefully
  --stop-at <dur>           Delay before stopping container

General Options:
  --target <pattern>        Target regex for netem (default: "re2:.*gossip-node.*")
  --random                  Pick a single random container from the matching set
  --log-level <level>       Log level for Pumba daemon (debug, info, warning; default: info)
  --list-options            Print machine-readable list of supported options
  -h, --help                Show this help message
================================================================================
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    show_help
    exit 0
fi

# Default parameters
TARGET="re2:.*gossip-node.*"
INTERFACE="eth0"
DELAY_MS=""
JITTER_MS=""
LOSS_PERCENT=""
CORRUPT_PERCENT=""
CHAOS_INTERVAL="1m"
CHAOS_DURATION="55s"
RANDOM_TARGET=false
LOG_LEVEL="info"

PAUSE_NODE=""
PAUSE_AT="0s"
PAUSE_DURATION="15s"

KILL_NODE=""
KILL_AT="0s"
KILL_SIGNAL="SIGKILL"

STOP_NODE=""
STOP_AT="0s"

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --delay) DELAY_MS="$2"; shift 2 ;;
        --delay=*) DELAY_MS="${1#*=}"; shift ;;
        --jitter) JITTER_MS="$2"; shift 2 ;;
        --jitter=*) JITTER_MS="${1#*=}"; shift ;;
        --loss) LOSS_PERCENT="$2"; shift 2 ;;
        --loss=*) LOSS_PERCENT="${1#*=}"; shift ;;
        --corrupt) CORRUPT_PERCENT="$2"; shift 2 ;;
        --corrupt=*) CORRUPT_PERCENT="${1#*=}"; shift ;;
        --chaos-interval) CHAOS_INTERVAL="$2"; shift 2 ;;
        --chaos-interval=*) CHAOS_INTERVAL="${1#*=}"; shift ;;
        --chaos-duration) CHAOS_DURATION="$2"; shift 2 ;;
        --chaos-duration=*) CHAOS_DURATION="${1#*=}"; shift ;;
        --interface) INTERFACE="$2"; shift 2 ;;
        --interface=*) INTERFACE="${1#*=}"; shift ;;
        --target) TARGET="$2"; shift 2 ;;
        --target=*) TARGET="${1#*=}"; shift ;;
        --random) RANDOM_TARGET=true; shift ;;
        --log-level) LOG_LEVEL="$2"; shift 2 ;;
        --log-level=*) LOG_LEVEL="${1#*=}"; shift ;;

        --pause-node) PAUSE_NODE="$2"; shift 2 ;;
        --pause-node=*) PAUSE_NODE="${1#*=}"; shift ;;
        --pause-at) PAUSE_AT="$2"; shift 2 ;;
        --pause-at=*) PAUSE_AT="${1#*=}"; shift ;;
        --pause-duration) PAUSE_DURATION="$2"; shift 2 ;;
        --pause-duration=*) PAUSE_DURATION="${1#*=}"; shift ;;

        --kill-node) KILL_NODE="$2"; shift 2 ;;
        --kill-node=*) KILL_NODE="${1#*=}"; shift ;;
        --kill-at) KILL_AT="$2"; shift 2 ;;
        --kill-at=*) KILL_AT="${1#*=}"; shift ;;
        --kill-signal) KILL_SIGNAL="$2"; shift 2 ;;
        --kill-signal=*) KILL_SIGNAL="${1#*=}"; shift ;;

        --stop-node) STOP_NODE="$2"; shift 2 ;;
        --stop-node=*) STOP_NODE="${1#*=}"; shift ;;
        --stop-at) STOP_AT="$2"; shift 2 ;;
        --stop-at=*) STOP_AT="${1#*=}"; shift ;;

        -h|--help) show_help; exit 0 ;;
        *)
            echo "Error: Unknown chaos option '$1'" >&2
            echo "Run '$0 --help' for available options." >&2
            exit 1
            ;;
    esac
done

CHILD_PIDS=()
PUMBA_CONTAINER="ifrit-pumba-runtime-$$"

cleanup() {
    # Terminate background subshells
    if [ ${#CHILD_PIDS[@]} -gt 0 ]; then
        for pid in "${CHILD_PIDS[@]}"; do
            kill -TERM "$pid" 2>/dev/null || true
        done
    fi
    # Stop Pumba docker container if running
    docker stop "$PUMBA_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$PUMBA_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Helper: parse duration string (e.g. 15s, 1m) to sleep seconds
parse_dur_seconds() {
    local dur="$1"
    if [[ "$dur" =~ ^[0-9]+$ ]]; then
        echo "$dur"
        return
    fi
    local total=0
    while [[ "$dur" =~ ([0-9]+)([smhd]) ]]; do
        local num="${BASH_REMATCH[1]}"
        local unit="${BASH_REMATCH[2]}"
        case "$unit" in
            s) total=$((total + num)) ;;
            m) total=$((total + num * 60)) ;;
            h) total=$((total + num * 3600)) ;;
            d) total=$((total + num * 86400)) ;;
        esac
        dur="${dur#*"${BASH_REMATCH[0]}"}"
    done
    echo "$total"
}

# -----------------------------------------------------------------------------
# 1. Container Lifecycle / Crash Fault Execution
# -----------------------------------------------------------------------------
if [ -n "$PAUSE_NODE" ]; then
    (
        delay_sec=$(parse_dur_seconds "$PAUSE_AT")
        if [ "$delay_sec" -gt 0 ]; then
            echo "[Chaos Manager] Waiting ${delay_sec}s before injecting pause fault..."
            sleep "$delay_sec"
        fi

        target_container="$PAUSE_NODE"
        if [ "$target_container" == "random" ]; then
            # Pick a live gossip-node at random
            target_container=$(docker compose ps -q gossip-node 2>/dev/null | shuf -n 1 || true)
            if [ -z "$target_container" ]; then
                target_container=$(docker ps --filter "name=gossip-node" -q | shuf -n 1 || true)
            fi
        fi

        if [ -n "$target_container" ]; then
            cname=$(docker inspect --format '{{.Name}}' "$target_container" 2>/dev/null | tr -d '/' || echo "$target_container")
            echo "[Chaos Manager] ⏸️ Pausing container $cname for $PAUSE_DURATION..."
            docker pause "$target_container" >/dev/null 2>&1 || true

            pause_sec=$(parse_dur_seconds "$PAUSE_DURATION")
            sleep "$pause_sec"

            echo "[Chaos Manager] ▶️ Reviving (unpausing) container $cname..."
            docker unpause "$target_container" >/dev/null 2>&1 || true
        else
            echo "[Chaos Manager] Warning: No target container found to pause."
        fi
    ) &
    CHILD_PIDS+=($!)
fi

if [ -n "$KILL_NODE" ]; then
    (
        delay_sec=$(parse_dur_seconds "$KILL_AT")
        if [ "$delay_sec" -gt 0 ]; then
            sleep "$delay_sec"
        fi
        target_container="$KILL_NODE"
        if [ "$target_container" == "random" ]; then
            target_container=$(docker compose ps -q gossip-node 2>/dev/null | shuf -n 1 || true)
        fi
        if [ -n "$target_container" ]; then
            cname=$(docker inspect --format '{{.Name}}' "$target_container" 2>/dev/null | tr -d '/' || echo "$target_container")
            echo "[Chaos Manager] 💥 Killing container $cname with signal $KILL_SIGNAL..."
            docker kill --signal "$KILL_SIGNAL" "$target_container" >/dev/null 2>&1 || true
        fi
    ) &
    CHILD_PIDS+=($!)
fi

# -----------------------------------------------------------------------------
# 2. Network Emulation (Netem via Pumba)
# -----------------------------------------------------------------------------
NETEM_EFFECTS=0
[ -n "$DELAY_MS" ] && NETEM_EFFECTS=$((NETEM_EFFECTS + 1))
[ -n "$LOSS_PERCENT" ] && NETEM_EFFECTS=$((NETEM_EFFECTS + 1))
[ -n "$CORRUPT_PERCENT" ] && NETEM_EFFECTS=$((NETEM_EFFECTS + 1))

if [ "$NETEM_EFFECTS" -gt 0 ]; then
    # Validate interval vs duration: Pumba requires duration < interval
    if [ -n "$CHAOS_INTERVAL" ] && [ -n "$CHAOS_DURATION" ]; then
        int_sec=$(parse_dur_seconds "$CHAOS_INTERVAL")
        dur_sec=$(parse_dur_seconds "$CHAOS_DURATION")
        if [ "$dur_sec" -ge "$int_sec" ]; then
            adjusted_sec=$((dur_sec + 5))
            echo "[Chaos Manager] ℹ️  Adjusting --chaos-interval to ${adjusted_sec}s (must be strictly greater than --chaos-duration ${CHAOS_DURATION})"
            CHAOS_INTERVAL="${adjusted_sec}s"
        fi
    fi

    # Global options for Pumba (must precede command)
    PUMBA_RUN_ARGS=(
        "--log-level" "$LOG_LEVEL"
    )
    if [ -n "$CHAOS_INTERVAL" ]; then
        PUMBA_RUN_ARGS+=("--interval" "$CHAOS_INTERVAL")
    fi
    if [ "$RANDOM_TARGET" = true ]; then
        PUMBA_RUN_ARGS+=("--random")
    fi

    # Construct Pumba netem command:
    # When multiple effects are specified (e.g. delay AND loss), Pumba requires the 'combine' subcommand.
    if [ "$NETEM_EFFECTS" -gt 1 ]; then
        PUMBA_CMD=("netem" "--interface" "$INTERFACE" "--duration" "$CHAOS_DURATION" "combine")
        if [ -n "$DELAY_MS" ]; then
            PUMBA_CMD+=("--delay" "--delay-time" "$DELAY_MS")
            if [ -n "$JITTER_MS" ]; then
                PUMBA_CMD+=("--delay-jitter" "$JITTER_MS")
            fi
        fi
        if [ -n "$LOSS_PERCENT" ]; then
            PUMBA_CMD+=("--loss" "--loss-percent" "$LOSS_PERCENT")
        fi
        if [ -n "$CORRUPT_PERCENT" ]; then
            PUMBA_CMD+=("--corrupt" "--corrupt-percent" "$CORRUPT_PERCENT")
        fi
        PUMBA_CMD+=("--" "$TARGET")
    else
        PUMBA_CMD=("netem" "--interface" "$INTERFACE" "--duration" "$CHAOS_DURATION")
        if [ -n "$DELAY_MS" ]; then
            PUMBA_CMD+=("delay" "--time" "$DELAY_MS")
            if [ -n "$JITTER_MS" ]; then
                PUMBA_CMD+=("--jitter" "$JITTER_MS")
            fi
        elif [ -n "$LOSS_PERCENT" ]; then
            PUMBA_CMD+=("loss" "--percent" "$LOSS_PERCENT")
        elif [ -n "$CORRUPT_PERCENT" ]; then
            PUMBA_CMD+=("corrupt" "--percent" "$CORRUPT_PERCENT")
        fi
        PUMBA_CMD+=("$TARGET")
    fi

    echo "[Chaos Manager] 🌪️ Starting network chaos daemon on $TARGET (interface: $INTERFACE)..."
    [ -n "$DELAY_MS" ] && echo "  - Delay: ${DELAY_MS}ms (jitter: ${JITTER_MS:-0}ms)"
    [ -n "$LOSS_PERCENT" ] && echo "  - Packet loss: ${LOSS_PERCENT}%"
    [ -n "$CORRUPT_PERCENT" ] && echo "  - Packet corruption: ${CORRUPT_PERCENT}%"
    echo "  - Period: duration=${CHAOS_DURATION}, interval=${CHAOS_INTERVAL}"

    docker rm -f "$PUMBA_CONTAINER" >/dev/null 2>&1 || true

    docker run --rm \
        --name "$PUMBA_CONTAINER" \
        -v /var/run/docker.sock:/var/run/docker.sock \
        gaiaadm/pumba:latest \
        "${PUMBA_RUN_ARGS[@]}" \
        "${PUMBA_CMD[@]}" &
    PUMBA_PID=$!
    CHILD_PIDS+=("$PUMBA_PID")

    # Background watchdog: verify Pumba doesn't immediately exit
    (
        sleep 1
        if ! kill -0 "$PUMBA_PID" 2>/dev/null; then
            echo "[Chaos Manager] ⚠️ Error: Pumba container process exited unexpectedly!" >&2
        fi
    ) &
    CHILD_PIDS+=($!)
fi

# Wait for all background tasks
wait
