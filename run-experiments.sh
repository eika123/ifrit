#!/usr/bin/env bash

RED=$'\033[1;31m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

# Locate optional pluggable chaos manager
CHAOS_MANAGER=""
if [ -f "experiments/pumba-chaos-manager.sh" ]; then
    CHAOS_MANAGER="experiments/pumba-chaos-manager.sh"
elif [ -f "./pumba-chaos-manager.sh" ]; then
    CHAOS_MANAGER="./pumba-chaos-manager.sh"
fi

CHAOS_SUPPORTED_OPTS=""
if [ -n "$CHAOS_MANAGER" ]; then
    CHAOS_SUPPORTED_OPTS=$("$CHAOS_MANAGER" --list-options 2>/dev/null || true)
fi

is_chaos_opt() {
    local opt="$1"
    for pair in $CHAOS_SUPPORTED_OPTS; do
        if [[ "$pair" == "$opt:val" ]]; then
            echo "val"
            return 0
        elif [[ "$pair" == "$opt:bool" ]]; then
            echo "bool"
            return 0
        fi
    done
    return 1
}

show_help() {
    cat << EOF
Ifrit Experiment Runner
================================================================================================
Orchestrates Ifrit distributed experiments over Docker container networks,
tracks container resource usage, coordinates pluggable network & lifecycle chaos,
merges SQLite telemetry databases, and generates plots.

Usage:
  ./run-experiments.sh [runner options] [chaos options] <experiment-script.sh> [script_args...]
-------------------------------------------------------------------------------------------------
Runner Options:
  --docker-activate         Run experiment inside a dedicated Docker container
  -b, --build               Rebuild Docker images before starting
  -t, --duration <dur>      Experiment run duration (e.g. 40s, 5m, 1h). Default: indefinite
  -c, --checkpoint-interval Sampling interval for resource usage (e.g. 5s)
  -f, --compose-file <file> Override default docker-compose file
  --teardown-grace-period   Seconds to wait before killing containers (default: 10s)
  -r, --rings <count>       Number of rings in Fireflies topology (default: 3)
  -h, --help                Show this help message

Examples:
  ./run-experiments.sh -t 40s -c 5s gossip-experiment.sh 10
  ./run-experiments.sh -t 2m --delay 500 --loss 10 gossip-experiment.sh 5
  ./run-experiments.sh -t 2m --pause-node random --pause-duration 15s gossip-experiment.sh 5
=================================================================================================
EOF

    if [ -n "$CHAOS_MANAGER" ]; then
        echo ""
        echo "Active Chaos Manager: $CHAOS_MANAGER"
        echo "(All options below are dynamically accepted and forwarded to $CHAOS_MANAGER):"
        echo "-------------------------------------------------------------------------------------------------"
        "$CHAOS_MANAGER" --help
    else
        echo ""
        echo "Note: No chaos manager detected (e.g. experiments/pumba-chaos-manager.sh)."
    fi
}

usage() {
    echo "Usage: $0 [runner options] [chaos options] <experiment-script.sh> [script_args...]"
    echo "Run '$0 --help' for available options."
}

CONTAINER_NAME="go-experiment-runner"
OUTPUT_DIR="$(pwd)/experiment_results"
mkdir -p "$OUTPUT_DIR"

# Parse flags
DOCKER_MODE=false
BUILD_MODE=false
EXPERIMENT_DURATION=""
CUSTOM_COMPOSE_FILE=""
TEARDOWN_GRACE_PERIOD="${TEARDOWN_GRACE_PERIOD:-10}"
CHAOS_ARGS=()

while [[ "$1" == --* || "$1" == -* ]]; do
    case "$1" in
        --docker-activate)
            DOCKER_MODE=true
            shift
            ;;
        -b|--build)
            BUILD_MODE=true
            shift
            ;;
        -t|--duration)
            EXPERIMENT_DURATION="$2"
            shift 2
            ;;
        --duration=*)
            EXPERIMENT_DURATION="${1#*=}"
            shift
            ;;
        -c|--checkpoint-interval)
            CHECKPOINT_INTERVAL="$2"
            shift 2
            ;;
        --checkpoint-interval=*)
            CHECKPOINT_INTERVAL="${1#*=}"
            shift
            ;;
        -f|--compose-file)
            CUSTOM_COMPOSE_FILE="$2"
            shift 2
            ;;
        --compose-file=*)
            CUSTOM_COMPOSE_FILE="${1#*=}"
            shift
            ;;
        --teardown-grace-period)
            TEARDOWN_GRACE_PERIOD="$2"
            shift 2
            ;;
        --teardown-grace-period=*)
            TEARDOWN_GRACE_PERIOD="${1#*=}"
            shift
            ;;
        -r|--rings)
            export RINGS="$2"
            shift 2
            ;;
        --rings=*)
            export RINGS="${1#*=}"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            # Check if this flag is accepted dynamically by the chaos manager
            opt_raw="${1#--}"
            opt_raw="${opt_raw#-}"
            opt_key="${opt_raw%%=*}"
            kind=$(is_chaos_opt "$opt_key" || true)

            if [ "$kind" = "val" ]; then
                if [[ "$1" == *=* ]]; then
                    CHAOS_ARGS+=("$1")
                    shift
                else
                    if [ $# -lt 2 ]; then
                        echo "${RED}Error:${NC} Chaos option '$1' requires a value." >&2
                        exit 1
                    fi
                    CHAOS_ARGS+=("$1" "$2")
                    shift 2
                fi
            elif [ "$kind" = "bool" ]; then
                CHAOS_ARGS+=("$1")
                shift
            else
                echo "${RED}Error:${NC} Unknown option '$1'" >&2
                echo "" >&2
                show_help >&2
                exit 1
            fi
            ;;
    esac
done

# Helper to parse human durations (e.g., 55s, 1m, 2h) to seconds
parse_duration_to_seconds() {
    local dur="$1"
    local total=0
    # Match combinations like 1h30m, 5m, 55s
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

# Export checkpoint interval if specified
if [ -n "$CHECKPOINT_INTERVAL" ]; then
    export IFRIT_TELEMETRY_CHECKPOINT_INTERVAL="$CHECKPOINT_INTERVAL"
    echo "Using telemetry checkpoint interval: $IFRIT_TELEMETRY_CHECKPOINT_INTERVAL"
fi

# Set and export COMPOSE_FILE environment variable for docker compose
if [ -n "$CUSTOM_COMPOSE_FILE" ]; then
    export COMPOSE_FILE="$CUSTOM_COMPOSE_FILE"
elif [ -f "docker-compose.experiments.yml" ]; then
    export COMPOSE_FILE="docker-compose.experiments.yml"
fi

if [ -n "$COMPOSE_FILE" ]; then
    echo "Using Compose configuration: $COMPOSE_FILE"
fi

# The next argument must be the experiment-script/command
EXPERIMENT_SCRIPT="$1"

if [ -z "$EXPERIMENT_SCRIPT" ]; then
    echo "${RED}Error:${NC} You must specify which experiment-script to run!" >&2
    echo "Usage: $0 [--docker-activate] [-t <duration>] [-f <compose-file>] <experiment-script.sh> [script_args...]" >&2
    exit 1
fi

shift # Remove the script name from the argument list

# Resolve script path (check current directory, experiments/ directory, or absolute path)
if [ -f "$EXPERIMENT_SCRIPT" ]; then
    SCRIPT_PATH="./$EXPERIMENT_SCRIPT"
elif [ -f "experiments/$EXPERIMENT_SCRIPT" ]; then
    SCRIPT_PATH="./experiments/$EXPERIMENT_SCRIPT"
else
    echo "${RED}Error:${NC} Could not find experiment script '$EXPERIMENT_SCRIPT' (checked . and ./experiments)" >&2
    exit 1
fi

if [ ! -x "$SCRIPT_PATH" ]; then
    echo "Making $SCRIPT_PATH executable..."
    chmod +x "$SCRIPT_PATH"
fi

# =====================================================================
# Check that SQLITE3 is installed
# =====================================================================
if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "sqlite3 was not found on the system. Installing..."
    sudo apt-get update && sudo apt-get install -y sqlite3
    if [ $? -ne 0 ]; then
        echo "${RED}Error:${NC} Could not install sqlite3. Aborting experiment." >&2
        exit 1
    fi
fi

# Detect original user if run with sudo
REAL_USER="${SUDO_USER:-$USER}"
REAL_GROUP="$(id -gn "$REAL_USER" 2>/dev/null || echo "$REAL_USER")"

cleanup() {
    # Disable trap during cleanup to prevent recursive signal handling
    trap - EXIT INT TERM
    
    # Terminate experiment process if still running
    if [ -n "$EXP_PID" ]; then
        kill -TERM "$EXP_PID" 2>/dev/null
        wait "$EXP_PID" 2>/dev/null
    fi

    # Terminate chaos manager if still running
    if [ -n "${CHAOS_PID:-}" ]; then
        kill -TERM "$CHAOS_PID" 2>/dev/null || true
        wait "$CHAOS_PID" 2>/dev/null || true
    fi

    # Capture container IP -> human-readable container name mapping before teardown
    DOCKER_DNS_FILE="$OUTPUT_DIR/docker_dns.txt"
    if [ ! -f "$DOCKER_DNS_FILE" ] && docker compose ps -q >/dev/null 2>&1; then
        docker compose ps -q 2>/dev/null | xargs -r docker inspect \
            --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} {{.Name}}' > "$DOCKER_DNS_FILE" 2>/dev/null || true
    fi

    # Stop active docker compose containers cleanly
    docker compose down --volumes --remove-orphans 2>/dev/null || true

    # Stop the stats-logger whatever the mode if it was started
    if [ -n "$STATS_PID" ]; then
        kill -9 "$STATS_PID" 2>/dev/null
        wait "$STATS_PID" 2>/dev/null
    fi

    # Fix ownership of output artifacts and virtual environment so non-root user can view/edit/delete them
    if [ -n "$REAL_USER" ]; then
        if [ -d "$OUTPUT_DIR" ]; then
            chown -R "$REAL_USER:$REAL_GROUP" "$OUTPUT_DIR" 2>/dev/null || true
            chmod -R u+rwX,go+rX "$OUTPUT_DIR" 2>/dev/null || true
        fi
        if [ -d "experiments/.venv" ]; then
            chown -R "$REAL_USER:$REAL_GROUP" "experiments/.venv" 2>/dev/null || true
        fi
        if [ -d "experiments/observer" ]; then
            chown -R "$REAL_USER:$REAL_GROUP" "experiments/observer" 2>/dev/null || true
        fi
    fi

    # ONLY if we started Docker specifically for this experiment
    if [ "$DOCKER_MODE" = true ]; then
        echo -e "\nStopping Docker-daemon and containerd..."
        sudo systemctl stop docker containerd docker.socket
        echo "The machine is cleaned up for on-demand Docker-processes."
    fi
}

# Register trap for secure termination
trap cleanup EXIT INT TERM

# =====================================================================
# Start Docker (if on-demand)
# =====================================================================
if [ "$DOCKER_MODE" = true ]; then
    echo "On-Demand Mode: Activating Docker-daemon..."
    sudo systemctl start docker
else
    echo "Standard Mode: Using existing Docker-environment..."
fi

# =====================================================================
# Recursive Build Mode (eBPF code generation + Docker Compose images)
# =====================================================================
if [ "$BUILD_MODE" = true ]; then
    echo "====================================================================="
    echo "Build Mode: Recursively building eBPF bytecode and Docker images..."
    echo "====================================================================="
    if command -v go >/dev/null 2>&1 || [ -x "/usr/local/go/bin/go" ]; then
        GO_BIN="$(command -v go || echo "/usr/local/go/bin/go")"
        echo "1/2: Generating eBPF bytecode using $GO_BIN generate..."
        PATH="$PATH:/usr/local/go/bin:$HOME/go/bin" "$GO_BIN" generate ./experiments/observer
    else
        echo "Notice: go binary not found on PATH; using pre-generated BPF objects."
    fi

    echo "2/2: Building all Docker images in ${COMPOSE_FILE:-docker-compose.experiments.yml}..."
    docker compose build --pull
    echo "Build complete!"
    echo "====================================================================="
fi

# =====================================================================
# Determine dynamic DB and plot names based on script & arguments
# =====================================================================
SCRIPT_BASE=$(basename "resource-usage-$EXPERIMENT_SCRIPT" .sh)
ARGS_SLUG=$(echo "$@" | tr -s ' ' '_' | tr -cd '[:alnum:]_-')

if [ -n "$EXPERIMENT_DURATION" ]; then
    DURATION_SLUG=$(echo "$EXPERIMENT_DURATION" | tr -cd '[:alnum:]')
    if [ -n "$ARGS_SLUG" ]; then
        EXP_IDENT="${SCRIPT_BASE}_${ARGS_SLUG}_${DURATION_SLUG}"
    else
        EXP_IDENT="${SCRIPT_BASE}_${DURATION_SLUG}"
    fi
else
    if [ -n "$ARGS_SLUG" ]; then
        EXP_IDENT="${SCRIPT_BASE}_${ARGS_SLUG}"
    else
        EXP_IDENT="${SCRIPT_BASE}"
    fi
fi

DB_FILE="$OUTPUT_DIR/${EXP_IDENT}.db"
PLOT_FILE="$OUTPUT_DIR/${EXP_IDENT}.png"

# Dynamic telemetry DB and plot for network observer
TELEMETRY_DB_NAME="network-telemetry_${EXP_IDENT#resource-usage-}.db"
TELEMETRY_PLOT_NAME="network-telemetry_${EXP_IDENT#resource-usage-}.png"
TELEMETRY_DB_FILE="$OUTPUT_DIR/$TELEMETRY_DB_NAME"
TELEMETRY_PLOT_FILE="$OUTPUT_DIR/$TELEMETRY_PLOT_NAME"
export TELEMETRY_DB="/results/$TELEMETRY_DB_NAME"

# Dynamic unified database for node-level gRPC gossip telemetry
GOSSIP_TELEMETRY_DB_NAME="gossip-telemetry_${EXP_IDENT#resource-usage-}.db"
GOSSIP_TELEMETRY_DB_FILE="$OUTPUT_DIR/$GOSSIP_TELEMETRY_DB_NAME"

# Backup database if an existing one is found
if [ -f "$DB_FILE" ]; then
    TIMESTAMP_BACKUP=$(date +%Y%m%d_%H%M%S)
    BACKUP_FILE="$OUTPUT_DIR/backup-${EXP_IDENT}_${TIMESTAMP_BACKUP}.db"
    echo "Existing database found at $DB_FILE. Creating backup at $BACKUP_FILE..."
    cp "$DB_FILE" "$BACKUP_FILE"
    # Remove existing db to start fresh for this new experiment run
    rm -f "$DB_FILE" "$DB_FILE-wal" "$DB_FILE-shm"
fi

if [ -f "$TELEMETRY_DB_FILE" ]; then
    TIMESTAMP_BACKUP=$(date +%Y%m%d_%H%M%S)
    BACKUP_FILE="$OUTPUT_DIR/backup-${TELEMETRY_DB_NAME%.db}_${TIMESTAMP_BACKUP}.db"
    echo "Existing telemetry DB found at $TELEMETRY_DB_FILE. Creating backup at $BACKUP_FILE..."
    cp "$TELEMETRY_DB_FILE" "$BACKUP_FILE"
    rm -f "$TELEMETRY_DB_FILE" "$TELEMETRY_DB_FILE-wal" "$TELEMETRY_DB_FILE-shm"
fi

echo "Using resource stats database: $DB_FILE"
echo "Using network telemetry database: $TELEMETRY_DB_FILE"
sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    container_name TEXT,
    cpu_perc REAL,
    mem_usage TEXT,
    mem_perc REAL
);"

# =====================================================================
# Start background logger (SQLITE-optimized)
# =====================================================================
echo "Starting time-series logging of resource usage for all containers to SQLite..."
(
    # Enable Write-Ahead Logging (WAL) for minimal I/O impact on the experiment
    sqlite3 "$DB_FILE" "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;" > /dev/null

    while true; do
        # 1. Get stats for all active containers in one single call
        # Format will be: 'name',cpu,'mem',mem%
        RAW_DATA=$(docker stats --no-stream --format "'{{.Name}}',{{.CPUPerc}},'{{.MemUsage}}',{{.MemPerc}}" 2>/dev/null)
        
        # Check if any containers are actually running at the moment
        if [ ! -z "$RAW_DATA" ]; then
            CURRENT_TIME=$(date +%H:%M:%S)
            
            # 2. Remove all '%'-symbols to ensure clean numerical values for SQLite
            CLEANED_DATA=$(echo "$RAW_DATA" | tr -d '%')
            
            # 3. Build a bulk SQL insert in memory with busy_timeout
            SQL_BULK="PRAGMA busy_timeout = 5000; BEGIN IMMEDIATE TRANSACTION;"
            while read -r row; do
                if [ ! -z "$row" ]; then
                    SQL_BULK="$SQL_BULK INSERT INTO stats (timestamp, container_name, cpu_perc, mem_usage, mem_perc) VALUES ('$CURRENT_TIME', $row);"
                fi
            done <<< "$CLEANED_DATA"
            SQL_BULK="$SQL_BULK COMMIT;"
            
            # 4. Send the whole batch to SQLite 
            echo "$SQL_BULK" | sqlite3 "$DB_FILE" 2>/dev/null
        fi
        
        sleep 1
    done
) &
STATS_PID=$!

# =====================================================================
# Run the experiment itself (lifecycle managed by runner)
# =====================================================================
# Start experiment script in its own process group/background
CHAOS_PID=""
"$SCRIPT_PATH" "$@" &
EXP_PID=$!

if [ -n "$EXPERIMENT_DURATION" ]; then
    echo "Waiting for containers to initialize before starting $EXPERIMENT_DURATION timer..."
    # Give compose a few seconds to finish image builds and spin up containers
    for i in {1..30}; do
        if docker compose ps -q gossip-node 2>/dev/null | grep -q .; then
            break
        fi
        sleep 1
    done

    # Start chaos manager if chaos arguments were provided
    if [ ${#CHAOS_ARGS[@]} -gt 0 ] && [ -n "$CHAOS_MANAGER" ]; then
        "$CHAOS_MANAGER" "${CHAOS_ARGS[@]}" &
        CHAOS_PID=$!
    fi

    echo "Running experiment (timer started: $EXPERIMENT_DURATION)..."
    sleep "$EXPERIMENT_DURATION" &
    SLEEP_PID=$!

    # Wait for whichever finishes first: the experiment script OR the sleep timer
    wait -n "$EXP_PID" "$SLEEP_PID" 2>/dev/null

    if kill -0 "$EXP_PID" 2>/dev/null; then
        echo "Duration limit ($EXPERIMENT_DURATION) reached. Stopping experiment..."
        # Stop chaos manager first so it does not attempt to attach to dying containers
        if [ -n "${CHAOS_PID:-}" ]; then
            kill -TERM "$CHAOS_PID" 2>/dev/null || true
            wait "$CHAOS_PID" 2>/dev/null || true
            CHAOS_PID=""
        fi
        # Capture container IP -> human-readable container name mapping before stopping
        DOCKER_DNS_FILE="$OUTPUT_DIR/docker_dns.txt"
        if [ ! -f "$DOCKER_DNS_FILE" ] && docker compose ps -q >/dev/null 2>&1; then
            docker compose ps -q 2>/dev/null | xargs -r docker inspect \
                --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} {{.Name}}' > "$DOCKER_DNS_FILE" 2>/dev/null || true
        fi
        # Stop containers with a generous 10s grace period for clean exit
        docker compose stop -t 10 >/dev/null 2>&1 || true
        kill -TERM "$EXP_PID" 2>/dev/null || true
        wait "$EXP_PID" 2>/dev/null || true
    else
        echo "Experiment finished before duration limit ($EXPERIMENT_DURATION)."
        if [ -n "${CHAOS_PID:-}" ]; then
            kill -TERM "$CHAOS_PID" 2>/dev/null || true
            wait "$CHAOS_PID" 2>/dev/null || true
            CHAOS_PID=""
        fi
        kill -9 "$SLEEP_PID" 2>/dev/null || true
        wait "$SLEEP_PID" 2>/dev/null || true
    fi
else
    for i in {1..30}; do
        if docker compose ps -q gossip-node 2>/dev/null | grep -q .; then
            break
        fi
        sleep 1
    done
    if [ ${#CHAOS_ARGS[@]} -gt 0 ] && [ -n "$CHAOS_MANAGER" ]; then
        "$CHAOS_MANAGER" "${CHAOS_ARGS[@]}" &
        CHAOS_PID=$!
    fi
    echo "Running experiment (indefinite, press Ctrl+C to stop and plot)..."
    wait "$EXP_PID" 2>/dev/null
    if [ -n "${CHAOS_PID:-}" ]; then
        kill -TERM "$CHAOS_PID" 2>/dev/null || true
        wait "$CHAOS_PID" 2>/dev/null || true
        CHAOS_PID=""
    fi
fi
unset EXP_PID

# Capture container IP -> human-readable container name mapping before teardown (if not captured yet)
DOCKER_DNS_FILE="$OUTPUT_DIR/docker_dns.txt"
if [ ! -f "$DOCKER_DNS_FILE" ] && docker compose ps -q >/dev/null 2>&1; then
    # fetch the docker id and use it to inspect the containers, redirecting ip-name pairs to the dns file
    docker compose ps -q 2>/dev/null | xargs -r docker inspect \
        -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} {{.Name}}" > "$DOCKER_DNS_FILE" 2>/dev/null || true
fi

# Best-effort container teardown  (clean up any remaining containers)
docker compose stop -t $TEARDOWN_GRACE_PERIOD >/dev/null 2>&1 || true
docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true

# Check if any uncheckpointed WAL files remain from telemetry or node databases.
# In a clean shutdown, each node closes its telemetry connection and folds its own WAL.
# Remaining WAL files indicate a node crashed, was killed abruptly, or failed to invoke Stop().
remaining_wals=()
for wal in "$OUTPUT_DIR"/*-wal; do
    if [ -f "$wal" ]; then
        remaining_wals+=("$wal")
    fi
done

if [ ${#remaining_wals[@]} -gt 0 ]; then
    echo "${YELLOW}⚠️  [WARNING]${NC} Uncheckpointed SQLite WAL file(s) detected after container teardown:"
    for wal in "${remaining_wals[@]}"; do
        wal_size=$(wc -c < "$wal" 2>/dev/null || stat -c%s "$wal" 2>/dev/null || echo "unknown")
        echo "    - $(basename "$wal") (size: ${wal_size} bytes)"
    done
    echo "    This indicates one or more nodes did not shut down cleanly or failed to close their telemetry database."
    echo "    Attempting recovery via fallback wal_checkpoint..."

    if command -v sqlite3 >/dev/null 2>&1; then
        for wal in "${remaining_wals[@]}"; do
            db="${wal%-wal}"
            if [ -f "$db" ]; then
                sqlite3 "$db" "PRAGMA wal_checkpoint(TRUNCATE);" 2>/dev/null || true
            fi
            rm -f "$wal" "${db}-shm"
        done
    else
        echo "    ${YELLOW}[NOTICE]${NC} 'sqlite3' CLI not found on host; leaving WAL files in place for python merge script."
    fi
fi

# Automatically merge per-node telemetry databases into a unified database
MERGE_SCRIPT=""
if [ -f "experiments/merge_gossip_telemetry.py" ]; then
    MERGE_SCRIPT="experiments/merge_gossip_telemetry.py"
elif [ -f "merge_gossip_telemetry.py" ]; then
    MERGE_SCRIPT="merge_gossip_telemetry.py"
fi

if [ -n "$MERGE_SCRIPT" ]; then
    echo "Merging per-node gossip telemetry databases into $GOSSIP_TELEMETRY_DB_FILE..."
    python3 "$MERGE_SCRIPT" -d "$OUTPUT_DIR" -o "$GOSSIP_TELEMETRY_DB_FILE" --cleanup
fi


# =====================================================================
# Generate plots. Installs uv if not present, and creates a virtual 
# environment inside experiments/.venv if not present.
# =====================================================================
PLOT_SCRIPT=""
if [ -f "experiments/plot_resource_usage.py" ]; then
    PLOT_SCRIPT="experiments/plot_resource_usage.py"
elif [ -f "plot_resource_usage.py" ]; then
    PLOT_SCRIPT="plot_resource_usage.py"
fi

if [ -n "$PLOT_SCRIPT" ]; then
    echo "Preparing Python environment for plotting ($PLOT_SCRIPT)..."

    # Ensure standard user binary locations are in PATH
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

    # 1. Check if uv is installed. If not, install it automatically.
    if ! command -v uv >/dev/null 2>&1; then
        echo "'uv' was not found in PATH. Installing 'uv' via the official installer..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        
        # Load uv into current session
        export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
        
        if ! command -v uv >/dev/null 2>&1; then
            echo "${YELLOW}⚠️  [WARNING]${NC} Could not install or find 'uv'. Skipping plotting."
            return 0 2>/dev/null || exit 0
        fi
    fi

    VENV_DIR="experiments/.venv"
    # 2. Create the virtual environment in experiments/.venv if it doesn't exist
    if [ ! -d "$VENV_DIR" ]; then
        echo "Creating a new virtual environment in $VENV_DIR with uv..."
        uv venv --quiet "$VENV_DIR"
    fi

    # 3. Install/ensure that matplotlib is available in the virtual environment
    uv pip install matplotlib --quiet --python "$VENV_DIR"

    # 4. Run the plotting script safely inside the virtual environment
    echo "Generating resource plots..."
    uv run --python "$VENV_DIR" python3 "$PLOT_SCRIPT" -d "$DB_FILE" -o "$PLOT_FILE"

    # Also generate network telemetry plots if network telemetry DB exists and plot script is present
    NET_PLOT_SCRIPT="experiments/plot_network_telemetry.py"
    if [ -f "$NET_PLOT_SCRIPT" ] && [ -f "$TELEMETRY_DB_FILE" ]; then
        echo "Generating network telemetry plots..."
        uv run --python "$VENV_DIR" python3 "$NET_PLOT_SCRIPT" -d "$TELEMETRY_DB_FILE" -o "$TELEMETRY_PLOT_FILE"
    fi
else
    echo "${YELLOW}⚠️  [WARNING]${NC} Could not find plot_resource_usage.py in experiments/ or ., skipping plot generation."
fi

# Cleanup runs automatically here via trap EXIT
