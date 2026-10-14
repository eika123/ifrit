#!/usr/bin/env bash


show_help() {
        cat << 'EOF'
Ifrit Experiment Runner
================================================================================================
Orchestrates Ifrit gossip experiments over a Docker container network, injects optional network
chaos (latency, jitter, packet loss), collects telemetry across nodes, merges
SQLite results, and plots resource and exchange statistics.
Usage:
  ./run-experiments.sh [options] <experiment-script.sh> [script_args...]
-------------------------------------------------------------------------------------------------
Options:
      --docker-activate         Run experiment inside a dedicated Docker container
      -b, --build               Rebuild Docker images before starting
      -t, --duration <dur>      Experiment run duration (e.g. 40s, 5m, 1h). Default: indefinite
      -c, --checkpoint-interval Sampling interval for resource usage (e.g. 5s)
      -f, --compose-file <file> Override default docker-compose file
      --teardown-grace-period   Seconds to wait before killing containers (default: 10s)
    Network Chaos (Pumba):
      --delay <ms>              Network latency to inject in milliseconds
      --jitter <ms>             Latency jitter in milliseconds
      --loss <%>                Packet loss percentage
      --chaos-interval <dur>    Interval between chaos periods (e.g. 1m, 5m)
      --chaos-duration <dur>    Duration of each chaos period (must be < interval, e.g. 55s)

    Note: Must have --chaos-interval > --chaos-duration
-------------------------------------------------------------------------------------------------
    Examples:
  ./run-experiments.sh -t 40s -c 5s gossip-experiment.sh 10
  ./run-experiments.sh -t 5m --delay 50 --jitter 10 --loss 1 gossip-experiment.sh 5
  ./run-experiments.sh --docker-activate --build -t 2m gossip-experiment.sh 8
=================================================================================================
EOF
}


usage(){
            echo "Usage: $0 [--docker-activate] [-b|--build] [-t <duration>] [-c <checkpoint-interval>] [--chaos-interval <1m>] [--chaos-duration <55s>] [--delay <ms>] [--jitter <ms>] [--loss <%>] [-f <compose-file>] [--teardown-grace-period <seconds>] <experiment-script.sh> [script_args...]"
            echo "Example: $0 --docker-activate --build -t 40s -c 5s gossip-experiment.sh 10"
            echo "Example: $0 -t 5m --chaos-interval 5m --chaos-duration 4m55s --delay 50 --jitter 10 gossip-experiment.sh 5"
            echo "Example: $0 -t 5m --chaos-interval 5m --chaos-duration 4m55s --delay 50 --jitter 10 --teardown-grace-period 15 gossip-experiment.sh 5"
            echo "Note: Must have --chaos-interval > --chaos-duration"
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
        --chaos-interval)
            CHAOS_INTERVAL="$2"
            shift 2
            ;;
        --chaos-interval=*)
            CHAOS_INTERVAL="${1#*=}"
            shift
            ;;
        --chaos-duration)
            CHAOS_DURATION="$2"
            shift 2
            ;;
        --chaos-duration=*)
            CHAOS_DURATION="${1#*=}"
            shift
            ;;
        --delay)
            DELAY_MS="$2"
            shift 2
            ;;
        --delay=*)
            DELAY_MS="${1#*=}"
            shift
            ;;
        --jitter)
            JITTER_MS="$2"
            shift 2
            ;;
        --jitter=*)
            JITTER_MS="${1#*=}"
            shift
            ;;
        --loss)
            LOSS_PERCENT="$2"
            shift 2
            ;;
        --loss=*)
            LOSS_PERCENT="${1#*=}"
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
        -h|--help)
            show_help
            exit 0
            ;;
        --*|-*)
            echo "Error: Unknown option '$1'" >&2
            usage >&2
            exit 1
            ;;
        *)
            break
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

# Export and validate chaos parameters
EFFECTIVE_INTERVAL="${CHAOS_INTERVAL:-1m}"
EFFECTIVE_DURATION="${CHAOS_DURATION:-55s}"

if [ -n "$CHAOS_INTERVAL" ] || [ -n "$CHAOS_DURATION" ]; then
    INTERVAL_SECS=$(parse_duration_to_seconds "$EFFECTIVE_INTERVAL")
    DURATION_SECS=$(parse_duration_to_seconds "$EFFECTIVE_DURATION")

    if [ "$DURATION_SECS" -ge "$INTERVAL_SECS" ]; then
        echo "Error: Pumba netem requires --chaos-duration ($EFFECTIVE_DURATION = ${DURATION_SECS}s) to be strictly shorter than --chaos-interval ($EFFECTIVE_INTERVAL = ${INTERVAL_SECS}s)."
        echo "Example of valid configuration: --chaos-interval 1m --chaos-duration 55s (or --chaos-interval 5m --chaos-duration 4m50s)"
        exit 1
    fi

    export PUMBA_INTERVAL="$EFFECTIVE_INTERVAL"
    export PUMBA_DURATION="$EFFECTIVE_DURATION"
fi

[ -n "$DELAY_MS" ] && export DELAY_MS="$DELAY_MS"
[ -n "$JITTER_MS" ] && export JITTER_MS="$JITTER_MS"
[ -n "$LOSS_PERCENT" ] && export LOSS_PERCENT="$LOSS_PERCENT"

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
    echo "Error: You must specify which experiment-script to run!"
    echo "Usage: $0 [--docker-activate] [-t <duration>] [-f <compose-file>] <experiment-script.sh> [script_args...]"
    exit 1
fi

shift # Remove the script name from the argument list

# Resolve script path (check current directory, experiments/ directory, or absolute path)
if [ -f "$EXPERIMENT_SCRIPT" ]; then
    SCRIPT_PATH="./$EXPERIMENT_SCRIPT"
elif [ -f "experiments/$EXPERIMENT_SCRIPT" ]; then
    SCRIPT_PATH="./experiments/$EXPERIMENT_SCRIPT"
else
    echo "Error: Could not find experiment script '$EXPERIMENT_SCRIPT' (checked . and ./experiments)"
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
        echo "Could not install sqlite3. Aborting experiment."
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

    echo "Running experiment (timer started: $EXPERIMENT_DURATION)..."
    sleep "$EXPERIMENT_DURATION" &
    SLEEP_PID=$!

    # Wait for whichever finishes first: the experiment script OR the sleep timer
    wait -n "$EXP_PID" "$SLEEP_PID" 2>/dev/null

    if kill -0 "$EXP_PID" 2>/dev/null; then
        echo "Duration limit ($EXPERIMENT_DURATION) reached. Stopping experiment..."
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
        kill -9 "$SLEEP_PID" 2>/dev/null || true
        wait "$SLEEP_PID" 2>/dev/null || true
    fi
else
    echo "Running experiment (indefinite, press Ctrl+C to stop and plot)..."
    wait "$EXP_PID" 2>/dev/null
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

# Fold any remaining WAL files into their .db files and remove -wal/-shm clutter
if command -v sqlite3 >/dev/null 2>&1; then
    for db in "$OUTPUT_DIR"/telemetry_*.db; do
        if [ -f "$db" ]; then
            sqlite3 "$db" "PRAGMA wal_checkpoint(TRUNCATE);" 2>/dev/null || true
            rm -f "${db}-wal" "${db}-shm"
        fi
    done
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
            echo "Could not install or find 'uv'. Skipping plotting."
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
    echo "Could not find plot_resource_usage.py in experiments/ or ., skipping plot generation."
fi

# Cleanup runs automatically here via trap EXIT
