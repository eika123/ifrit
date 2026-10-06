#!/usr/bin/env bash

CONTAINER_NAME="go-experiment-runner"
OUTPUT_DIR="$(pwd)/experiment_results"
mkdir -p "$OUTPUT_DIR"

# Parse flags
DOCKER_MODE=false
EXPERIMENT_DURATION=""
CUSTOM_COMPOSE_FILE=""

while [[ "$1" == --* || "$1" == -* ]]; do
    case "$1" in
        --docker-activate)
            DOCKER_MODE=true
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
        -f|--compose-file)
            CUSTOM_COMPOSE_FILE="$2"
            shift 2
            ;;
        --compose-file=*)
            CUSTOM_COMPOSE_FILE="${1#*=}"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--docker-activate] [-t <duration>] [-f <compose-file>] <experiment-script.sh> [script_args...]"
            echo "Example: $0 --docker-activate -t 40s gossip-experiment.sh 10"
            echo "Example: $0 --compose-file custom-compose.yml gossip-experiment.sh 5"
            exit 0
            ;;
        *)
            break
            ;;
    esac
done

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

# Backup database if an existing one is found
if [ -f "$DB_FILE" ]; then
    TIMESTAMP_BACKUP=$(date +%Y%m%d_%H%M%S)
    BACKUP_FILE="$OUTPUT_DIR/backup-${EXP_IDENT}_${TIMESTAMP_BACKUP}.db"
    echo "Existing database found at $DB_FILE. Creating backup at $BACKUP_FILE..."
    cp "$DB_FILE" "$BACKUP_FILE"
    # Remove existing db to start fresh for this new experiment run
    rm -f "$DB_FILE" "$DB_FILE-wal" "$DB_FILE-shm"
fi

echo "Using database: $DB_FILE"
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
    echo "Running experiment (max duration: $EXPERIMENT_DURATION)..."
    sleep "$EXPERIMENT_DURATION" &
    SLEEP_PID=$!

    # Wait for whichever finishes first: the experiment script OR the sleep timer
    wait -n "$EXP_PID" "$SLEEP_PID" 2>/dev/null

    if kill -0 "$EXP_PID" 2>/dev/null; then
        echo "Duration limit ($EXPERIMENT_DURATION) reached. Stopping experiment..."
        # First stop docker containers directly so the compose process unblocks immediately
        docker compose stop -t 2 >/dev/null 2>&1 || true
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

# Best-effort container teardown (clean up any remaining containers)
docker compose stop -t 2 >/dev/null 2>&1 || true
docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true


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
    echo "Generating plots..."
    uv run --python "$VENV_DIR" python3 "$PLOT_SCRIPT" -d "$DB_FILE" -o "$PLOT_FILE"
else
    echo "Could not find plot_resource_usage.py in experiments/ or ., skipping plot generation."
fi

# Cleanup runs automatically here via trap EXIT
