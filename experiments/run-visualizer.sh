#!/usr/bin/env bash
# run-visualizer.sh
# Convenient wrapper to run the Ifrit Telemetry Dashboard
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ensure uv is installed/available
if ! command -v uv >/dev/null 2>&1; then
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi

if ! command -v uv >/dev/null 2>&1; then
    echo "Error: 'uv' was not found on PATH. Install it or run: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
    exit 1
fi

# Run the visualizer application forwarding any passed arguments (e.g. DB path, --port 8080)
exec uv run --project "$SCRIPT_DIR" python "$SCRIPT_DIR/visualize-interactive/serve_telemetry_ui.py" "$@"