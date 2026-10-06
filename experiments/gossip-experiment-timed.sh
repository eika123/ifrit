#!/usr/bin/env bash

# Self-timed experiment script: launches gossip nodes with its own internal duration limit
# Usage: ./gossip-experiment-timed.sh <node_count> <duration>
# Example: ./gossip-experiment-timed.sh 5 30s

NODES="${1:-3}"
DURATION="${2:-30s}"

echo "Starting gossip cluster with $NODES node(s) for $DURATION (script-managed timer)..."

# Run docker compose with timeout
timeout --preserve-status "$DURATION" docker compose up --scale gossip-node="$NODES"
