#!/usr/bin/env bash

# Pure experiment script: launches gossip nodes
# Usage: ./gossip-experiment.sh [node_count]
NODES="${1:-3}"

echo "Starting gossip cluster with $NODES node(s)..."
exec docker compose up --scale gossip-node="$NODES"