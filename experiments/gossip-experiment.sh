#!/usr/bin/env bash

# Pure experiment script: launches gossip nodes
# Usage: ./gossip-experiment.sh [--build] [node_count]
BUILD_FLAG=""
NODES=3
for arg in "$@"; do
    if [[ "$arg" == "--build" || "$arg" == "-b" ]]; then
        BUILD_FLAG="--build"
    elif [[ "$arg" =~ ^[0-9]+$ ]]; then
        NODES="$arg"
    fi
done

echo "Starting gossip cluster with $NODES node(s) (build: ${BUILD_FLAG:-no})..."
exec docker compose up $BUILD_FLAG --scale gossip-node="$NODES"