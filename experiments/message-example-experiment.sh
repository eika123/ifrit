#!/usr/bin/env bash

# Pure experiment script: launches gossip nodes
# Usage: ./message-example-experiment.sh [--build] [--rings N] [node_count]
BUILD_FLAG=""
NODES="${NODES:-3}"
RINGS="${RINGS:-3}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--build)
            BUILD_FLAG="--build"
            shift
            ;;
        -r|--rings)
            RINGS="$2"
            shift 2
            ;;
        --rings=*)
            RINGS="${1#*=}"
            shift
            ;;
        -n|--nodes)
            NODES="$2"
            shift 2
            ;;
        --nodes=*)
            NODES="${1#*=}"
            shift
            ;;
        *)
            if [[ "$1" =~ ^[0-9]+$ ]]; then
                NODES="$1"
            fi
            shift
            ;;
    esac
done

export RINGS="$RINGS"
export NODES="$NODES"

echo "Starting gossip cluster with $NODES node(s) (rings: $RINGS, build: ${BUILD_FLAG:-no}) for sending simple messages ...."
exec docker compose up $BUILD_FLAG --scale gossip-node="$NODES"