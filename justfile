set dotenv-load
set dotenv-path := "config/.env"
set positional-arguments
set shell := ["bash", "-euo", "pipefail", "-c"]

export IFRIT_CONFIG_PATHS := env("IFRIT_CONFIG_PATHS", "./config:.:/var/tmp")

default:
    @just --list

[group('development')]
config-init:
    @if [ ! -f config/ifrit_config.yaml ]; then \
        cp config/ifrit_config.example.yaml config/ifrit_config.yaml; \
        echo "Created config/ifrit_config.yaml from example."; \
    else \
        echo "config/ifrit_config.yaml already exists."; \
    fi
    @if [ ! -f config/.env ]; then \
        cp config/.env.example config/.env; \
        echo "Created config/.env from example."; \
    else \
        echo "config/.env already exists."; \
    fi

[group('development')]
test *args='./...':
    go test -count=1 "$@"

[group('development')]
test-race *args='./...':
    go test -race -count=1 "$@"

[group('development')]
vet:
    go vet ./...

[group('development')]
fmt:
    go fmt ./...

[group('development')]
build:
    go build ./...

[group('development')]
check: fmt vet build test test-race

[group('local')]
tui-gossip *args:
    ./scripts/run_local_gossip.sh "$@"

[group('local')]
tui-telemetry *args:
    ./experiments/run-visualizer.sh "$@"

alias viz := tui-telemetry

[group('local')]
local-http *args:
    ./scripts/run_local_http.sh "$@"

[group('local')]
local-http-test nodes='5' mode='--test':
    ./scripts/run_local_http.sh -n {{ nodes }} {{ mode }}

[group('local')]
local-streaming:
    ./scripts/run_local_streaming.sh

[group('experiments')]
exp *args:
    @has_script=0; \
    has_duration=0; \
    for arg in "$@"; do \
        if [[ "$arg" == *.sh ]]; then \
            has_script=1; \
        elif [[ "$arg" == -t || "$arg" == --duration || "$arg" == --duration=* ]]; then \
            has_duration=1; \
        fi; \
    done; \
    if [ "$has_script" -eq 1 ]; then \
        ./experiments/run-experiments.sh "$@"; \
    elif [ $# -eq 0 ]; then \
        ./experiments/run-experiments.sh -t 1m --loss 10 --corrupt 5 --delay 200 --jitter 50 ./experiments/gossip-experiment.sh --nodes 10 --rings 3; \
    elif [ "$has_duration" -eq 1 ]; then \
        ./experiments/run-experiments.sh "$@" --loss 10 --corrupt 5 --delay 200 --jitter 50 ./experiments/gossip-experiment.sh --nodes 10 --rings 3; \
    else \
        ./experiments/run-experiments.sh "$@" -t 1m --loss 10 --corrupt 5 --delay 200 --jitter 50 ./experiments/gossip-experiment.sh --nodes 10 --rings 3; \
    fi

[group('experiments')]
exp-help:
    ./experiments/run-experiments.sh --help

[group('experiments')]
clean-results:
    @if [ -d experiments/results ]; then \
        find experiments/results -mindepth 1 -delete; \
        echo "Cleaned experiments/results/"; \
    else \
        echo "experiments/results/ does not exist."; \
    fi

[group('experiments')]
clean-libpod:
    rm -rf libpod

[group('experiments')]
clean-ca-data:
    rm -rf ifrit-cad

[group('experiments')]
clean: clean-results clean-libpod

[group('experiments')]
clean-all: clean clean-ca-data
