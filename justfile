set positional-arguments
set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

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
        ./run-experiments.sh "$@"; \
    elif [ $# -eq 0 ]; then \
        ./run-experiments.sh -t 1m --loss 10 --corrupt 5 --delay 200 --jitter 50 ./experiments/gossip-experiment.sh --nodes 10 --rings 3; \
    elif [ "$has_duration" -eq 1 ]; then \
        ./run-experiments.sh "$@" --loss 10 --corrupt 5 --delay 200 --jitter 50 ./experiments/gossip-experiment.sh --nodes 10 --rings 3; \
    else \
        ./run-experiments.sh "$@" -t 1m --loss 10 --corrupt 5 --delay 200 --jitter 50 ./experiments/gossip-experiment.sh --nodes 10 --rings 3; \
    fi

[group('experiments')]
exp-help:
    ./run-experiments.sh --help

[group('experiments')]
clean:
    @if [ -d experiments/results ]; then \
        find experiments/results -mindepth 1 -delete; \
        echo "Cleaned experiments/results/"; \
    else \
        echo "experiments/results/ does not exist."; \
    fi

alias clean-results := clean
