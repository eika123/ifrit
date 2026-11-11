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
exp *args='-t 1m --loss 10 --corrupt 5 --delay 200 --jitter 50 ./experiments/gossip-experiment.sh --nodes 10 --rings 3':
    ./run-experiments.sh {{ args }}

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
