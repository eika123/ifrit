# Experiments Network Observer

This directory contains the scaffolding for the passive network observation daemon.

## Architecture & Evolution Path

```
  [ Phase 1: Pure Go Observer (Active Now) ]
  Raw Socket (AF_PACKET / ETH_P_ALL)
       │
       ├──► UDP 9001: proto.Unmarshal(&pb.Ping{}), proto.Unmarshal(&pb.Pong{})
       │    └──► Calculates actual round-trip latency (RTT) per nonce
       │
       └──► TCP 9000: Measures gossip content wire byte size over time
            └──► SQLite database: experiment_results/network_telemetry.db

  ─────────────────────────────────────────────────────────────

  [ Phase 2: Hybrid Evolution with cilium/ebpf ]
  Kernel eBPF Probes (tc / socket filter + uprobes on crypto/tls.(*Conn).Write)
       │
       └──► cilium/ebpf RingBuffer
            └──► Reuses same SQLite schema & plotting pipeline
```

## eBPF Toolchain & Code Generation

The eBPF probe program is implemented in C at `bpf/filter.c` and loaded using [`cilium/ebpf`](https://github.com/cilium/ebpf).

### Required Toolchain

To compile the eBPF C program into bytecode and Go bindings, the following host packages are required:
- `clang` (compiles `filter.c` to BPF target)
- `llvm` (provides `llvm-strip` to strip DWARF symbols)
- `libbpf-dev` (provides BPF endianness and helper headers under `/usr/include/bpf`)
- `bpftool` (or `linux-tools-common` and `linux-tools-$(uname -r)` / `linux-tools-generic` on Ubuntu/Debian, used to dump `vmlinux.h` from kernel BTF `/sys/kernel/btf/vmlinux`)

### Automated Setup Script

Use [`setup_bpf.sh`](setup_bpf.sh) to automate the entire process:

```bash
# 1. Run with automatic dependency installation via apt:
./experiments/observer/setup_bpf.sh --install-deps

# 2. Or run without package installation (if dependencies are already present):
./experiments/observer/setup_bpf.sh
```

This script:
1. Validates that `clang`, `llvm-strip`, `bpftool`, and `libbpf-dev` are installed.
2. Extracts or symlinks the Linux kernel BTF header to `bpf/vmlinux.h`.
3. Runs `go generate ./experiments/observer` to generate:
   - `filter_bpf.go` (Go types and embedding logic)
   - `filter_bpf.o` (compiled BPF bytecode object)

### Build Artifacts on the Host

All generated BPF artifacts (`vmlinux.h`, `filter_bpf.go`, and `filter_bpf.o`) are gitignored and generated locally on the host. 

When cloning the repository onto a fresh computer, run the setup script once:
```bash
./experiments/observer/setup_bpf.sh --install-deps
```
This ensures the host toolchain is installed and the required BPF objects and Go definitions are compiled before running `go build ./...` or `go test ./...`.

## Running as a Container Service in docker-compose.experiments.yml

Add the observer as an optional service joined to `ifrit-net`:

```yaml
  network-observer:
    build:
      context: .
      dockerfile: experiments/observer/Containerfile
    container_name: ifrit-observer
    network_mode: "host" # or cap_add: [NET_ADMIN, NET_RAW] on ifrit-net
    volumes:
      - ./experiment_results:/results
    command: ["-db", "/results/network_telemetry.db"]
```

## Running Locally on Host (Requires root / sudo for raw socket)

```bash
sudo go run ./experiments/observer/main.go -db experiment_results/network_telemetry.db
```

## SQLite Telemetry Schema

The daemon automatically populates two tables in `network_telemetry.db`:
- `ping_pong_events`: `(id, timestamp, event_type, src_ip, dst_ip, nonce_hex, rtt_ms)`
- `tcp_traffic_stats`: `(id, timestamp, src_ip, dst_ip, packet_bytes)`
