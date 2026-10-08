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
