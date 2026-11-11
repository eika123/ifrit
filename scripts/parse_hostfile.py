#!/usr/bin/env python3
"""
parse_hostfile.py

Internal helper for scripts: parses a TOML hostfile conforming to Option B:
[ca-authority]
host = "127.0.0.1"
port = 8321

[[nodes]]
host = "127.0.0.1"
http_port = 8081
tcp_port = 9000
udp_port = 9001

Outputs whitespace/newline-separated lines consumable by bash read/loops.
Modes:
  --ca       -> prints "HOST PORT"
  --nodes    -> prints one line per node: "HOST HTTP_PORT TCP_PORT UDP_PORT"
  --http-csv -> prints comma-separated "HOST:HTTP_PORT,..."
"""

import os
import sys

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore
    except ModuleNotFoundError:
        print("Error: Python 'tomllib' (or 'tomli') required.", file=sys.stderr)
        raise

def main():
    if len(sys.argv) < 3:
        print("Usage: parse_hostfile.py <hostfile.toml> (--ca | --nodes | --http-csv)", file=sys.stderr)
        sys.exit(1)

    hostfile_path = sys.argv[1]
    mode = sys.argv[2]

    if not os.path.isfile(hostfile_path):
        print(f"Error: hostfile '{hostfile_path}' not found", file=sys.stderr)
        sys.exit(1)

    with open(hostfile_path, "rb") as f:
        data = tomllib.load(f)

    if mode == "--ca":
        ca = data.get("ca-authority") or data.get("ca_authority") or {}
        ca_host = ca.get("host", "127.0.0.1")
        ca_port = ca.get("port", 8321)
        print(f"{ca_host} {ca_port}")

    elif mode == "--nodes":
        nodes = data.get("nodes", [])
        if not nodes:
            print(f"Error: no [[nodes]] defined in {hostfile_path}", file=sys.stderr)
            sys.exit(1)
        for n in nodes:
            host = n.get("host", "127.0.0.1")
            http_p = n.get("http_port")
            tcp_p = n.get("tcp_port")
            udp_p = n.get("udp_port")
            if not (http_p and tcp_p and udp_p):
                print(f"Error: node missing port in {n}", file=sys.stderr)
                sys.exit(1)
            print(f"{host} {http_p} {tcp_p} {udp_p}")

    elif mode == "--http-csv":
        nodes = data.get("nodes", [])
        endpoints = [f"{n.get('host')}:{n.get('http_port')}" for n in nodes if n.get("host") and n.get("http_port")]
        print(",".join(endpoints))

    else:
        print(f"Error: unknown mode {mode}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

