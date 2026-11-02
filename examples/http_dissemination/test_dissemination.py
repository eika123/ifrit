#!/usr/bin/env python3
"""
test_dissemination.py

Language-agnostic end-to-end dissemination test for Ifrit HTTP nodes.
Uses only Python 3 standard libraries (urllib, json, uuid, time, argparse, tomllib).

Pluggable black-box test:
Connects to an existing cluster of Ifrit HTTP nodes passed via --hostfile or --nodes,
injects items across nodes, and asserts 100% convergence and XOR fingerprint
matching across all nodes.
"""

import argparse
import json
import math
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

# tomllib is standard in Python 3.11+. Fall back to tomli if running on older Python.
try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore
    except ModuleNotFoundError:
        tomllib = None  # type: ignore

HTTP_CLIENT_ERRORS = (
    urllib.error.URLError,
    TimeoutError,
    json.JSONDecodeError,
    OSError,
)


def to_url(endpoint: str, path: str) -> str:
    """Normalize a host:port or URL endpoint and append the specified subpath."""
    ep = endpoint.strip().rstrip("/")
    if not (ep.startswith("http://") or ep.startswith("https://")):
        ep = f"http://{ep}"
    clean_path = path.lstrip("/")
    return f"{ep}/{clean_path}"


def parse_hostfile(path: str) -> list[str]:
    """
    Parse a TOML hostfile conforming to Option B:
    [ca-authority]
    host = "127.0.0.1"
    port = 8321

    [[nodes]]
    host = "127.0.0.1"
    http_port = 8081
    tcp_port = 9000
    udp_port = 9001
    """
    if tomllib is None:
        raise RuntimeError("Python standard library 'tomllib' (or 'tomli') is required to parse TOML hostfiles.")

    if not os.path.isfile(path):
        raise FileNotFoundError(f"Hostfile not found at '{path}'")

    with open(path, "rb") as f:
        data = tomllib.load(f)

    nodes = data.get("nodes", [])
    if not isinstance(nodes, list) or len(nodes) == 0:
        raise ValueError(f"Hostfile '{path}' contains no [[nodes]] definitions.")

    http_endpoints: list[str] = []
    for idx, node in enumerate(nodes, start=1):
        if not isinstance(node, dict):
            raise ValueError(f"Node #{idx} in hostfile is not a table.")
        host = node.get("host")
        http_port = node.get("http_port")
        if not host or not http_port:
            raise ValueError(f"Node #{idx} in hostfile is missing 'host' or 'http_port'.")
        http_endpoints.append(f"{host}:{http_port}")

    return http_endpoints


def http_get_stored_data(url: str, timeout: float = 5.0) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise urllib.error.HTTPError(url, resp.status, f"HTTP {resp.status}", resp.headers, None)
        raw = resp.read().decode("utf-8")
        return json.loads(raw)


def http_post_data_item(url: str, payload: dict, timeout: float = 5.0) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status not in (200, 201):
            raise urllib.error.HTTPError(url, resp.status, f"HTTP {resp.status}", resp.headers, None)
        raw = resp.read().decode("utf-8")
        return json.loads(raw)


def check_node_healthy(node: str) -> bool:
    url = to_url(node, "/health")
    try:
        data = http_get_stored_data(url, timeout=2.0)
        return data.get("status") == "ok"
    except HTTP_CLIENT_ERRORS:
        return False


def wait_for_health(nodes: list[str], timeout: float = 15.0) -> None:
    print(f"[INFO] Waiting for {len(nodes)} nodes to become healthy (timeout: {timeout:.1f}s)...")
    start = time.time()
    pending = set(nodes)

    while pending and (time.time() - start) < timeout:
        pending = {node for node in pending if not check_node_healthy(node)}
        if pending:
            time.sleep(0.2)

    if pending:
        raise TimeoutError(f"Health check timed out after {timeout:.1f}s for nodes: {sorted(pending)}")

    print(f"[INFO] All {len(nodes)} nodes are healthy.")


def calculate_default_timeout(num_nodes: int, items_per_node: int) -> float:
    """
    Compute an adaptive convergence timeout based on cluster size and data volume.

    Formula:
      T = T_base + C_rounds * ceil(log2(N)) + C_data * (N * I)

    Where:
      - T_base = 20.0s (startup grace and baseline anti-entropy interval)
      - C_rounds = 3.0s per gossip round (log2(N))
      - C_data = 0.05s per total item streamed across cluster
    """
    total_items = num_nodes * items_per_node
    rounds = math.ceil(math.log2(max(num_nodes, 2)))
    adaptive = 20.0 + (3.0 * rounds) + (0.05 * total_items)
    return max(25.0, round(adaptive, 1))


def run_dissemination_test(
    nodes: list[str], items_per_node: int = 2, timeout: float = 25.0
) -> bool:
    print(f"[INFO] Running dissemination test across {len(nodes)} nodes:")
    for n in nodes:
        print(f"       - {n}")

    # 1. Generate unique UUIDs and distribute them across nodes
    injected_by_node: dict[str, list[str]] = {}
    all_injected_items: set[str] = set()

    for node in nodes:
        node_items = []
        for _ in range(items_per_node):
            item = f"item-{uuid.uuid4()}"
            node_items.append(item)
            all_injected_items.add(item)
        injected_by_node[node] = node_items

    # 2. POST items to each node
    print(f"[INFO] Injecting {len(all_injected_items)} total items ({items_per_node} per node)...")
    for node, items in injected_by_node.items():
        url = to_url(node, "/items")
        for item in items:
            try:
                resp = http_post_data_item(url, {"item": item})
                if resp.get("status") != "added":
                    print(f"[ERROR] Failed to add item {item} to {node}: {resp}", file=sys.stderr)
                    return False
            except HTTP_CLIENT_ERRORS as e:
                print(f"[ERROR] POST {url} failed: {e}", file=sys.stderr)
                return False

    print(f"[INFO] Successfully injected items. Waiting for network convergence (timeout: {timeout:.1f}s)...")

    # 3. Poll GET /items on all nodes until complete convergence
    start_time = time.time()
    last_reported_count = -1

    while (time.time() - start_time) < timeout:
        all_converged = True
        fingerprints: dict[str, str] = {}
        missing_by_node: dict[str, set[str]] = {}

        for node in nodes:
            url = to_url(node, "/items")
            try:
                resp = http_get_stored_data(url, timeout=3.0)
                stored_items = set(resp.get("items", []))
                fp = resp.get("fingerprint", "")
                fingerprints[node] = fp

                missing = all_injected_items - stored_items
                if missing:
                    missing_by_node[node] = missing
                    all_converged = False
            except HTTP_CLIENT_ERRORS:
                all_converged = False
                break

        # Check fingerprint consistency
        unique_fps = set(fingerprints.values())
        if all_converged and len(unique_fps) == 1 and "" not in unique_fps:
            elapsed = time.time() - start_time
            matched_fp = list(unique_fps)[0]
            print(
                f"[PASS] Network converged in {elapsed:.2f}s! "
                f"All {len(nodes)} nodes contain {len(all_injected_items)} items. "
                f"Fingerprint: {matched_fp}"
            )
            return True

        # Progress tracking
        min_items = min(len(all_injected_items - missing_by_node.get(n, set())) for n in nodes)
        if min_items != last_reported_count:
            last_reported_count = min_items
            print(f"       Convergence progress: {min_items}/{len(all_injected_items)} items present on all nodes...")

        time.sleep(0.3)

    # 4. Timeout failure report
    print(f"\n[ERROR] Dissemination failed to converge within {timeout:.1f}s!", file=sys.stderr)
    print("Diagnostics per node:", file=sys.stderr)
    for node in nodes:
        url = to_url(node, "/items")
        try:
            resp = http_get_stored_data(url)
            count = resp.get("count", 0)
            fp = resp.get("fingerprint", "unknown")
            missing = all_injected_items - set(resp.get("items", []))
            print(
                f"  Node {node}: count={count}, fingerprint={fp}, missing={len(missing)} items",
                file=sys.stderr,
            )
        except HTTP_CLIENT_ERRORS as e:
            print(f"  Node {node}: unreachable ({e})", file=sys.stderr)

    return False


def main():
    parser = argparse.ArgumentParser(
        description="Language-agnostic dissemination test for Ifrit HTTP nodes."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--hostfile",
        type=str,
        help="Path to TOML hostfile defining [[nodes]] and [ca-authority].",
    )
    group.add_argument(
        "--nodes",
        type=str,
        help="Comma-separated list of node host:port pairs or URLs (e.g. 127.0.0.1:8081,127.0.0.1:8082)",
    )
    parser.add_argument(
        "-i",
        "--items",
        dest="items",
        type=int,
        default=2,
        help="Number of unique items to inject per node (default: 2)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Maximum seconds to wait for network convergence (default: dynamic based on nodes and items)",
    )
    parser.add_argument(
        "--health-timeout",
        type=float,
        default=15.0,
        help="Maximum seconds to wait for initial health check (default: 15.0)",
    )

    args = parser.parse_args()

    if args.hostfile:
        try:
            node_list = parse_hostfile(args.hostfile)
        except (ValueError, FileNotFoundError, RuntimeError) as e:
            print(f"[ERROR] Failed to parse hostfile: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        node_list = [n.strip() for n in args.nodes.split(",") if n.strip()]

    if len(node_list) < 2:
        print("[ERROR] At least 2 nodes are required for dissemination testing.", file=sys.stderr)
        sys.exit(1)

    try:
        wait_for_health(node_list, timeout=args.health_timeout)
    except TimeoutError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    timeout = args.timeout
    if timeout is None:
        timeout = calculate_default_timeout(len(node_list), args.items)
        print(f"[INFO] Using dynamically scaled convergence timeout: {timeout:.1f}s (for {len(node_list)} nodes, {args.items} items/node)")

    print("[INFO] Nodes seem healthy and stable -- starting dissemination test")
    success = run_dissemination_test(
        node_list, items_per_node=args.items, timeout=timeout
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
