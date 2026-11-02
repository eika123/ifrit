# HTTP Data Dissemination Example & Language-Agnostic Test Harness

This directory contains a lightweight, language-agnostic HTTP application layer sitting directly on top of Ifrit and Fireflies, coupled with a pure Python 3 end-to-end dissemination test.

## Architecture

- **Application (`app.go`, `main.go`)**:
  - Each node runs an Ifrit peer configured with a convergent `ReverseIndexStore[string]` (`DigestSet[string]`).
  - An embedded HTTP server exposes REST endpoints to inject items and retrieve the current store contents.
  - When items are added via HTTP on one node, Ifrit's Fireflies gossip (`Spread`) detects set divergence with ring neighbours, and unified streaming (`Sync`) automatically disseminates the missing items across the network.
- **Test Driver (`test_dissemination.py`)**:
  - Uses only the Python 3 standard library (`urllib.request`, `json`, `uuid`, `time`, `argparse`) with zero external pip dependencies.
  - Injects distinct UUID strings across multiple nodes via `POST /items`.
  - Continuously polls `GET /items` across all nodes until complete convergence is achieved (every node contains 100% of injected items and reports identical XOR fingerprints).

---

## REST API Specification

### 1. `GET /health`
Returns node readiness and current store statistics.

**Response (`200 OK`)**:
```json
{
  "status": "ok",
  "store_size": 2,
  "fingerprint": "5c8674e2e2ca11ff"
}
```

### 2. `POST /items`
Adds an item string (e.g. UUID) to the local store and triggers network reconciliation.

**Request**:
```json
{
  "item": "e7b0d234-58e1-4c12-a7d2-7c918230b8e2"
}
```
*(Plain text body is also accepted)*

**Response (`201 Created`)**:
```json
{
  "status": "added",
  "item": "e7b0d234-58e1-4c12-a7d2-7c918230b8e2",
  "is_new": true,
  "store_size": 1,
  "fingerprint": "5c8674e2e2ca11ff"
}
```

### 3. `GET /items`
Retrieves all items stored in the node.

**Response (`200 OK`)**:
```json
{
  "items": [
    "item-1",
    "item-2"
  ],
  "count": 2,
  "fingerprint": "5c8674e2e2ca11ff"
}
```

---

## Running the Cluster & Tests

### Option A: Standalone via Cluster Bash Script

Start the local cluster and run the pluggable black-box dissemination test end-to-end:

```bash
# Start cluster, run test, and exit:
./scripts/run_local_http.sh --test

# Or leave the cluster running for interactive testing/curl:
./scripts/run_local_http.sh
```

### Option B: Pluggable Test Against Running Nodes

Point the Python driver to any running cluster of nodes:

```bash
python3 examples/http_dissemination/test_dissemination.py \
  --nodes http://127.0.0.1:8081,http://127.0.0.1:8082,http://127.0.0.1:8083 \
  --items-per-node 2 \
  --timeout 25
```

### Option C: Via `go test`

```bash
go test -v -count=1 ./examples/http_dissemination/...
go test -race -count=1 ./examples/http_dissemination/...
```

