# Replicated DHT Example

This example runs a two-node replicated key-value store (`services/dht`) on top of Ifrit's Fireflies ServiceDirectory and `ratelessIBLT` set reconciliation.

Each node mounts the `"dht"` service, attaches a grow-only `KeyedReconcilableStore` under `"service/dht/items"`, and exposes an HTTP API on port `8080` inside its container (`8081` for `dht-1`, `8082` for `dht-2`).

## Run with Docker Compose

From the repository root:

```bash
docker compose -f examples/dht/docker-compose.yml up --build
```

This starts:
- `ca` — Ifrit certificate authority on `ca:8321`
- `dht-1` — DHT node exposed on `http://localhost:8081`
- `dht-2` — DHT node exposed on `http://localhost:8082`

## Interact via HTTP

`Item.Value` is a Go `[]byte`, so JSON values are base64-encoded (`"d29ybGQ="` = `"world"`, `"ZnJvbS1kaHQtMg=="` = `"from-dht-2"`).

```bash
# 1. Write an item on dht-1 (port 8081)
curl -i -X PUT http://localhost:8081/dht/items \
  -d '{"Key":"hello","Value":"d29ybGQ="}'

# 2. Read the replicated item from dht-2 (port 8082)
curl -i 'http://localhost:8082/dht/items?q=hello'

# 3. Write a conflicting sibling for the same key on dht-2
curl -i -X PUT http://localhost:8082/dht/items \
  -d '{"Key":"hello","Value":"ZnJvbS1kaHQtMg=="}'

# 4. Both nodes converge to a 2-element JSON array containing both siblings
curl -i 'http://localhost:8081/dht/items?q=hello'
```

## Stop & Clean Up

```bash
docker compose -f examples/dht/docker-compose.yml down
```

## Run the Go Integration Test

```bash
go test -v -race -count=1 ./examples/dht/...
```
