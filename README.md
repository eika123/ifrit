# Ifrit
Go library implementing the Fireflies protocol, https://dl.acm.org/citation.cfm?id=2701418.
Ifrit provides a membership, message, signature, and gossip service.
Applications have a full membership view and can send messages directly to their destination.

[![GoDoc](https://godoc.org/github.com/joonnna/ifrit?status.svg)](https://godoc.org/github.com/joonnna/ifrit)

### Starting a Ifrit network
To start an Ifrit network, you need to deploy the Ifrit certificate authority, responsible for signing certificates and acting as an entry point into the network.

The certificate authority serves a single HTTP endpoint for certificate signing requests, piggybacking certificates of existing participants on responses.
To start a network, simply deploy it.

Firstly, import the certificate authority package:
```go
"github.com/joonnna/ifrit/crypto/cauth"
```
Then create and start a CA instance:
```go
ca, err := cauth.NewCa()
if err != nil {
    panic(err)
}

go ca.Start()

```

Furthermore, you can customize CA parameters via CLI flags (`--host`, `--port`, `--path`, `--new`), `IFRIT_*` environment variables, or an optional YAML config file searched at `-config` (default `./ca_config.yaml`), `./config/ca_config.yaml`, and `/etc/ifrit/config.yaml`.
Key CA parameters:
- `boot_nodes` / `NumBootNodes`: how many participant certificates the certificate authority stores locally (default: `5`).
- `num_rings` / `NumRings`: how many Ifrit rings will be used by participants, embedded in all certificates (default: `3`).
- `port`: which port to bind to (default: `8321`).
- `path`: directory for CA keys and group state (default: `./ifrit-cad`).




### Starting a client
Firstly you'll have to populate the client config with the address (`ip:port`) of the certificate authority.
For local development, initialize the git-ignored config files under `config/`:
```bash
just config-init
# Or manually:
cp config/ifrit_config.example.yaml config/ifrit_config.yaml
cp config/.env.example config/.env
```
For standalone distributed deployments, place `ifrit_config.yaml` in `/var/tmp/ifrit_config.yaml` (or point `IFRIT_CONFIG` directly to it). Ensure `ca_addr` is set (like `ca_addr: "ip:8321"`).


Now you'll want to import the library:
```go
"github.com/joonnna/ifrit"
```
Now you can create and start a client:
```go
c, err := ifrit.NewClient(&ifrit.Config{
    New:      true,
    Hostname: "localhost",
    TCPPort:  tcpPort,
    UDPPort:  udpPort,
})
if err != nil {
    panic(err)
}

go c.Start()
```
After participating in the network for some time you will learn of all other participants in the network, you can retreive their addresses as follows:
```go
allNetworkMembers := c.Members()
```


### Sending a message
After joining an Ifrit network you can send messages to anyone in it:

```go
members := client.Members()

randomMember := members[rand.Int() % len(members)]

ch := client.SendTo(randomMember, msg)

response := <-ch
```
The response will eventually be propagated through the returned channel.


To receive messages, you can register a message handler:
```go
client.RegisterMsgHandler(yourMessageHandler)

// This callback will be invoked on each received message.
func yourMessageHandler(data []byte) ([]byte, error) {
    // Do message logic
    return yourResponse, yourError
}
```
The response, or error if its non-nil, will be propagated back to the sender.


### Adding gossip (State Reconciliation)
Ifrit disseminates application state across Fireflies ring neighbors using a typed `ifrit.ReverseIndexStore[T]`. Create a digest-backed store (or supply a custom `ReverseIndexStore[T]`), register it on the client, and insert elements — Ifrit handles digest exchange and delta synchronization with peers automatically:

```go
// Define a comparable type for items replicated via gossip.
type user struct {
    ID        string `json:"id"`
    FirstName string `json:"first_name"`
    LastName  string `json:"last_name"`
}

// Create a thread-safe reconcilable store and register it with the client.
store, err := ifrit.NewDigestSet[user](ifrit.MustDefaultHasher[user]())
if err != nil {
    panic(err)
}
ifrit.RegisterDataStore(c, store)

// Insert local items; Ifrit automatically reconciles divergence with ring neighbors.
store.AddElement(user{ID: "user-1", FirstName: "Ada", LastName: "Lovelace"})
```

For custom serialization formats, use `ifrit.RegisterDataStoreWithCodec(c, store, codec)`. See the complete example in [examples/gossip/gossipContentExample.go](examples/gossip/gossipContentExample.go).

### Adding streaming
Ifrit supports bi-directional streaming. The sender invokes `client.OpenStream(dest)` which returns two channels (`input` to send to the server, `reply` to receive from the server). Register the server-side handler via `client.RegisterStreamHandler(streamHandler)`:
```go
members := client.Members()
randomMember := members[rand.Int()%len(members)]
input, reply := client.OpenStream(randomMember)
// Use the channels
close(input)

func streamHandler(input, reply chan []byte) {
    // Use the channels
    close(reply)
}
```
To avoid untimely closing of channels, the application should implement a means of acknowledgement before closing any streams. 

**NOTE**: The ``reply`` stream at the sending side must not block so that the resources can be released. See the fully-working example of streaming [here](examples/streaming/streamingExample.go).

### Config & Environment Details

All tracked configuration templates live in `config/`, while local overrides and secrets remain git-ignored:
- `config/ifrit_config.example.yaml` — default client YAML template (copy to git-ignored `config/ifrit_config.yaml` or run `just config-init`).
- `config/ifrit_container_config.yaml` — container network preset (`ca_addr: "ca:8321"`) mounted by `docker-compose.yml` and `experiments/docker-compose.experiments.yml`.
- `config/.env.example` — environment and secrets template (copy to git-ignored `config/.env`). `just` loads `config/.env` automatically on invocation; Go binaries read exported environment variables from process memory.

#### Config Search Order
Ifrit clients resolve `ifrit_config.yaml` in the following order:
1. `IFRIT_CONFIG` — explicit file path override (takes highest precedence; used by containers, tests, and local runner scripts).
2. `IFRIT_CONFIG_PATHS` — OS path-list (e.g. `./config:.:/var/tmp`) of directories searched in order for `ifrit_config.yaml`.
   - Running via `just` sets `IFRIT_CONFIG_PATHS` to `./config:.:/var/tmp` by default (overridable in `config/.env` or your shell) so workspace `config/` takes precedence locally.
   - Running standalone Go binaries without `IFRIT_CONFIG_PATHS` defaults to `/var/tmp`, `./config`, `.` so host-level `/var/tmp/ifrit_config.yaml` takes precedence on distributed cluster nodes.

When building the container image via `Dockerfile`, `ARG IFRIT_DEFAULT_CONFIG` defaults to `config/ifrit_config.example.yaml` and can be overridden at build time (`--build-arg IFRIT_DEFAULT_CONFIG=...`) or at runtime via volume mount / `IFRIT_CONFIG`.

#### Client Configuration Variables
Ifrit supplies defaults for behavioral settings while requiring `ca_addr`:
- `ca_addr` (`string`): `ip:port` of the CA (e.g. `"localhost:8321"`).
- `gossip_interval` (`int32`, default `10`): How often (in seconds) the Ifrit client gossips with a neighboring peer.
- `monitor_interval` (`int32`, default `10`): How often (in seconds) the Ifrit client monitors other peers.
- `view_update_interval` (`int32`, default `10`): View update interval (in seconds).
- `ping_timeout` (`int32`, default `5`): Ping timeout (in seconds).
- `ping_limit` (`int32`, default `3`): Number of failed pings before a peer is considered dead.
- `pings_per_interval` (`int32`, default `3`): Number of peers pinged per monitoring interval.
- `removal_timeout` (`int32`, default `60`): Seconds to wait after discovering an unresponsive peer before removing it from the live view.
- `max_concurrent_messages` (`uint32`, default `5`): Maximum concurrent outgoing messages.
- `use_compression` (`bool`, default `true`): Whether outgoing RPC payloads use compression.
- `reconciliation_strategy` (`string`, default `"naive"`): Note/state reconciliation strategy.
- `session_timeout` (`int32`, default `30`): Reconciliation session timeout (in seconds).
- `viz_update_interval` (`int32`, default `10`): Visualizer update interval (in seconds).

### Common `just` Commands
- `just check`: Run `go fmt`, `go vet`, `go build`, `go test`, and `go test -race`.
- `just config-init`: Initialize git-ignored `config/ifrit_config.yaml` and `config/.env` from `.example` templates.
- `just tui-gossip` / `just local-streaming` / `just local-http-test`: Run local clusters and examples.
- `just exp` / `just tui-telemetry`: Run container chaos experiments and open the telemetry UI.
