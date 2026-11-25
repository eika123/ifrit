# `reconcile`

Generic two-phase set reconciliation over gRPC bidirectional streams (`ReconcileService.Reconcile`).

Let A and B be sets on two distinct hosts.
Each reconciliation session runs in two phases:
1. **Phase 1 (Set difference negotiation):** A `Negotiator` exchanges compact set representations (`NegotiatePayload` frames) to compute a `Diff` (`Requested` digests the local node needs for set B, `Available` digests the remote node needs for set A, and `RemoteFP` for set B).
2. **Phase 2 (Validated item transfer):** Peers request missing digests (`WantDigests`), stream serialized items (`DataItemHeader` / `DataItemChunk` / `DataItemEnd`), verify digests against the allowlist, run tamper detection, and apply accepted items via `ItemApplier[T]`.

---

## 1. Creating a Store and Choosing a Reconciliation Protocol

A reconcilable store implements `reconcile.Store[T]`, which pairs a `digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol]` with a default `Negotiator()`:

```go
type Store[T any] interface {
	digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol]
	Negotiator() Negotiator
}
```

Importantly, the `reconcile.Store[T]` may also override methods of the Reverse Index Store like for instance Insert, 
in order to keep internal state related to set reconciliation,
like set sketches in rateless IBLT.

### Available protocols

| Package | Protocol ID | When to use | Constructor |
| :--- | :--- | :--- | :--- |
| `reconcile/ratelessIBLT` | `"riblt/1"` | **Default for large/growing sets.** Exchanges Rateless IBLT sketch symbols incrementally so bandwidth scales with the symmetric difference size rather than total set size. | `ratelessIBLT.NewReconcilableStore[T](hasher, sketchSize...)` |
| `reconcile/naive` | `"naive/1"` | **Small sets or simple baselines.** Exchanges full digest lists in batches (`DefaultBatchSize` / `WithBatchSize`). | `naive.NewReconcilableStore[T](hasher)` |

You can also wrap an existing `digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol]` with `ratelessIBLT.WrapStore(base, sketchSize...)` or `naive.WrapStore(base)`.

> **Top-level convenience:** The root `ifrit` package re-exports `ifrit.NewReconcilableStore`, `ifrit.NewNaiveStore`, and `ifrit.NewReconcilableStoreWithStrategy` if you are wiring stores through `ifrit.Client`.

### Constructing an `Engine[T]`

`reconcile.NewEngine[T](store, cfg)` wires a store to a protocol, codec, authenticator, tamper detector, and applier. All five dependencies are required (it fails closed if any is `nil`):

```go
store, err := ratelessIBLT.NewReconcilableStore[MyItem](myHasher)
if err != nil {
	return err
}

engine, err := reconcile.NewEngine[MyItem](store, reconcile.Config[MyItem]{
	StoreID:      "my-store",
	Negotiator:   store.Negotiator(),          // or explicit naive.NewNegotiator(...) / ratelessIBLT.NewNegotiator(...)
	Codec:        reconcile.DefaultItemCodec[MyItem](),
	ConnProvider: myConnProvider,              // needed for outbound ReconcileWithPeer
	Auth:         myAuthenticator,             // needed for inbound HandleReconcile
	Detector:     myTamperDetector,            // or reconcile.AcceptAll[MyItem]()
	Applier:      myItemApplier,               // or reconcile.NoopApplier[MyItem]
})
```

- **Protocol selection & fallback (`Registry`):** When acting as a server (`HandleReconcile`), `Engine` reads the `"reconcile-protocol"` (`reconcile.ProtocolMetadataKey`) metadata header from the incoming stream. If `cfg.Registry` is set, it looks up the matching `Negotiator`; otherwise it falls back to `cfg.Negotiator`. Registering both `"riblt/1"` and `"naive/1"` in a `reconcile.Registry` lets a server accept either protocol from peers.
- **Codecs:** `reconcile.DefaultItemCodec[T]()` automatically handles `[]byte`, `string`, `proto.Message` (pointer or value), and falls back to `reconcile.JSONCodec[T]{}` for arbitrary structs.

---

## 2. Injecting Tamper Detection (`TamperDetector[T]`)

`TamperDetector[T]` validates incoming items before they reach `ItemApplier[T]`, and handles any non-benign failures from the reconciliation pipeline:

```go
type TamperDetector[T any] interface {
	ValidateItem(ctx context.Context, item T) error
	OnMisbehavior(ctx context.Context, err error, evidence []byte)
}
```

### How `ValidateItem` and `OnMisbehavior` work together

Before `ValidateItem` runs, `Engine` already enforces that the item's digest was requested in Phase 2 (`WantDigests` allowlist), that its payload size matches `DataItemHeader.TotalSize` and is within `Config.MaxItemBytes` (`reconcile.DefaultMaxItemBytes`, 1 MiB), and that `Codec.Decode` + `store.Digest(item)` match the expected digest.

1. **`ValidateItem(ctx, item)`** runs first on each decoded item to check signatures, timestamps, or domain invariants:
   - **`nil`**: Item passes validation and is handed to `ItemApplier[T]`.
   - **`reconcile.ErrIgnore`** (or an error wrapping it via `errors.Is`): Benign rejection — the item is skipped without calling `OnMisbehavior` and without aborting the stream.
   - **Any other error**: Treated as peer misbehavior; `Engine` passes the error and raw item bytes to `OnMisbehavior` and aborts the stream.
2. **`OnMisbehavior(ctx, err, evidence)`** is the sink for non-benign errors across the pipeline. `Engine` invokes it whenever framing/digest verification, `ValidateItem`, or `ItemApplier` returns an error that does not wrap `reconcile.ErrIgnore`, then aborts the stream.

### Example

```go
type MyDetector struct{}

func (d *MyDetector) ValidateItem(ctx context.Context, item MyItem) error {
	if !verifySignature(item) {
		return fmt.Errorf("invalid signature for item %s", item.ID)
	}
	return nil
}

func (d *MyDetector) OnMisbehavior(ctx context.Context, err error, evidence []byte) {
	log.Printf("reconcile misbehavior: %v (evidence=%x)", err, evidence)
	// Optionally record a strike or accuse the peer.
}
```

If a store holds trusted or unsigned data where tamper detection is not needed, pass `reconcile.AcceptAll[T]()` (which returns `reconcile.NoopTamperDetector[T]{}`).

---

## 3. Injecting `ItemApplier[T]`

`ItemApplier[T]` is the callback invoked during Phase 2 for every incoming item that passes `Engine` checks and `TamperDetector.ValidateItem`:

```go
type ItemApplier[T any] func(ctx context.Context, item T) error
```

Use it to update application state, secondary indexes, or notify subscribers when new items arrive from a peer, as well as inserting into the store if your applier owns store writes:

```go
applier := func(ctx context.Context, item MyItem) error {
	if isStale(item) {
		// Benign rejection: skipped without calling OnMisbehavior or aborting the stream.
		return reconcile.ErrIgnore
	}
	if err := myStore.Insert(item); err != nil {
		return err
	}
	notifyListeners(item)
	return nil
}
```

`ItemApplier[T]` follows the same error semantics as `ValidateItem`:
- **`nil`**: Item is accepted and reconciliation continues.
- **`reconcile.ErrIgnore`** (or any error wrapping it): Benign skip — does not trigger `OnMisbehavior` and does not abort the stream.
- **Any other non-`nil` error**: Passed into `TamperDetector.OnMisbehavior` and aborts the reconciliation stream.
- **`reconcile.NoopApplier[T]`**: Provided when you only need a read-only/pass-through engine.

---

## 4. Multiplexing Stores with `reconcile.Mux`

`reconcile.Mux` allows a single gRPC server (and single `ReconcileService.Reconcile` RPC endpoint) to serve multiple independent reconcilable stores on the same node.

### How it works

1. Outbound callers attach the target store identifier to outgoing gRPC stream metadata under key `"store-id"` (`reconcile.StoreIDMetadataKey`). When `Config.StoreID` is non-empty, `Engine.ReconcileWithPeer` attaches this header automatically.
2. When an inbound `Reconcile` stream arrives, `Mux.Reconcile` extracts `"store-id"` from incoming gRPC metadata and looks up the registered `StreamHandler` (which `*reconcile.Engine[T]` implements via `HandleReconcile`):
   - If `"store-id"` is present and registered, the stream is dispatched to that handler.
   - If `"store-id"` is missing and **exactly one** store is registered on the `Mux`, it routes to that single store for convenience.
   - Otherwise, it returns `codes.InvalidArgument` (missing `"store-id"` with multiple/zero stores) or `codes.NotFound` (unknown `"store-id"`).
3. Optional `StreamGuard` functions passed to `NewMux(guard...)` wrap every dispatched stream (for example, to enforce admission control or rate limiting) before `handler.HandleReconcile(stream)` runs.

### Hooking a store and engine up to `Mux`

```go
// 1. Create the multiplexer (optionally with a StreamGuard) and register it on your gRPC server.
mux := reconcile.NewMux()
mux.Register(grpcServer) // registers reconpb.ReconcileServiceServer

// 2. Register each engine under its StoreID.
if err := mux.RegisterStore("views", viewEngine); err != nil {
	return err
}
if err := mux.RegisterStore("custom-kv", kvEngine); err != nil {
	return err
}
```

`Mux` also supports `ReplaceStore(storeID, handler)` to atomically swap a handler for an existing ID, and `UnregisterStore(storeID)` to remove a store at runtime.
Specifically, the engine supports resolving the incoming set reconciliation protocol at runtime through `Engine.resolveProtocol`, enabling runtime choice
of set reconciliation protocols. This may incur some cost, like constructing a riblt sketch or decoder.