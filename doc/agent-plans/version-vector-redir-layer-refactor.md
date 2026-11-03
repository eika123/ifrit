# Architecture & Refactor Plan: Grow-Only Ingestion & Version Vector Indirection Layer

## 1. Executive Summary & Problem Statement

### 1.1 Root Cause in Current Architecture
Currently, `evalNote`, `evalAccusation`, `mergeNotes`, and `mergeAccusations` in `core/handlers.go` conflate **raw storage ingestion** with **semantic validation**:
- Notes or accusations that fail signature verification, carry unknown peer certificates, contain invalid masks, target disabled rings, or carry older epochs are rejected early and **never inserted into `ReverseIndexStore`**.
- **Set Reconciliation Failure:** In distributed set reconciliation (e.g. Pinset, Invertible Bloom Filters, commutative XOR fingerprinting), nodes exchange digests of their underlying raw stores. If node $A$ stores a raw note or accusation (even if corrupt, stale, or adversarial) while node $B$ silently discards it before storage, their raw fingerprints will **diverge permanently**. Every subsequent gossip round will detect a mismatch, request the missing item, fail validation again, and remain out of sync indefinitely.

### 1.2 Core Architectural Invariant
> **"Every incoming accusation and note must be put into the reverse index stores, valid, not valid, corrupt or carrying a universe destroying bomb. The reverse index store will store it regardless, and the responsibility for handling what are the most recent notes, what are the currently active accusations etc. belong to the redirection layers."**

To enforce this invariant, we separate the system into two distinct architectural tiers:
1. **Tier 1: Grow-Only Raw Storage (`ReverseIndexStore`):** Unconditional append-only storage of all received cryptographic payloads. Computes the commutative XOR fingerprint used for network-wide set reconciliation.
2. **Tier 2: Semantic Redirection / Indirection Layer:** Evaluates certificates, signatures, ring constraints, and epoch numbers. Tracks the active state of the cluster (latest valid notes, active accusations, suspicion timers, ring topologies).

```
                  Incoming Wire Traffic (gRPC Spread, Gossip, Reconcile)
                                        │
             ┌──────────────────────────┴──────────────────────────┐
             │                                                     │
             ▼                                                     ▼
    [pb.Note Stream]                                    [pb.Accusation Stream]
             │                                                     │
═════════════╪═════════════════════════════════════════════════════╪═════════════
TIER 1: GROW-ONLY RAW STORAGE (Unconditional Ingestion)
═════════════╪═════════════════════════════════════════════════════╪═════════════
             ▼                                                     ▼
     view.NoteStore()                                   view.AccusationStore()
   (ReverseIndexStore)                                   (ReverseIndexStore)
   • Unconditional append                              • Unconditional append
   • Corrupt, forged, bomb                             • Corrupt, forged, bomb
   • Raw XOR Fingerprint                               • Raw XOR Fingerprint
             │                                                     │
═════════════╪═════════════════════════════════════════════════════╪═════════════
TIER 2: SEMANTIC & INDIRECTION LAYERS (Validation & State Promotion)
═════════════╪═════════════════════════════════════════════════════╪═════════════
             ▼                                                     ▼
       evalNote()                                           evalAccusation()
   • Check Peer Certificate                            • Check Predecessor
   • Verify ECDSA Signature                            • Verify ECDSA Signature
   • Validate Ring Mask                                • Match Target Note Epoch
             │                                                     │
       (If Valid)                                            (If Valid)
             ▼                                                     ▼
   activeNotes (VV-Mutable)                            activeAccusations (VV-Mutable)
   • Monotonic epoch advancement                       • Monotonic epoch per (peer, ring)
   • Update peer.note                                  • Suspicion timers & Rebuttals
```

---

## 2. Evaluation of `VersionVectorMutable` for Indirection Layers

### 2.1 Current State in `View` (`core/discovery/view.go`)
- **Notes:** Managed via `noteEpochs map[string]map[uint64]revIdxStore.DigestSymbol` and `Peer.note *Note`.
- **Accusations:** Managed via `activeAccusations map[string]map[uint32]activeAccusationEntry` protected by `activeAccMutex sync.RWMutex`.

### 2.2 Why `VersionVectorMutable` is the Optimal Replacement
`VersionVectorMutable` replaces these nested maps with a proven, thread-safe, monotonic data structure:
1. **Monotonic Version Enforcement:** `AddItem(VersionedItem[T])` automatically rejects items where `Version <= curr.Version`. This eliminates ad-hoc `>=` checks and race conditions.
2. **Encapsulated Concurrency:** Self-contained `sync.RWMutex` eliminates nested map locking in `View`.
3. **Active State Fingerprinting:** Produces an incremental $O(1)$ commutative XOR `Fingerprint()` of the *active semantic view*, enabling instantaneous active-state comparison independent of raw historical storage.
4. **Direct Serialization:** `Versions()` produces `map[K]uint64` in $O(N)$ without extra allocations, directly matching `pb.State.ExistingHosts`.

### 2.3 Proposed Refactoring of `VersionVectorMutable`
Currently, `VersionVectorMutable[T any, S Symbol[S]]` binds the key type directly to `S` (requiring keys to be `DigestSymbol` / uint64).
We will decouple key type `K comparable` from digest symbol `S Symbol[S]`:

```go
type VersionVectorMutable[K comparable, T any, S Symbol[S]] interface {
    AddItem(item VersionedItem[T]) (*VersionedItem[T], bool)
    GetOne(key K) (item VersionedItem[T], found bool)
    GetMany(keys []K) (items []VersionedItem[T])
    ContainsKey(key K) bool
    ContainsKeyVersion(key K, version uint64) bool
    Remove(key K) (VersionedItem[T], bool)
    RemoveVersion(key K, version uint64) bool
    Fingerprint() S
    Size() int
    Empty() bool
    Elements() []VersionedItem[T]
    Versions() map[K]uint64
    DigestsCopy() []S
    Clear()
}
```

#### Application in `View`:
1. **Note Indirection (`activeNotes`):**
   - Type: `VersionVectorMutable[string, *Note, revIdxStore.DigestSymbol]`
   - Key: `peer.Id` (`string`)
   - Item: `*Note`
   - Version: `note.epoch`
2. **Accusation Indirection (`activeAccusations`):**
   - Type: `VersionVectorMutable[string, *Accusation, revIdxStore.DigestSymbol]`
   - Key: Canonical `fmt.Sprintf("%s:%d", accusedId, ringNum)`
   - Item: `*Accusation`
   - Version: `accusation.epoch`

---

## 3. Decoupled Pipeline Design

### 3.1 Note Ingestion & Semantic Evaluation
1. **Protobuf Conversion:**
   `discovery.NoteFromPb(pbNote *pb.Note) *Note` creates an internal `Note` struct unconditionally, even if the signature is missing or fields are corrupt.
2. **Ingestion Step:**
   All incoming notes in `mergeNotes(notes []*pb.Note)`, `Spread`, and `reconcileNotes` are immediately inserted into `view.NoteStore()`.
3. **Evaluation Step (`evalNote`):**
   - Lookup peer in `fullView`. If unknown (missing certificate), return without error (the note is safely stored in `noteStore` and can be evaluated when the certificate is received).
   - Validate mask against Byzantine threshold (`view.ValidMask(mask)`).
   - Check if already superseded or equal in `activeNotes`.
   - Verify ECDSA signature against peer public key.
   - If valid:
     - `activeNotes.AddItem(...)`
     - `peer.AddNote(...)`
     - `view.PruneActiveAccusations(peer.Id, epoch)`
     - If `!view.IsAccused(peer)`: reset ping count, cancel active timers, restore to `liveStore`.

### 3.2 Accusation Ingestion & Semantic Evaluation
1. **Protobuf Conversion:**
   `discovery.AccusationFromPb(pbAcc *pb.Accusation) *Accusation` creates an internal `Accusation` struct unconditionally.
2. **Ingestion Step:**
   All incoming accusations in `mergeAccusations(accusations []*pb.Accusation)`, `Spread`, and `reconcileAccusations` are immediately inserted into `view.AccusationStore()`.
3. **Evaluation Step (`evalAccusation`):**
   - Lookup `accuser` and `accused` in `fullView`. If unknown, return without error.
   - **Self-Accusation:**
     - If accused is self: verify signature and that accuser is legitimate predecessor on `ringNum`.
     - If epoch matches current local note epoch, trigger immediate rebuttal broadcast (`node.protocol().Rebuttal(node)`).
   - **Remote Accusation:**
     - Verify signature against accuser's public key.
     - Verify accused's current note epoch matches accusation epoch.
     - Verify ring is not disabled by accused's note mask.
     - Verify accuser is the legitimate predecessor of accused on `ringNum`.
     - If valid:
       - `activeAccusations.AddItem(...)`
       - If accused is live and has no suspicion timer, start suspicion timer.

---

## 4. Step-by-Step Implementation Roadmap

### Phase 1: Generalize `VersionVectorMutable` Key Parameter
- Update `versionvector/interface.go` to `VersionVectorMutable[K comparable, T any, S Symbol[S]]`.
- Update `versionvector/version_vector_mutable.go` and `versionvector/version_vector_mutable_test.go`.
- Validate with `go test -race ./versionvector/...`.

### Phase 2: Protobuf Ingestion Decoupling
- Add `NoteFromPb` to `core/discovery/note.go`.
- Add `AccusationFromPb` to `core/discovery/accusation.go`.
- Update `mergeNotes` and `mergeAccusations` in `core/handlers.go` to unconditionally insert raw items into `NoteStore` and `AccusationStore` before evaluation.
- Update `Spread` in `core/handlers.go` to unconditionally ingest `args.GetOwnNote()`.

### Phase 3: Replace Ad-Hoc Maps in `View` with `VersionVectorMutable`
- Replace `noteEpochs` with `activeNotes VersionVectorMutable[string, *Note, revIdxStore.DigestSymbol]`.
- Replace `activeAccusations` map with `activeAccusations VersionVectorMutable[string, *Accusation, revIdxStore.DigestSymbol]`.
- Update `AddNote`, `HasNote`, `Note`, `ExistingHostsMap`, `ActiveAccusationsForPeer`, `IsAccused`, and `RingAccusation`.
- Implement `pruneActiveAccusations` using `activeAccusations.RemoveVersion` or `Remove`.

### Phase 4: Clean Up `evalNote` and `evalAccusation` & Consolidate Active Notes (Completed)
- Removed `note *Note` and `noteMutex sync.RWMutex` from `discovery.Peer`, eliminating dual source of truth and peer lock contention.
- Added `PromoteNote`, `PromoteAccusation`, `ActiveNotes`, and `SelfNote` on `discovery.View`.
- Streamlined `evalNote` and `evalAccusation` into pure semantic validators that promote validated payloads directly to the active `VersionVectorMutable` indirection layer.
- Removed redundant wrapper `recordActiveAccusation`, promoting accusations directly via `PromoteAccusation`.
- Streamlined `applyValidAccusation` to directly branch on `v.PromoteAccusation(rawAcc)` return value without redundant note lookups.
- Implemented reboot epoch catch-up in `ShouldRebuttal`: if an incoming accusation targets `epoch >= currNote.epoch`, the node jumps past it (`epoch + 1`), signs a new note, and triggers an immediate rebuttal broadcast.
- Migrated all call sites across `handlers.go`, `mutators.go`, `protocol.go`, and test suites to `View.ActiveNote` and `View.SelfNote`.

### Phase 5: Verification & Testing (Completed)
- Enforced `go fmt ./...`, `go vet ./...`, `go build ./...`.
- Updated test assertions in `view_test.go` and `handlers_test.go` for the reboot catch-up behavior.
- Verified full test suite under race detector: `go test -race -count=1 ./core/... ./versionvector/... ./examples/...`. All tests passed with 0 data races.
