package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/eika123/ifrit/digestmaps"
	reconpb "github.com/eika123/ifrit/reconcile/proto"
	"google.golang.org/grpc"
)

const (
	// StoreIDMetadataKey is the gRPC metadata key used to route multiplexed reconciliation streams.
	StoreIDMetadataKey = "store-id"
	// ProtocolMetadataKey is the gRPC metadata key selecting the Phase 1 Negotiator protocol.
	ProtocolMetadataKey = "reconcile-protocol"

	DefaultMaxWantDigests         = 1 << 20
	DefaultMaxNegotiateFrameBytes = 16 * 1024 * 1024
	DefaultMaxDrainFrames         = 4096
	DefaultMaxDrainBytes          = 32 * 1024 * 1024
)

var (
	ErrMissingStore           = errors.New("reconcile: store is required")
	ErrMissingConnProvider    = errors.New("reconcile: ConnProvider is required")
	ErrMissingAuthenticator   = errors.New("reconcile: PeerAuthenticator is required")
	ErrMissingNegotiator      = errors.New("reconcile: Negotiator or Registry is required")
	ErrMissingDetector        = errors.New("reconcile: TamperDetector is required (use AcceptAll[T]() to opt out)")
	ErrMissingCodec           = errors.New("reconcile: ItemCodec is required (use DefaultItemCodec[T]() for standard types)")
	ErrMissingApplier         = errors.New("reconcile: ItemApplier is required (use NoopApplier[T] for dry-runs)")
	ErrUnknownProtocol        = errors.New("reconcile: unknown reconciliation protocol")
	ErrStoreAlreadyRegistered = errors.New("reconcile: store already registered")
	ErrSessionLimitExceeded   = errors.New("reconcile: session resource limit exceeded")
	ErrIgnore                 = errors.New("reconcile: ignore item")
	ErrFramingViolation       = errors.New("reconcile: stream framing violation")
	ErrUnexpectedDigest       = errors.New("reconcile: received unexpected digest not in allowlist")
	ErrUnexpectedSyncFrame    = errors.New("reconcile: received unexpected data frame when zero items expected")
	ErrItemSizeLimitExceeded  = errors.New("reconcile: item size exceeds configured maximum")
	ErrNegotiationClosed      = errors.New("reconcile: negotiation send side already closed")
)

// NoopAuthenticator is an explicit opt-in PeerAuthenticator for standalone tests and benchmarks.
func NoopAuthenticator(context.Context) error { return nil }

// StreamHandler serves inbound single-RPC Reconcile streams for a single store.
type StreamHandler interface {
	HandleReconcile(stream reconpb.ReconcileService_ReconcileServer) error
}

// Store is a protocol-tagged reconcilable store extending digestmaps.ReverseIndexStore.
// Implementations maintain any protocol-specific auxiliary state (such as sketches)
// automatically on Insert / InsertBatch and declare their default Phase 1 Negotiator.
type Store[T any] interface {
	digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol]
	Negotiator() Negotiator
}

// StoreReconciler reconciles a single store with a remote peer at addr and handles
// inbound reconciliation streams for that store on a Mux.
type StoreReconciler interface {
	ReconcileWithPeer(ctx context.Context, addr string) (Summary, error)
	StreamHandler
}

// Summary reports the outcome of a single store reconciliation with a peer.
type Summary struct {
	Peer              string `json:"peer"`
	DigestsRequested  int    `json:"digests_requested"` // A \ B sent to peer
	DigestsAvailable  int    `json:"digests_available"` // B \ A fetched from peer
	ItemsSent         int    `json:"items_sent"`
	ItemsReceived     int    `json:"items_received"`
	ItemsIgnored      int    `json:"items_ignored,omitempty"`
	RemoteFingerprint []byte `json:"remote_fingerprint,omitempty"`
	UsedFallback      bool   `json:"used_fallback"`
}

// ItemCodec serializes and deserializes items during transfer.
type ItemCodec[T any] interface {
	Encode(item T) ([]byte, error)
	Decode(data []byte) (T, error)
}

// JSONCodec implements ItemCodec[T] using encoding/json.
type JSONCodec[T any] struct{}

func (JSONCodec[T]) Encode(item T) ([]byte, error) {
	return json.Marshal(item)
}

func (JSONCodec[T]) Decode(data []byte) (T, error) {
	var item T
	err := json.Unmarshal(data, &item)
	return item, err
}

// ConnProvider returns a gRPC ClientConnInterface for the given peer address.
// Pooled connections returned by a ConnProvider are NOT closed by the reconciler.
type ConnProvider func(ctx context.Context, addr string) (grpc.ClientConnInterface, error)

// PeerAuthenticator validates an incoming gRPC stream context (e.g. mTLS cert / view admission).
type PeerAuthenticator func(ctx context.Context) error

// ItemApplier applies a decoded, validated item into local storage.
// Returning an error wrapping ErrIgnore skips the item without triggering OnMisbehavior
// or aborting the reconciliation stream.
type ItemApplier[T any] func(ctx context.Context, item T) error

// NoopApplier is an explicit opt-in ItemApplier that discards validated items without
// mutating local storage (useful for benchmarks and dry-run tests).
func NoopApplier[T any](context.Context, T) error { return nil }

// TamperDetector provides injectable Byzantine item validation and misbehavior reporting hooks.
// ValidateItem returning an error wrapping ErrIgnore skips the item without triggering
// OnMisbehavior or aborting the reconciliation stream.
type TamperDetector[T any] interface {
	ValidateItem(ctx context.Context, item T) error
	OnMisbehavior(ctx context.Context, err error, evidence []byte)
}

// NoopTamperDetector accepts all items and ignores misbehavior reports.
type NoopTamperDetector[T any] struct{}

func (NoopTamperDetector[T]) ValidateItem(context.Context, T) error        { return nil }
func (NoopTamperDetector[T]) OnMisbehavior(context.Context, error, []byte) {}

// AcceptAll returns a TamperDetector that explicitly accepts all items without validation.
func AcceptAll[T any]() TamperDetector[T] {
	return NoopTamperDetector[T]{}
}

// Config configures a protocol-agnostic store reconciliation Engine.
type Config[T any] struct {
	Negotiator     Negotiator
	Registry       *Registry
	Codec          ItemCodec[T]
	ConnProvider   ConnProvider
	Auth           PeerAuthenticator
	Detector       TamperDetector[T]
	Applier        ItemApplier[T]
	MaxItemBytes   int64
	MaxWantDigests int
	Timeout        time.Duration
	StoreID        string
}
