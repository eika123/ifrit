package reconcile

import (
	"context"
	"encoding/json"
	"time"

	"github.com/eika123/ifrit/digestmaps"
	"google.golang.org/grpc"
)

// Store is a protocol-agnostic reconcilable store extending digestmaps.ReverseIndexStore.
// Implementations maintain internal reconciliation state (such as sketches) automatically
// on Insert / InsertBatch, keeping reconciliation mechanics hidden from callers.
type Store[T any] interface {
	digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol]
	NewReconciler(cfg Config[T]) StoreReconciler
}

// StoreReconciler reconciles a single store with a remote peer at addr.
type StoreReconciler interface {
	ReconcileWithPeer(ctx context.Context, addr string) (Summary, error)
}

// Summary reports the outcome of a single store reconciliation with a peer.
type Summary struct {
	Peer              string `json:"peer"`
	DigestsRequested  int    `json:"digests_requested"` // A \ B sent to peer
	DigestsAvailable  int    `json:"digests_available"` // B \ A fetched from peer
	ItemsSent         int    `json:"items_sent"`
	ItemsReceived     int    `json:"items_received"`
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
type ItemApplier[T any] func(ctx context.Context, item T) error

// TamperDetector provides injectable Byzantine item validation and misbehavior reporting hooks.
type TamperDetector[T any] interface {
	ValidateItem(ctx context.Context, item T) error
	OnMisbehavior(ctx context.Context, err error, evidence []byte)
}

// NoopTamperDetector is a default TamperDetector that accepts all items and ignores misbehavior.
type NoopTamperDetector[T any] struct{}

func (NoopTamperDetector[T]) ValidateItem(context.Context, T) error        { return nil }
func (NoopTamperDetector[T]) OnMisbehavior(context.Context, error, []byte) {}

// Config configures a protocol-agnostic store reconciler.
type Config[T any] struct {
	Codec           ItemCodec[T]
	ConnProvider    ConnProvider
	Auth            PeerAuthenticator
	Detector        TamperDetector[T]
	Applier         ItemApplier[T]
	SymbolBatchSize int
	MaxItemBytes    int64
	Timeout         time.Duration
	StoreID         string
}
