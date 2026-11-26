package services

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/eika123/ifrit/core/discovery"
	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	"github.com/eika123/ifrit/reconcile/naive"
	"github.com/eika123/ifrit/reconcile/ratelessIBLT"
)

const serviceStorePrefix = "service/"

type storeConfig[T any] struct {
	codec        reconcile.ItemCodec[T]
	detector     reconcile.TamperDetector[T]
	applier      reconcile.ItemApplier[T]
	negotiator   reconcile.Negotiator
	registry     *reconcile.Registry
	maxItemBytes int64
	timeout      time.Duration
}

// StoreOption configures how AttachStore builds the reconcile.Engine for a service store.
type StoreOption[T any] func(*storeConfig[T])

// WithStoreCodec sets a custom ItemCodec[T] for serializing reconciled items.
func WithStoreCodec[T any](codec reconcile.ItemCodec[T]) StoreOption[T] {
	return func(c *storeConfig[T]) {
		c.codec = codec
	}
}

// WithStoreDetector sets a TamperDetector[T] that validates incoming reconciled items.
func WithStoreDetector[T any](detector reconcile.TamperDetector[T]) StoreOption[T] {
	return func(c *storeConfig[T]) {
		c.detector = detector
	}
}

// WithStoreApplier overrides the default store.Insert(item) callback for reconciled items.
func WithStoreApplier[T any](applier reconcile.ItemApplier[T]) StoreOption[T] {
	return func(c *storeConfig[T]) {
		c.applier = applier
	}
}

// WithStoreNegotiator overrides the outbound reconciliation Negotiator.
func WithStoreNegotiator[T any](neg reconcile.Negotiator) StoreOption[T] {
	return func(c *storeConfig[T]) {
		c.negotiator = neg
	}
}

// WithStoreRegistry overrides the inbound protocol registry accepted by this store's engine.
func WithStoreRegistry[T any](reg *reconcile.Registry) StoreOption[T] {
	return func(c *storeConfig[T]) {
		c.registry = reg
	}
}

// WithStoreMaxItemBytes sets the per-item byte limit during reconciliation.
func WithStoreMaxItemBytes[T any](n int64) StoreOption[T] {
	return func(c *storeConfig[T]) {
		c.maxItemBytes = n
	}
}

// WithStoreTimeout sets the per-reconciliation RPC timeout.
func WithStoreTimeout[T any](d time.Duration) StoreOption[T] {
	return func(c *storeConfig[T]) {
		c.timeout = d
	}
}

// AttachStore builds a reconcile.Engine[T] for store and attaches it to ep under
// "service/<serviceID>/<storeName>", giving store.Insert() transparent eventual-consistency
// replication across ep's RingSuperOverlay. A single Endpoint may attach multiple
// independently named stores (e.g. "items", "meta").
func AttachStore[T any](
	ep *Endpoint,
	storeName string,
	store digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol],
	opts ...StoreOption[T],
) error {
	if ep == nil || ep.host == nil {
		return errors.New("services: endpoint cannot be nil")
	}
	if store == nil {
		return reconcile.ErrMissingStore
	}
	if err := discovery.ValidateServiceID(storeName); err != nil {
		return fmt.Errorf("services: invalid store name %q: %w", storeName, err)
	}

	var cfg storeConfig[T]
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if cfg.codec == nil {
		cfg.codec = reconcile.DefaultItemCodec[T]()
	}
	if cfg.detector == nil {
		cfg.detector = reconcile.AcceptAll[T]()
	}
	if cfg.applier == nil {
		cfg.applier = func(_ context.Context, item T) error {
			store.Insert(item)
			return nil
		}
	}
	if cfg.negotiator == nil {
		if rs, ok := store.(reconcile.Store[T]); ok && rs.Negotiator() != nil {
			cfg.negotiator = rs.Negotiator()
		} else {
			cfg.negotiator = ratelessIBLT.NewNegotiator()
		}
	}
	if cfg.registry == nil {
		reg, err := reconcile.NewRegistry(
			ratelessIBLT.NewNegotiator(),
			naive.NewNegotiator(),
		)
		if err != nil {
			return err
		}
		cfg.registry = reg
	}

	muxStoreID := serviceStorePrefix + ep.ID() + "/" + storeName
	eng, err := reconcile.NewEngine(store, reconcile.Config[T]{
		Negotiator:   cfg.negotiator,
		Registry:     cfg.registry,
		Codec:        cfg.codec,
		ConnProvider: ep.host.ConnProvider(),
		Auth:         ep.host.PeerAuthenticator(),
		Detector:     cfg.detector,
		Applier:      cfg.applier,
		MaxItemBytes: cfg.maxItemBytes,
		Timeout:      cfg.timeout,
		StoreID:      muxStoreID,
	})
	if err != nil {
		return err
	}
	return ep.RegisterStoreReconciler(storeName, eng, storeFingerprintFn(store))
}

func storeFingerprintFn[T any](store digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol]) func() []byte {
	return func() []byte {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(store.Fingerprint()))
		return buf[:]
	}
}
