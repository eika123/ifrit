package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/eika123/ifrit/core/discovery"
	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	log "github.com/inconshreveable/log15"
)

// serviceRegistry holds all locally attached third-party service bindings keyed by
// validated serviceID (matching [a-z0-9._-]{1,64}, e.g. "dht", "pubsub").
type serviceRegistry struct {
	mu       sync.RWMutex
	services map[string]*localService
}

type localService struct {
	stores map[string]*serviceStoreEntry // keyed by validated storeName within the service namespace
}

func newServiceRegistry() *serviceRegistry {
	return &serviceRegistry{
		services: make(map[string]*localService),
	}
}

func (r *serviceRegistry) getOrCreateLocked(serviceID string) *localService {
	svc, ok := r.services[serviceID]
	if !ok {
		svc = &localService{
			stores: make(map[string]*serviceStoreEntry),
		}
		r.services[serviceID] = svc
	}
	return svc
}

func (r *serviceRegistry) setStore(serviceID, storeName string, entry *serviceStoreEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.getOrCreateLocked(serviceID).stores[storeName] = entry
}

func (r *serviceRegistry) storeEntry(serviceID, storeName string) *serviceStoreEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if svc, ok := r.services[serviceID]; ok {
		return svc.stores[storeName]
	}
	return nil
}

func (r *serviceRegistry) storeEntries() []*serviceStoreEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var entries []*serviceStoreEntry
	for _, svc := range r.services {
		for _, entry := range svc.stores {
			if entry != nil {
				entries = append(entries, entry)
			}
		}
	}
	return entries
}

// remove deletes all local bindings for serviceID and returns all mounted mux store IDs.
func (r *serviceRegistry) remove(serviceID string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var storeIDs []string
	if svc, ok := r.services[serviceID]; ok {
		for _, entry := range svc.stores {
			if entry != nil && entry.storeID != "" {
				storeIDs = append(storeIDs, entry.storeID)
			}
		}
		delete(r.services, serviceID)
	}
	return storeIDs
}

type serviceStoreEntry struct {
	serviceID string
	storeName string
	storeID   string // full reconcile.Mux key: "service/<serviceID>/<storeName>"
	rec       reconcile.StoreReconciler
	fpFn      func() []byte
	peerFPMu  sync.RWMutex
	peerFP    map[string][]byte // peerID -> last known remote 8-byte fingerprint
}

func (e *serviceStoreEntry) remoteFP(peerID string) []byte {
	e.peerFPMu.RLock()
	defer e.peerFPMu.RUnlock()
	return e.peerFP[peerID]
}

func (e *serviceStoreEntry) setRemoteFP(peerID string, fp []byte) {
	if len(fp) == 0 {
		return
	}
	e.peerFPMu.Lock()
	defer e.peerFPMu.Unlock()
	e.peerFP[peerID] = append([]byte(nil), fp...)
}

// RegisterService registers a third-party service on this node, creating its deterministic
// RingSuperOverlay over S_svc and publishing a signed ServiceNote into ifrit/services.
func (n *Node) RegisterService(serviceID string, version uint64, healthCheck func() bool) (*discovery.RingSuperOverlay, error) {
	if n.view == nil || n.view.ServiceDirectory() == nil {
		return nil, errors.New("service directory is not initialized")
	}
	_, overlay, err := n.view.ServiceDirectory().RegisterLocalService(n.cs, serviceID, version, healthCheck)
	if err != nil {
		return nil, err
	}
	return overlay, nil
}

// UnregisterService detaches serviceID's handlers, store reconciler, and super-overlay,
// and publishes a signed ServiceNote epoch without serviceID.
func (n *Node) UnregisterService(serviceID string) error {
	if err := discovery.ValidateServiceID(serviceID); err != nil {
		return err
	}

	if storeIDs := n.services.remove(serviceID); len(storeIDs) > 0 && n.reconcileMux != nil {
		for _, storeID := range storeIDs {
			n.reconcileMux.UnregisterStore(storeID)
		}
	}

	if n.view != nil && n.view.ServiceDirectory() != nil {
		if _, err := n.view.ServiceDirectory().UnregisterLocalService(n.cs, serviceID); err != nil {
			return err
		}
	}
	return nil
}

// AccuseServicePeer signs and records a ServiceAccusation against peerID for serviceID on ringNum.
func (n *Node) AccuseServicePeer(serviceID, peerID string, ringNum uint32) error {
	if n.view == nil || n.view.ServiceDirectory() == nil {
		return errors.New("service directory is not initialized")
	}
	peer := n.view.Peer(peerID)
	if peer == nil {
		return errNoPeer
	}
	_, err := n.view.ServiceDirectory().CreateServiceAccusation(n.cs, peer, serviceID, ringNum, n.livePeerLookup)
	return err
}

// RegisterServiceStoreReconciler mounts rec on the node's reconcile.Mux under
// "service/<serviceID>/<storeName>" and enables automatic background anti-entropy
// across the service's RingSuperOverlay.
func (n *Node) RegisterServiceStoreReconciler(serviceID, storeName string, rec reconcile.StoreReconciler, fpFn func() []byte) error {
	if err := discovery.ValidateServiceID(serviceID); err != nil {
		return err
	}
	if err := discovery.ValidateServiceID(storeName); err != nil {
		return fmt.Errorf("invalid store name %q: %w", storeName, err)
	}
	if rec == nil {
		return errors.New("service store reconciler cannot be nil")
	}
	muxStoreID := serviceStorePrefix + serviceID + "/" + storeName
	if n.reconcileMux != nil {
		if err := n.reconcileMux.ReplaceStore(muxStoreID, rec); err != nil {
			return fmt.Errorf("bind service store reconciler %q: %w", muxStoreID, err)
		}
	}
	n.services.setStore(serviceID, storeName, &serviceStoreEntry{
		serviceID: serviceID,
		storeName: storeName,
		storeID:   muxStoreID,
		rec:       rec,
		fpFn:      fpFn,
		peerFP:    make(map[string][]byte),
	})
	return nil
}

// RegisterServiceStore builds a reconcile.Engine[T] for store and attaches it to serviceID
// under "service/<serviceID>/<storeName>", giving store.Insert() transparent eventual-consistency
// replication across the service's RingSuperOverlay.
func RegisterServiceStore[T any](
	n *Node,
	serviceID string,
	storeName string,
	store digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol],
	codec reconcile.ItemCodec[T],
) error {
	if n == nil {
		return errors.New("node cannot be nil")
	}
	if store == nil {
		return reconcile.ErrMissingStore
	}
	if err := discovery.ValidateServiceID(serviceID); err != nil {
		return err
	}
	if err := discovery.ValidateServiceID(storeName); err != nil {
		return fmt.Errorf("invalid store name %q: %w", storeName, err)
	}
	if codec == nil {
		codec = reconcile.DefaultItemCodec[T]()
	}
	neg := n.defaultNegotiator
	if rs, ok := store.(reconcile.Store[T]); ok && rs.Negotiator() != nil {
		neg = rs.Negotiator()
	}
	syncCfg := n.SyncConfig()
	muxStoreID := serviceStorePrefix + serviceID + "/" + storeName
	eng, err := reconcile.NewEngine(store, reconcile.Config[T]{
		Negotiator:   neg,
		Registry:     n.reconcileRegistry,
		Codec:        codec,
		ConnProvider: n.reconcilerConnProvider(),
		Auth:         n.reconcilerPeerAuth(),
		Detector:     reconcile.AcceptAll[T](),
		Applier: func(_ context.Context, item T) error {
			store.Insert(item)
			return nil
		},
		MaxItemBytes: syncCfg.MaxItemBytes,
		Timeout:      syncCfg.Timeout,
		StoreID:      muxStoreID,
	})
	if err != nil {
		return err
	}
	return n.RegisterServiceStoreReconciler(serviceID, storeName, eng, storeFingerprintFn(store))
}

func (n *Node) reconcileServiceStores() {
	if n.view == nil || n.view.ServiceDirectory() == nil {
		return
	}

	entries := n.services.storeEntries()
	if len(entries) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, entry := range entries {
		overlay := n.view.ServiceDirectory().Overlay(entry.serviceID)
		if overlay == nil {
			continue
		}
		partners := overlay.GossipPartners()
		if len(partners) == 0 {
			continue
		}
		var localFP []byte
		if entry.fpFn != nil {
			localFP = entry.fpFn()
		}

		for _, partner := range partners {
			if len(localFP) > 0 && bytes.Equal(localFP, entry.remoteFP(partner.ID)) {
				continue
			}
			wg.Add(1)
			go func(e *serviceStoreEntry, p discovery.PeerInfo) {
				defer wg.Done()
				ctx, cancel := n.syncTimeoutContext()
				defer cancel()

				sum, err := e.rec.ReconcileWithPeer(ctx, p.Addr)
				if err != nil {
					if !isReconcilerAbortedErr(err) {
						log.Debug("Service store reconciliation failed", "service", e.serviceID, "addr", p.Addr, "err", err)
					}
					return
				}
				e.setRemoteFP(p.ID, sum.RemoteFingerprint)
			}(entry, partner)
		}
	}
	wg.Wait()
}

// Self returns the local peer's identity and RPC address.
func (n *Node) Self() discovery.PeerInfo {
	return discovery.PeerInfo{
		ID:   n.self.Id,
		Addr: n.comm.Addr(),
	}
}

// LivePeers returns all live cluster members in the base Fireflies view.
func (n *Node) LivePeers() []discovery.PeerInfo {
	live := n.view.Live()
	out := make([]discovery.PeerInfo, 0, len(live))
	for _, p := range live {
		out = append(out, discovery.PeerInfo{ID: p.Id, Addr: p.Addr})
	}
	return out
}

// Neighbours returns the RPC addresses of all direct ring neighbors in the base Fireflies view.
func (n *Node) Neighbours() []string {
	neighbours := n.view.MyNeighbours()
	out := make([]string, 0, len(neighbours))
	for _, p := range neighbours {
		out = append(out, p.Addr)
	}
	return out
}

// ServiceMembers returns all live, non-evicted peers currently hosting serviceID.
func (n *Node) ServiceMembers(serviceID string) []discovery.PeerInfo {
	if n.view == nil || n.view.ServiceDirectory() == nil {
		return nil
	}
	return n.view.ServiceDirectory().Members(serviceID)
}

// ServiceNeighbours returns the deterministic k-ring neighbors from serviceID's RingSuperOverlay.
func (n *Node) ServiceNeighbours(serviceID string) []discovery.PeerInfo {
	if n.view == nil || n.view.ServiceDirectory() == nil {
		return nil
	}
	overlay := n.view.ServiceDirectory().Overlay(serviceID)
	if overlay == nil {
		return nil
	}
	return overlay.Neighbours()
}

// ConnProvider returns a reconcile.ConnProvider borrowing pooled mTLS connections from comm.
func (n *Node) ConnProvider() reconcile.ConnProvider {
	return n.reconcilerConnProvider()
}

// PeerAuthenticator returns a reconcile.PeerAuthenticator enforcing mTLS + live-view membership.
func (n *Node) PeerAuthenticator() reconcile.PeerAuthenticator {
	return n.reconcilerPeerAuth()
}
