package core

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/eika123/ifrit/core/discovery"
	"github.com/eika123/ifrit/crypto/pki"
	"github.com/eika123/ifrit/digestmaps"
	pb "github.com/eika123/ifrit/protobuf"
	"github.com/eika123/ifrit/reconcile"
	"github.com/eika123/ifrit/reconcile/naive"
	"github.com/eika123/ifrit/reconcile/ratelessIBLT"
	"github.com/golang/protobuf/proto"
	log "github.com/inconshreveable/log15"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	storeIDCerts = "certs"
	storeIDNotes = "notes"
	storeIDAccs  = "accusations"
	storeIDData  = "data"
)

// ControlReconcilerHooks defines injectable validation and application hooks for
// control store reconciliation.
type ControlReconcilerHooks struct {
	CertDetector reconcile.TamperDetector[*pki.Certificate]
	CertApplier  reconcile.ItemApplier[*pki.Certificate]

	NoteDetector reconcile.TamperDetector[*discovery.Note]
	NoteApplier  reconcile.ItemApplier[*discovery.Note]

	AccDetector reconcile.TamperDetector[*discovery.Accusation]
	AccApplier  reconcile.ItemApplier[*discovery.Accusation]
}

// --- Protobuf ItemCodecs for control items ---

type certCodec struct{}

func (certCodec) Encode(c *pki.Certificate) ([]byte, error) {
	if c == nil {
		return nil, errors.New("cannot encode nil certificate")
	}
	return proto.Marshal(c.ToPbMsg())
}

func (certCodec) Decode(data []byte) (*pki.Certificate, error) {
	var msg pb.Certificate
	if err := proto.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return pki.CertificateFromPb(&msg), nil
}

type noteCodec struct{}

func (noteCodec) Encode(n *discovery.Note) ([]byte, error) {
	if n == nil {
		return nil, errors.New("cannot encode nil note")
	}
	return proto.Marshal(n.ToPbMsg())
}

func (noteCodec) Decode(data []byte) (*discovery.Note, error) {
	var msg pb.Note
	if err := proto.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return discovery.NoteFromPb(&msg), nil
}

type accusationCodec struct{}

func (accusationCodec) Encode(a *discovery.Accusation) ([]byte, error) {
	if a == nil {
		return nil, errors.New("cannot encode nil accusation")
	}
	return proto.Marshal(a.ToPbMsg())
}

func (accusationCodec) Decode(data []byte) (*discovery.Accusation, error) {
	var msg pb.Accusation
	if err := proto.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return discovery.AccusationFromPb(&msg), nil
}

// SyncConfig defines streaming transfer limits and timeouts.
type SyncConfig struct {
	MaxItemBytes int64         // Maximum byte size of a single item (default 64 MB; <= 0 disables limit)
	Timeout      time.Duration // Timeout for a reconciliation session (default 30s)
}

// DefaultSyncConfig returns standard reconciliation streaming parameters.
func DefaultSyncConfig() SyncConfig {
	return SyncConfig{
		MaxItemBytes: 1024 * 1024 * 64,
		Timeout:      30 * time.Second,
	}
}

// SyncConfig returns the node's active streaming configuration.
func (n *Node) SyncConfig() SyncConfig {
	return n.syncConfig
}

func isNaiveStrategy(strategy string) bool {
	s := strings.ToLower(strings.TrimSpace(strategy))
	return s == "naive" || s == naive.ProtocolName
}

func newControlViewStores(strategy string) (*discovery.ViewStores, error) {
	if isNaiveStrategy(strategy) {
		certs, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[*pki.Certificate]())
		if err != nil {
			return nil, err
		}
		notes, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[*discovery.Note]())
		if err != nil {
			return nil, err
		}
		accs, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[*discovery.Accusation]())
		if err != nil {
			return nil, err
		}
		return &discovery.ViewStores{
			Certs:       certs,
			Notes:       notes,
			Accusations: accs,
		}, nil
	}

	certs, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[*pki.Certificate]())
	if err != nil {
		return nil, err
	}
	notes, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[*discovery.Note]())
	if err != nil {
		return nil, err
	}
	accs, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[*discovery.Accusation]())
	if err != nil {
		return nil, err
	}
	return &discovery.ViewStores{
		Certs:       certs,
		Notes:       notes,
		Accusations: accs,
	}, nil
}

func (n *Node) inboundStreamGuard() reconcile.StreamGuard {
	return func(ctx context.Context, next func() error) error {
		if n == nil || n.peerGate == nil {
			return next()
		}
		cert, err := n.validateCtx(ctx)
		if err != nil {
			// Unauthenticated caller: let inner PeerAuthenticator handle error/telemetry.
			return next()
		}
		remoteID := string(cert.SubjectKeyId)
		if n.view == nil || n.view.Peer(remoteID) == nil {
			// Unrecognized peer (e.g. cold bootstrap before admission): let inner PeerAuthenticator handle PermissionDenied.
			return next()
		}
		selfID := ""
		if n.self != nil {
			selfID = n.self.Id
		}
		if err := n.peerGate.TryStartInbound(selfID, remoteID); err != nil {
			return status.Errorf(codes.Aborted, "reconciliation session busy: %v", err)
		}
		defer n.peerGate.ReleaseInbound(remoteID)
		return next()
	}
}

func (n *Node) initControlReconcilers(hooks ControlReconcilerHooks) error {
	ribltNeg := ratelessIBLT.NewNegotiator()
	naiveNeg := naive.NewNegotiator()
	reg, err := reconcile.NewRegistry(ribltNeg, naiveNeg)
	if err != nil {
		return err
	}
	n.reconcileRegistry = reg
	if isNaiveStrategy(n.reconciliationStrategy) {
		n.defaultNegotiator = naiveNeg
	} else {
		n.defaultNegotiator = ribltNeg
	}
	n.reconcileMux = reconcile.NewMux(n.inboundStreamGuard())
	if err := n.rebuildControlReconcilers(hooks); err != nil {
		return err
	}
	n.reconcileMux.Register(n.comm)
	return nil
}

// setControlReconcilerHooks swaps the control store validation/applier hooks
// and re-binds the control store reconcilers on the node's store mux (for tests).
func (n *Node) setControlReconcilerHooks(hooks ControlReconcilerHooks) {
	if err := n.rebuildControlReconcilers(hooks); err != nil {
		log.Error("failed to rebuild control reconcilers", "err", err)
	}
}

func (n *Node) reconcilerConnProvider() reconcile.ConnProvider {
	return func(_ context.Context, addr string) (grpc.ClientConnInterface, error) {
		return n.comm.ClientConn(addr)
	}
}

func (n *Node) reconcilerPeerAuth() reconcile.PeerAuthenticator {
	return func(ctx context.Context) error {
		cert, err := n.validateCtx(ctx)
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "invalid caller cert: %v", err)
		}
		remoteID := string(cert.SubjectKeyId)
		if n.view.Peer(remoteID) == nil {
			return status.Errorf(codes.PermissionDenied, "caller not recognized in view: %x", remoteID)
		}
		return nil
	}
}

func buildControlReconciler[T any](
	n *Node,
	store digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol],
	storeID string,
	codec reconcile.ItemCodec[T],
	detector reconcile.TamperDetector[T],
	applier reconcile.ItemApplier[T],
) (reconcile.StoreReconciler, error) {
	if store == nil {
		return nil, nil
	}
	if detector == nil {
		detector = reconcile.AcceptAll[T]()
	}
	syncCfg := n.SyncConfig()
	eng, err := reconcile.NewEngine(store, reconcile.Config[T]{
		Negotiator:   n.defaultNegotiator,
		Registry:     n.reconcileRegistry,
		Codec:        codec,
		ConnProvider: n.reconcilerConnProvider(),
		Auth:         n.reconcilerPeerAuth(),
		Detector:     detector,
		Applier:      applier,
		MaxItemBytes: syncCfg.MaxItemBytes,
		Timeout:      syncCfg.Timeout,
		StoreID:      storeID,
	})
	if err != nil {
		return nil, err
	}
	if n.reconcileMux != nil {
		if err := n.reconcileMux.ReplaceStore(storeID, eng); err != nil {
			return nil, err
		}
	}
	return eng, nil
}

func (n *Node) rebuildControlReconcilers(hooks ControlReconcilerHooks) error {
	var err error
	n.certReconciler, err = buildControlReconciler(n, n.view.CertStore(), storeIDCerts, certCodec{}, hooks.CertDetector, hooks.CertApplier)
	if err != nil {
		return err
	}
	n.noteReconciler, err = buildControlReconciler(n, n.view.NoteStore(), storeIDNotes, noteCodec{}, hooks.NoteDetector, hooks.NoteApplier)
	if err != nil {
		return err
	}
	n.accReconciler, err = buildControlReconciler(n, n.view.AccusationStore(), storeIDAccs, accusationCodec{}, hooks.AccDetector, hooks.AccApplier)
	return err
}

func (n *Node) registerStoreReconciler(rec reconcile.StoreReconciler, fingerprintFn func() []byte) {
	n.dataReconcilerMutex.Lock()
	n.dataStoreReconciler = rec
	n.dataStoreFP = fingerprintFn
	n.dataReconcilerMutex.Unlock()
	if n.reconcileMux != nil && rec != nil {
		if err := n.reconcileMux.ReplaceStore(storeIDData, rec); err != nil {
			log.Error("failed to bind data store reconciler", "err", err)
		}
	}
}

// reconcileControlStores runs control store reconciliation strictly sequentially in
// causal dependency order: certs -> notes -> accusations.
func (n *Node) reconcileControlStores(ctx context.Context, addr string) (certFP, noteFP, accFP []byte, err error) {
	if n.certReconciler != nil {
		sum, err := n.certReconciler.ReconcileWithPeer(ctx, addr)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reconcile certs: %w", err)
		}
		certFP = sum.RemoteFingerprint
	}
	if n.noteReconciler != nil {
		sum, err := n.noteReconciler.ReconcileWithPeer(ctx, addr)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reconcile notes: %w", err)
		}
		noteFP = sum.RemoteFingerprint
	}
	if n.accReconciler != nil {
		sum, err := n.accReconciler.ReconcileWithPeer(ctx, addr)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reconcile accusations: %w", err)
		}
		accFP = sum.RemoteFingerprint
	}
	return certFP, noteFP, accFP, nil
}

// reconcilePeerStores executes sequential control reconciliation (certs -> notes -> accusations)
// concurrently with application data store reconciliation, updating peer fingerprints on completion.
func (n *Node) reconcilePeerStores(ctx context.Context, peer *discovery.Peer) error {
	if peer == nil {
		return errors.New("reconcilePeerStores: peer cannot be nil")
	}

	n.dataReconcilerMutex.RLock()
	dataRec := n.dataStoreReconciler
	n.dataReconcilerMutex.RUnlock()

	var (
		wg      sync.WaitGroup
		ctrlErr error
		dataErr error
		certFP  []byte
		noteFP  []byte
		accFP   []byte
		dataFP  []byte
	)

	wg.Go(func() {
		certFP, noteFP, accFP, ctrlErr = n.reconcileControlStores(ctx, peer.Addr)
	})

	if dataRec != nil {
		wg.Go(func() {
			sum, err := dataRec.ReconcileWithPeer(ctx, peer.Addr)
			dataErr = err
			dataFP = sum.RemoteFingerprint
		})
	}

	wg.Wait()

	if ctrlErr != nil {
		return ctrlErr
	}
	if dataErr != nil {
		return dataErr
	}

	viewFP := xorFingerprintBytes(certFP, noteFP)
	peer.SetFingerprints(dataFP, accFP, viewFP)
	return nil
}

func xorFingerprintBytes(a, b []byte) []byte {
	if len(a) != 8 || len(b) != 8 {
		return nil
	}
	va := binary.BigEndian.Uint64(a)
	vb := binary.BigEndian.Uint64(b)
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], va^vb)
	return out[:]
}

func storeFingerprintFn[T any](store digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol]) func() []byte {
	return func() []byte {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(store.Fingerprint()))
		return buf[:]
	}
}

// RegisterReconcilableDataStore binds a ReverseIndexStore[T] and reconcile.ItemCodec[T]
// as the node's application data store for StoreReconciler gossip.
// If store implements reconcile.Store[T], its declared Negotiator is used for outbound
// reconciliation; otherwise the node's default Negotiator is used. Inbound streams accept
// any Negotiator registered in the node's protocol registry.
func RegisterReconcilableDataStore[T any](
	n *Node,
	store digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol],
	codec reconcile.ItemCodec[T],
) {
	if n == nil || store == nil {
		return
	}
	if codec == nil {
		codec = reconcile.DefaultItemCodec[T]()
	}
	neg := n.defaultNegotiator
	if rs, ok := store.(reconcile.Store[T]); ok && rs.Negotiator() != nil {
		neg = rs.Negotiator()
	}
	syncCfg := n.SyncConfig()
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
		StoreID:      storeIDData,
	})
	if err != nil {
		log.Error("failed to create data store reconciler", "err", err)
		return
	}
	n.registerStoreReconciler(eng, storeFingerprintFn(store))
}

// --- TamperDetector + ItemApplier hooks wired to evalXYZ ---

type certControlDetector struct {
	node *Node
}

func (d certControlDetector) ValidateItem(_ context.Context, item *pki.Certificate) error {
	_, err := d.node.validateCertItem(item)
	return err
}

func (certControlDetector) OnMisbehavior(_ context.Context, err error, _ []byte) {
	log.Debug("Control cert reconciliation misbehavior", "err", err)
}

type noteControlDetector struct {
	node *Node
}

func (d noteControlDetector) ValidateItem(_ context.Context, item *discovery.Note) error {
	if item == nil {
		return errors.New("nil note")
	}
	_, err := d.node.validateNotePb(item.ToPbMsg())
	return err
}

func (noteControlDetector) OnMisbehavior(_ context.Context, err error, _ []byte) {
	log.Debug("Control note reconciliation misbehavior", "err", err)
}

type accControlDetector struct {
	node *Node
}

func (d accControlDetector) ValidateItem(_ context.Context, item *discovery.Accusation) error {
	if item == nil {
		return errors.New("nil accusation")
	}
	_, err := d.node.validateAccusationPb(item.ToPbMsg())
	return err
}

func (accControlDetector) OnMisbehavior(_ context.Context, err error, _ []byte) {
	log.Debug("Control accusation reconciliation misbehavior", "err", err)
}

func (n *Node) defaultControlReconcilerHooks() ControlReconcilerHooks {
	return ControlReconcilerHooks{
		CertDetector: certControlDetector{node: n},
		CertApplier: func(_ context.Context, item *pki.Certificate) error {
			if item == nil || len(item.Raw()) == 0 {
				return errNilCert
			}
			cert, err := x509.ParseCertificate(item.Raw())
			if err != nil {
				return err
			}
			if n.self != nil && n.self.Id == string(cert.SubjectKeyId) {
				return fmt.Errorf("%w: self certificate", reconcile.ErrIgnore)
			}
			return n.applyVerifiedCert(item, cert)
		},
		NoteDetector: noteControlDetector{node: n},
		NoteApplier: func(_ context.Context, item *discovery.Note) error {
			if item == nil {
				return errors.New("nil note")
			}
			pbNote := item.ToPbMsg()
			if n.self != nil && n.self.Id == string(pbNote.GetId()) {
				return fmt.Errorf("%w: self note", reconcile.ErrIgnore)
			}
			peer := n.view.Peer(string(pbNote.GetId()))
			if peer == nil {
				return errNoPeer
			}
			err := n.applyVerifiedNote(pbNote, peer)
			if errors.Is(err, errOldNote) {
				return fmt.Errorf("%w: %w", reconcile.ErrIgnore, err)
			}
			return err
		},
		AccDetector: accControlDetector{node: n},
		AccApplier: func(_ context.Context, item *discovery.Accusation) error {
			if item == nil {
				return errors.New("nil accusation")
			}
			pbAcc := item.ToPbMsg()
			accuserID := string(pbAcc.GetAccuser())
			var accuser *discovery.Peer
			if n.self != nil && accuserID == n.self.Id {
				accuser = n.self
			} else {
				accuser = n.view.Peer(accuserID)
			}
			if accuser == nil {
				return errNoPeer
			}

			err := n.applyVerifiedAccusation(pbAcc, accuser)
			if errors.Is(err, errAccAlreadyExists) ||
				errors.Is(err, errInvalidEpoch) ||
				errors.Is(err, errInvalidAccuser) ||
				errors.Is(err, errDisabledRing) ||
				errors.Is(err, errInvalidSelfAccusation) {
				log.Debug(err.Error(), "ringNum", pbAcc.GetRingNum(), "epoch", pbAcc.GetEpoch())
				return fmt.Errorf("%w: %w", reconcile.ErrIgnore, err)
			}
			return err
		},
	}
}

func (n *Node) syncTimeoutContext() (context.Context, context.CancelFunc) {
	baseCtx := n.syncCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	timeout := n.SyncConfig().Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return context.WithTimeout(baseCtx, timeout)
}

func (n *Node) reconcileBootstrapControl(addr string) error {
	ctx, cancel := n.syncTimeoutContext()
	defer cancel()
	_, _, _, err := n.reconcileControlStores(ctx, addr)
	return err
}

func (n *Node) admitViaThinSpread(addr string, target ...*discovery.Peer) error {
	msg := &pb.State{}
	if n.view != nil {
		if selfNote := n.view.SelfNote(); selfNote != nil {
			msg.OwnNote = selfNote.ToPbMsg()
		}
	}
	if adv := n.AdversarialPolicy(); adv != nil && adv.OnGossipOut != nil {
		var p *discovery.Peer
		if len(target) > 0 {
			p = target[0]
		}
		adv.OnGossipOut(p, msg)
	}
	reply, err := n.comm.Gossip(addr, msg)
	if err != nil {
		return err
	}
	if accs := reply.GetAccusations(); len(accs) > 0 {
		n.mergeAccusations(accs)
	}
	return nil
}

func grpcStatusCode(err error) (codes.Code, bool) {
	if err == nil {
		return codes.OK, false
	}
	var se interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &se) {
		return codes.OK, false
	}
	return se.GRPCStatus().Code(), true
}

func isReconcilerAuthErr(err error) bool {
	code, ok := grpcStatusCode(err)
	return ok && (code == codes.PermissionDenied || code == codes.Unauthenticated)
}

func isReconcilerAbortedErr(err error) bool {
	code, ok := grpcStatusCode(err)
	return ok && code == codes.Aborted
}

func (n *Node) gossipWithStoreReconcilers() {
	neighbours := n.view.GossipPartners()
	var wg sync.WaitGroup

	for _, peer := range neighbours {
		if !n.IsDivergent(peer) {
			continue
		}

		if n.peerGate != nil && !n.peerGate.TryStartOutbound(peer.Id) {
			continue
		}

		wg.Add(1)
		go func(p *discovery.Peer) {
			defer wg.Done()
			if n.peerGate != nil {
				defer n.peerGate.ReleaseOutbound(p.Id)
			}

			ctx, cancel := n.syncTimeoutContext()
			defer cancel()

			err := n.reconcilePeerStores(ctx, p)
			if err != nil && isReconcilerAuthErr(err) {
				if admitErr := n.admitViaThinSpread(p.Addr, p); admitErr != nil {
					log.Debug("Thin Spread re-admission failed", "addr", p.Addr, "err", admitErr)
					return
				}
				err = n.reconcilePeerStores(ctx, p)
			}
			if isReconcilerAbortedErr(err) {
				log.Debug("Outbound reconciliation aborted by peer tie-breaker", "addr", p.Addr)
				return
			}
			if err != nil {
				log.Error("Peer store reconciliation failed", "addr", p.Addr, "err", err)
			}
		}(peer)
	}

	wg.Wait()
}
