package core

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/eika123/ifrit/core/discovery"
	"github.com/eika123/ifrit/crypto/pki"
	"github.com/eika123/ifrit/digestmaps"
	pb "github.com/eika123/ifrit/protobuf"
	"github.com/eika123/ifrit/reconcile"
	"github.com/eika123/ifrit/reconcile/naive"
	"github.com/eika123/ifrit/reconcile/ratelessIBLT"
	"github.com/eika123/ifrit/reconcile/transfer"
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
	ChunkBytes       int           // Deprecated: kept for API compatibility
	MaxItemBytes     int64         // Maximum byte size of a single item (default 64 MB; <= 0 disables limit)
	ControlBatchSize int           // Deprecated: kept for API compatibility
	Timeout          time.Duration // Timeout for a reconciliation session (default 30s)
}

// DefaultSyncConfig returns standard reconciliation streaming parameters.
func DefaultSyncConfig() SyncConfig {
	return SyncConfig{
		ChunkBytes:       1024 * 128,
		MaxItemBytes:     1024 * 1024 * 64,
		ControlBatchSize: 128,
		Timeout:          30 * time.Second,
	}
}

// SetSyncConfig updates the streaming configuration on the node.
func (n *Node) SetSyncConfig(cfg SyncConfig) {
	n.syncConfigMutex.Lock()
	defer n.syncConfigMutex.Unlock()
	n.syncConfig = cfg
}

// SyncConfig returns the node's active streaming configuration.
func (n *Node) SyncConfig() SyncConfig {
	n.syncConfigMutex.RLock()
	defer n.syncConfigMutex.RUnlock()
	return n.syncConfig
}

func newControlViewStores(strategy string) (*discovery.ViewStores, error) {
	if strategy == "naive" {
		certs, err := naive.NewReconcilableStore(digestmaps.MustDefaultHasher[*pki.Certificate]())
		if err != nil {
			return nil, err
		}
		notes, err := naive.NewReconcilableStore(digestmaps.MustDefaultHasher[*discovery.Note]())
		if err != nil {
			return nil, err
		}
		accs, err := naive.NewReconcilableStore(digestmaps.MustDefaultHasher[*discovery.Accusation]())
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

func (n *Node) inboundStreamGuard() transfer.StreamGuard {
	return func(ctx context.Context, next func() error) error {
		if n == nil || n.sessionManager == nil {
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
		sess := n.sessionManager.GetOrCreate(remoteID)
		seq, ok, err := sess.TryStartInboundReconciling(selfID, remoteID)
		if !ok {
			return status.Errorf(codes.Aborted, "reconciliation session busy: %v", err)
		}
		defer sess.ReleaseInbound(seq)
		return next()
	}
}

type reconcilerMux interface {
	RegisterStore(storeID string, handler any)
	RegisterGRPC(s *grpc.Server)
}

func (n *Node) initControlReconcilers(hooks ControlReconcilerHooks) {
	var mux reconcilerMux
	if n.reconciliationStrategy == "naive" {
		mux = naive.NewReconcilerMux(n.inboundStreamGuard())
	} else {
		mux = ratelessIBLT.NewReconcilerMux(n.inboundStreamGuard())
	}
	n.bindStoreServer = func(storeID string, handler any) {
		mux.RegisterStore(storeID, handler)
	}
	n.rebuildControlReconcilers(hooks)
	n.comm.RegisterGRPC(mux.RegisterGRPC)
}

// SetControlReconcilerHooks swaps the control store validation/applier hooks
// and re-binds the control store reconcilers on the node's store server.
func (n *Node) SetControlReconcilerHooks(hooks ControlReconcilerHooks) {
	n.rebuildControlReconcilers(hooks)
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
) reconcile.StoreReconciler {
	rs, ok := store.(reconcile.Store[T])
	if !ok || rs == nil {
		return nil
	}
	syncCfg := n.SyncConfig()
	rec := rs.NewReconciler(reconcile.Config[T]{
		Codec:        codec,
		ConnProvider: n.reconcilerConnProvider(),
		Auth:         n.reconcilerPeerAuth(),
		Detector:     detector,
		Applier:      applier,
		MaxItemBytes: syncCfg.MaxItemBytes,
		Timeout:      syncCfg.Timeout,
		StoreID:      storeID,
	})
	if n.bindStoreServer != nil {
		n.bindStoreServer(storeID, rec)
	}
	return rec
}

func (n *Node) rebuildControlReconcilers(hooks ControlReconcilerHooks) {
	n.certReconciler = buildControlReconciler(n, n.view.CertStore(), storeIDCerts, certCodec{}, hooks.CertDetector, hooks.CertApplier)
	n.noteReconciler = buildControlReconciler(n, n.view.NoteStore(), storeIDNotes, noteCodec{}, hooks.NoteDetector, hooks.NoteApplier)
	n.accReconciler = buildControlReconciler(n, n.view.AccusationStore(), storeIDAccs, accusationCodec{}, hooks.AccDetector, hooks.AccApplier)
}

func (n *Node) registerStoreReconciler(rec reconcile.StoreReconciler, fingerprintpFn func() []byte) {
	n.dataReconcilerMutex.Lock()
	n.dataStoreReconciler = rec
	n.dataStoreFP = fingerprintpFn
	n.dataReconcilerMutex.Unlock()
	if n.bindStoreServer != nil && rec != nil {
		n.bindStoreServer(storeIDData, rec)
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

// RegisterReconcilableDataStore binds a reconcile.Store[T] and reconcile.ItemCodec[T]
// as the node's application data store for StoreReconciler gossip.
func RegisterReconcilableDataStore[T any](
	n *Node,
	store reconcile.Store[T],
	codec reconcile.ItemCodec[T],
) {
	if n == nil || store == nil {
		return
	}
	if codec == nil {
		codec = reconcile.DefaultItemCodec[T]()
	}
	syncCfg := n.SyncConfig()
	rec := store.NewReconciler(reconcile.Config[T]{
		Codec:        codec,
		ConnProvider: n.reconcilerConnProvider(),
		Auth:         n.reconcilerPeerAuth(),
		MaxItemBytes: syncCfg.MaxItemBytes,
		Timeout:      syncCfg.Timeout,
		StoreID:      storeIDData,
	})
	n.registerStoreReconciler(rec, storeFingerprintFn(store))
}

// --- Phase 2B: Production TamperDetector + ItemApplier hooks wired to evalXYZ ---

type certControlDetector struct {
	node *Node
}

func (d certControlDetector) ValidateItem(_ context.Context, item *pki.Certificate) error {
	if item == nil || len(item.Raw()) == 0 {
		return errNilCert
	}
	cert, err := x509.ParseCertificate(item.Raw())
	if err != nil {
		return err
	}
	if d.node.self != nil && d.node.self.Id == string(cert.SubjectKeyId) {
		return nil
	}
	return d.node.validateCertificate(cert)
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
	pbNote := item.ToPbMsg()
	if d.node.self != nil && d.node.self.Id == string(pbNote.GetId()) {
		return nil
	}
	sign := pbNote.GetSignature()
	if sign == nil {
		return errInvalidSignature
	}
	peer := d.node.view.Peer(string(pbNote.GetId()))
	if peer == nil {
		return errNoPeer
	}
	if !d.node.view.ValidMask(pbNote.GetMask()) {
		return errInvalidMask
	}
	return d.node.verifySignedMessage(pbNote, sign, peer)
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
	pbAcc := item.ToPbMsg()
	accuserID := string(pbAcc.GetAccuser())

	var accuser *discovery.Peer
	if d.node.self != nil && accuserID == d.node.self.Id {
		accuser = d.node.self
	} else {
		accuser = d.node.view.Peer(accuserID)
	}
	if accuser == nil {
		return errNoPeer
	}
	if err := d.node.verifySignedMessage(pbAcc, pbAcc.GetSignature(), accuser); err != nil {
		return err
	}
	if pbAcc.GetRingNum() == 0 || pbAcc.GetRingNum() > d.node.view.NumRings() {
		return errors.New("accusation ring number out of bounds")
	}
	return nil
}

func (accControlDetector) OnMisbehavior(_ context.Context, err error, _ []byte) {
	log.Debug("Control accusation reconciliation misbehavior", "err", err)
}

func (n *Node) defaultControlReconcilerHooks() ControlReconcilerHooks {
	return ControlReconcilerHooks{
		CertDetector: certControlDetector{node: n},
		CertApplier: func(_ context.Context, item *pki.Certificate) error {
			cert, err := x509.ParseCertificate(item.Raw())
			if err != nil {
				return err
			}
			if n.self != nil && n.self.Id == string(cert.SubjectKeyId) {
				return nil
			}
			if n.view == nil || n.view.CertStore() == nil {
				return errors.New("cert store is not initialized")
			}
			n.view.CertStore().Insert(item)
			if !n.view.Exists(string(cert.SubjectKeyId)) {
				return n.evalValidCertificate(cert)
			}
			return nil
		},
		NoteDetector: noteControlDetector{node: n},
		NoteApplier: func(_ context.Context, item *discovery.Note) error {
			if n.view == nil || n.view.NoteStore() == nil {
				return errors.New("note store is not initialized")
			}
			pbNote := item.ToPbMsg()
			if n.self != nil && n.self.Id == string(pbNote.GetId()) {
				return nil
			}
			err := n.evalNote(pbNote)
			if errors.Is(err, errOldNote) {
				return nil
			}
			return err
		},
		AccDetector: accControlDetector{node: n},
		AccApplier: func(_ context.Context, item *discovery.Accusation) error {
			if n.view == nil || n.view.AccusationStore() == nil {
				return errors.New("accusation store is not initialized")
			}
			n.view.AccusationStore().Insert(item)
			pbAcc := item.ToPbMsg()
			accuserID := string(pbAcc.GetAccuser())
			accusedID := string(pbAcc.GetAccused())

			var accuser *discovery.Peer
			if n.self != nil && accuserID == n.self.Id {
				accuser = n.self
			} else {
				accuser = n.view.Peer(accuserID)
			}
			if accuser == nil {
				return nil
			}

			var accused *discovery.Peer
			if n.self != nil && accusedID == n.self.Id {
				accused = n.self
			} else {
				accused = n.view.Peer(accusedID)
			}
			if accused == nil {
				return nil
			}
			if _, ok := n.view.ActiveNote(accusedID); !ok {
				return nil
			}

			err := n.evalAccusation(pbAcc, accuser, accused)
			if errors.Is(err, errAccAlreadyExists) ||
				errors.Is(err, errInvalidEpoch) ||
				errors.Is(err, errInvalidAccuser) ||
				errors.Is(err, errDisabledRing) ||
				errors.Is(err, errInvalidSelfAccusation) {
				log.Debug(err.Error(), "ringNum", pbAcc.GetRingNum(), "epoch", pbAcc.GetEpoch())
				return nil
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

		var sess *PeerReconcileSession
		var seq uint64
		if n.sessionManager != nil {
			sess = n.sessionManager.GetOrCreate(peer.Id)
			var ok bool
			seq, ok = sess.TryStartOutboundReconciling()
			if !ok {
				continue
			}
		}

		wg.Add(1)
		go func(p *discovery.Peer, s *PeerReconcileSession, sq uint64) {
			defer wg.Done()
			if s != nil {
				defer s.ResetIfSeq(sq)
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
		}(peer, sess, seq)
	}

	wg.Wait()
}
