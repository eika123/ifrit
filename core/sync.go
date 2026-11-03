package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
)

var (
	ErrSyncSessionBusy       = errors.New("sync: session is busy")
	ErrUnexpectedDigest      = errors.New("sync: received unexpected digest not in allowlist")
	ErrItemSizeLimitExceeded = errors.New("sync: item size exceeds maximum allowed size")
	ErrUnexpectedSyncFrame   = errors.New("sync: received unexpected sync frame")
	ErrFramingViolation      = errors.New("sync: stream framing protocol violation")
)

// syncStream unifies client and server streaming RPC handles for Gossip_Sync.
type syncStream interface {
	Send(*pb.SyncFrame) error
	Recv() (*pb.SyncFrame, error)
	Context() context.Context
}

// SyncConfig defines streaming transfer limits and chunking parameters.
type SyncConfig struct {
	ChunkBytes       int           // Slices for pooled DataItemChunk frames (default 128 KB)
	MaxItemBytes     int64         // Maximum byte size of a single item (default 64 MB; <= 0 disables limit)
	ControlBatchSize int           // Maximum items per control frame (default 128 certs, 512 notes/accs)
	Timeout          time.Duration // Timeout for an entire sync session (default 30s)
}

// DefaultSyncConfig returns standard streaming parameters.
func DefaultSyncConfig() SyncConfig {
	return SyncConfig{
		ChunkBytes:       131072,   // 128 KB
		MaxItemBytes:     67108864, // 64 MB
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

// spawnSyncSession spawns a tracked outbound Sync streaming goroutine to the given peer.
func (n *Node) spawnSyncSession(p *discovery.Peer, sess *PeerReconcileSession, seq uint64) {
	n.exitMutex.RLock()
	if n.exitFlag {
		n.exitMutex.RUnlock()
		if sess != nil {
			sess.ResetIfSeq(seq)
		}
		return
	}

	n.wg.Add(1)
	n.exitMutex.RUnlock()

	go func() {
		defer n.wg.Done()
		n.runSyncSession(p, sess, seq)
	}()
}

// runSyncSession executes caller-side Sync transfer to peer p.
func (n *Node) runSyncSession(p *discovery.Peer, sess *PeerReconcileSession, seq uint64) {
	if p == nil || sess == nil {
		return
	}

	timeout := n.SyncConfig().Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(n.syncCtx, timeout)
	defer cancel()

	stream, err := n.comm.OpenSyncStream(ctx, p.Addr)
	if err != nil || stream == nil {
		log.Error("Failed to open sync stream", "addr", p.Addr, "err", err, "streamIsNil", stream == nil)
		sess.ResetIfSeq(seq)
		return
	}

	if err := n.executeBidirectionalSync(ctx, stream, p, sess, seq, true); err != nil {
		log.Error("Outbound sync session failed", "addr", p.Addr, "err", err)
		sess.ResetIfSeq(seq)
		return
	}
}

// syncBootstrap executes a synchronous outbound Sync stream to an entry point address
// using negotiated deltas, ingesting initial certificates and notes.
func (n *Node) syncBootstrap(addr string, deltas ReconcileDeltas) error {
	if !deltas.HasDeltas() {
		return nil
	}

	timeout := n.SyncConfig().Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(n.syncCtx, timeout)
	defer cancel()

	stream, err := n.comm.OpenSyncStream(ctx, addr)
	if err != nil || stream == nil {
		return fmt.Errorf("sync bootstrap: failed to open sync stream to %s: %w", addr, err)
	}

	sess := NewPeerReconcileSession(addr)
	seq, ok := sess.TryStartOutboundReconciling()
	if !ok {
		return fmt.Errorf("sync bootstrap: failed to start outbound session for %s", addr)
	}
	sess.SetDeltas(seq, deltas)
	sess.TransitionAfterReconcile(seq, true)

	return n.executeBidirectionalSync(ctx, stream, nil, sess, seq, true)
}

// executeBidirectionalSync executes the symmetric streaming transfer engine.
// It is invoked on both the Caller (outbound) and the Responder (inbound).
func (n *Node) executeBidirectionalSync(
	ctx context.Context,
	stream syncStream,
	p *discovery.Peer,
	sess *PeerReconcileSession,
	seq uint64,
	isCaller bool,
) error {
	if stream == nil {
		if sess != nil {
			sess.ResetIfSeq(seq)
		}
		return errors.New("sync: stream cannot be nil")
	}

	deltas := sess.Deltas()
	cfg := n.SyncConfig()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type egressResult struct {
		err error
	}
	type ingressResult struct {
		complete *pb.SyncComplete
		err      error
	}

	var callerCompleteCh chan struct{}
	if !isCaller {
		callerCompleteCh = make(chan struct{})
	}

	egressCh := make(chan egressResult, 1)
	ingressCh := make(chan ingressResult, 1)

	var peerID string
	if p != nil {
		peerID = p.Id
	} else if sess != nil {
		peerID = sess.PeerID()
	}

	go func() {
		err := n.sendEgress(ctx, stream, deltas, isCaller, cfg, callerCompleteCh)
		egressCh <- egressResult{err: err}
	}()

	go func() {
		comp, err := n.recvIngress(ctx, stream, deltas, isCaller, cfg, callerCompleteCh, peerID)
		ingressCh <- ingressResult{complete: comp, err: err}
	}()

	var egressErr error
	var ingressErr error
	var remoteComplete *pb.SyncComplete

	for i := 0; i < 2; i++ {
		select {
		case res := <-egressCh:
			egressErr = res.err
			if egressErr != nil {
				cancel()
			}
		case res := <-ingressCh:
			ingressErr = res.err
			remoteComplete = res.complete
			if ingressErr != nil {
				cancel()
			}
		case <-ctx.Done():
			if ctx.Err() != nil {
				if egressErr == nil {
					egressErr = ctx.Err()
				}
				if ingressErr == nil {
					ingressErr = ctx.Err()
				}
			}
		}
	}

	if egressErr != nil {
		sess.ResetIfSeq(seq)
		return egressErr
	}
	if ingressErr != nil {
		sess.ResetIfSeq(seq)
		return ingressErr
	}

	// Update cached peer fingerprints from remote's SyncComplete for immediate single-round quiescence
	if p != nil && remoteComplete != nil {
		if fpData := remoteComplete.GetFingerprintData(); len(fpData) > 0 {
			p.SetFingerprintData(fpData)
		}
		if fpAcc := remoteComplete.GetFingerprintAccusations(); len(fpAcc) > 0 {
			p.SetFingerprintAccusations(fpAcc)
		}
		if fpView := remoteComplete.GetFingerprintView(); len(fpView) > 0 {
			p.SetFingerprintView(fpView)
		}
	}

	sess.CompleteTransfer(seq)
	return nil
}

// sendEgress streams outbound items in causal dependency order:
// Certificates -> Notes -> Accusations -> Chunked Data Items -> SyncComplete.
func (n *Node) sendEgress(
	ctx context.Context,
	stream syncStream,
	deltas ReconcileDeltas,
	isCaller bool,
	cfg SyncConfig,
	callerCompleteCh <-chan struct{},
) error {
	// 1. Certificates
	egressCerts := deltas.EgressCertificates(isCaller)
	if len(egressCerts) > 0 && n.CertStore() != nil {
		batchSize := cfg.ControlBatchSize
		if batchSize <= 0 {
			batchSize = 128
		}
		var batch []*pb.Certificate
		for _, d := range egressCerts {
			if c, found := n.CertStore().GetByDigest(revIdxStore.DigestSymbol(d)); found && c != nil {
				batch = append(batch, c.ToPbMsg())
				if len(batch) >= batchSize {
					err := stream.Send(&pb.SyncFrame{Payload: &pb.SyncFrame_Certificates{Certificates: &pb.CertificateBatch{Items: batch}}})
					if err != nil {
						return err
					}
					batch = nil
				}
			}
		}
		if len(batch) > 0 {
			err := stream.Send(&pb.SyncFrame{Payload: &pb.SyncFrame_Certificates{Certificates: &pb.CertificateBatch{Items: batch}}})
			if err != nil {
				return err
			}
		}
	}

	// 2. Notes
	egressNotes := deltas.EgressNotes(isCaller)
	if len(egressNotes) > 0 && n.view != nil && n.view.NoteStore() != nil {
		batchSize := cfg.ControlBatchSize * 4
		if batchSize <= 0 {
			batchSize = 512
		}
		var batch []*pb.Note
		for _, d := range egressNotes {
			if note, found := n.view.NoteStore().GetByDigest(revIdxStore.DigestSymbol(d)); found && note != nil {
				batch = append(batch, note.ToPbMsg())
				if len(batch) >= batchSize {
					err := stream.Send(&pb.SyncFrame{Payload: &pb.SyncFrame_Notes{Notes: &pb.NoteBatch{Items: batch}}})
					if err != nil {
						return err
					}
					batch = nil
				}
			}
		}
		if len(batch) > 0 {
			err := stream.Send(&pb.SyncFrame{Payload: &pb.SyncFrame_Notes{Notes: &pb.NoteBatch{Items: batch}}})
			if err != nil {
				return err
			}
		}
	}

	// 3. Accusations
	egressAccs := deltas.EgressAccusations(isCaller)
	if len(egressAccs) > 0 && n.view != nil && n.view.AccusationStore() != nil {
		batchSize := cfg.ControlBatchSize * 4
		if batchSize <= 0 {
			batchSize = 512
		}
		var batch []*pb.Accusation
		for _, d := range egressAccs {
			if acc, found := n.view.AccusationStore().GetByDigest(revIdxStore.DigestSymbol(d)); found && acc != nil {
				batch = append(batch, acc.ToPbMsg())
				if len(batch) >= batchSize {
					err := stream.Send(&pb.SyncFrame{Payload: &pb.SyncFrame_Accusations{Accusations: &pb.AccusationBatch{Items: batch}}})
					if err != nil {
						return err
					}
					batch = nil
				}
			}
		}
		if len(batch) > 0 {
			err := stream.Send(&pb.SyncFrame{Payload: &pb.SyncFrame_Accusations{Accusations: &pb.AccusationBatch{Items: batch}}})
			if err != nil {
				return err
			}
		}
	}

	// 4. Data Items
	egressData := deltas.EgressData(isCaller)
	reconciler := n.GetDataReconciler()
	if len(egressData) > 0 && reconciler != nil {
		chunkBytes := cfg.ChunkBytes
		if chunkBytes <= 0 {
			chunkBytes = 131072
		}
		buf := make([]byte, chunkBytes)
		for _, d := range egressData {
			rc, sizeHint, ok, err := reconciler.OpenItemReader(revIdxStore.DigestSymbol(d))
			if err != nil || !ok || rc == nil {
				continue
			}

			// Send DataItemHeader
			err = stream.Send(&pb.SyncFrame{
				Payload: &pb.SyncFrame_DataHeader{
					DataHeader: &pb.DataItemHeader{
						Digest:    d,
						TotalSize: sizeHint,
					},
				},
			})
			if err != nil {
				rc.Close()
				return err
			}

			// Stream chunks
			for {
				nRead, rErr := rc.Read(buf)
				if nRead > 0 {
					chunkCopy := make([]byte, nRead)
					copy(chunkCopy, buf[:nRead])
					err = stream.Send(&pb.SyncFrame{
						Payload: &pb.SyncFrame_DataChunk{
							DataChunk: &pb.DataItemChunk{
								Data: chunkCopy,
							},
						},
					})
					if err != nil {
						rc.Close()
						return err
					}
				}
				if rErr == io.EOF {
					break
				}
				if rErr != nil {
					rc.Close()
					return rErr
				}
			}
			rc.Close()

			// Send DataItemEnd
			err = stream.Send(&pb.SyncFrame{
				Payload: &pb.SyncFrame_DataEnd{
					DataEnd: &pb.DataItemEnd{
						Digest: d,
					},
				},
			})
			if err != nil {
				return err
			}
		}
	}

	// On responder (!isCaller), wait until caller has finished streaming all its items and sent SyncComplete.
	// This ensures responder ingests caller's data before sending its own final SyncComplete,
	// guarantees the computed fingerprintData accurately reflects the ingested state,
	// and prevents caller from prematurely tearing down the stream while responder is still receiving.
	if !isCaller && callerCompleteCh != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-callerCompleteCh:
		}
	}

	// 5. Send Complete
	var fpData []byte
	if reconciler != nil {
		fpData = n.FingerprintData()
	}
	err := stream.Send(&pb.SyncFrame{
		Payload: &pb.SyncFrame_Complete{
			Complete: &pb.SyncComplete{
				FingerprintView:         n.ViewFingerprintBytes(),
				FingerprintAccusations:  n.AccusationFingerprintBytes(),
				FingerprintData:         fpData,
				FingerprintCertificates: n.CertFingerprintBytes(),
			},
		},
	})
	if err != nil {
		return err
	}

	if cs, ok := stream.(interface{ CloseSend() error }); ok {
		_ = cs.CloseSend()
	}

	return nil
}

// recvIngress receives incoming frames, validates incoming digests against session allowlists,
// commits merged control batches, and decodes/ingests data items into the reconciler.
func (n *Node) recvIngress(
	ctx context.Context,
	stream syncStream,
	deltas ReconcileDeltas,
	isCaller bool,
	cfg SyncConfig,
	callerCompleteCh chan struct{},
	peerID string,
) (*pb.SyncComplete, error) {
	var once sync.Once
	signalCallerComplete := func() {
		once.Do(func() {
			if callerCompleteCh != nil {
				close(callerCompleteCh)
			}
		})
	}
	defer signalCallerComplete()
	// Build allowlists for Blocker B3 security
	expectedData := make(map[uint64]struct{}, len(deltas.IngressData(isCaller)))
	for _, d := range deltas.IngressData(isCaller) {
		expectedData[d] = struct{}{}
	}

	var curDataDigest uint64
	var curDataBuf bytes.Buffer
	var hasActiveData bool
	var remoteComplete *pb.SyncComplete

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		frame, err := stream.Recv()
		if err == io.EOF {
			if hasActiveData {
				log.Error("Sync stream truncated: EOF received mid-item", "remotePeer", peerID, "activeDigest", fmt.Sprintf("%016x", curDataDigest))
				return nil, fmt.Errorf("%w: stream closed unexpectedly mid-item %016x", io.ErrUnexpectedEOF, curDataDigest)
			}
			if remoteComplete == nil {
				log.Error("Sync stream truncated: EOF received before SyncComplete", "remotePeer", peerID)
				return nil, fmt.Errorf("%w: stream closed before receiving SyncComplete", io.ErrUnexpectedEOF)
			}
			break
		}
		if err != nil {
			return nil, err
		}
		if frame == nil {
			continue
		}

		switch p := frame.Payload.(type) {
		case *pb.SyncFrame_Certificates:
			if p.Certificates != nil && len(p.Certificates.GetItems()) > 0 {
				n.mergeCertificates(p.Certificates.GetItems())
			}
		case *pb.SyncFrame_Notes:
			if p.Notes != nil && len(p.Notes.GetItems()) > 0 {
				n.mergeNotes(p.Notes.GetItems())
			}
		case *pb.SyncFrame_Accusations:
			if p.Accusations != nil && len(p.Accusations.GetItems()) > 0 {
				n.mergeAccusations(p.Accusations.GetItems())
			}
		case *pb.SyncFrame_DataHeader:
			if p.DataHeader != nil {
				if hasActiveData {
					log.Error("Sync framing violation: received DataHeader while previous item still active", "remotePeer", peerID, "activeDigest", fmt.Sprintf("%016x", curDataDigest), "newDigest", fmt.Sprintf("%016x", p.DataHeader.GetDigest()))
					return nil, fmt.Errorf("%w: received DataHeader while item %016x is active", ErrFramingViolation, curDataDigest)
				}
				curDataDigest = p.DataHeader.GetDigest()
				if len(expectedData) == 0 {
					// Structural protocol fault: remote peer sent an unsolicited DataHeader when 0 data items were negotiated or transfer quota was already fulfilled.
					log.Error("Security/Protocol violation: remote peer pushed DataHeader when zero items expected", "remotePeer", peerID, "digest", fmt.Sprintf("%016x", curDataDigest))
					return nil, fmt.Errorf("%w: remote peer pushed DataHeader %016x when 0 items expected", ErrUnexpectedSyncFrame, curDataDigest)
				}
				if _, exists := expectedData[curDataDigest]; !exists {
					log.Warn("Sync ingress: received unexpected digest not in allowlist", "remotePeer", peerID, "digest", fmt.Sprintf("%016x", curDataDigest))
					return nil, fmt.Errorf("%w: %016x", ErrUnexpectedDigest, curDataDigest)
				}
				if cfg.MaxItemBytes > 0 && p.DataHeader.GetTotalSize() > cfg.MaxItemBytes {
					log.Warn("Sync ingress: item header exceeds size limit", "remotePeer", peerID, "digest", fmt.Sprintf("%016x", curDataDigest), "totalSize", p.DataHeader.GetTotalSize(), "limit", cfg.MaxItemBytes)
					return nil, fmt.Errorf("%w: item %016x header size %d exceeds maximum allowed size of %d bytes", ErrItemSizeLimitExceeded, curDataDigest, p.DataHeader.GetTotalSize(), cfg.MaxItemBytes)
				}
				curDataBuf.Reset()
				hasActiveData = true
			}
		case *pb.SyncFrame_DataChunk:
			if !hasActiveData {
				log.Error("Sync framing violation: received DataChunk without active DataHeader", "remotePeer", peerID)
				return nil, fmt.Errorf("%w: received DataChunk without active DataHeader", ErrFramingViolation)
			}
			if p.DataChunk != nil && len(p.DataChunk.GetData()) > 0 {
				if cfg.MaxItemBytes > 0 && int64(curDataBuf.Len()+len(p.DataChunk.GetData())) > cfg.MaxItemBytes {
					return nil, fmt.Errorf("%w: item %016x exceeds maximum allowed size of %d bytes", ErrItemSizeLimitExceeded, curDataDigest, cfg.MaxItemBytes)
				}
				curDataBuf.Write(p.DataChunk.GetData())
			}
		case *pb.SyncFrame_DataEnd:
			if !hasActiveData {
				log.Error("Sync framing violation: received DataEnd without active DataHeader", "remotePeer", peerID)
				return nil, fmt.Errorf("%w: received DataEnd without active DataHeader", ErrFramingViolation)
			}
			if p.DataEnd != nil {
				if p.DataEnd.GetDigest() != curDataDigest {
					log.Error("Sync framing violation: data end digest does not match header", "remotePeer", peerID, "endDigest", fmt.Sprintf("%016x", p.DataEnd.GetDigest()), "headerDigest", fmt.Sprintf("%016x", curDataDigest))
					return nil, fmt.Errorf("data end digest %016x != header digest %016x", p.DataEnd.GetDigest(), curDataDigest)
				}
				reconciler := n.GetDataReconciler()
				if reconciler != nil {
					if err := reconciler.IngestItem(revIdxStore.DigestSymbol(curDataDigest), &curDataBuf); err != nil {
						return nil, fmt.Errorf("failed to ingest item %016x: %w", curDataDigest, err)
					}
				}
				hasActiveData = false
				curDataBuf.Reset()
				delete(expectedData, curDataDigest)
			}
		case *pb.SyncFrame_Complete:
			if p.Complete != nil {
				remoteComplete = p.Complete
				signalCallerComplete()
				return remoteComplete, nil
			}
		}
	}

	return remoteComplete, nil
}
