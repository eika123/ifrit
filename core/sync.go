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
	"github.com/joonnna/ifrit/digestmaps"
	pb "github.com/joonnna/ifrit/protobuf"
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
		ChunkBytes:       1024 * 128,       // 128 KB
		MaxItemBytes:     1024 * 1024 * 64, // 64 MB
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
func (n *Node) spawnSyncSession(peer *discovery.Peer, sess *PeerReconcileSession, seq uint64) {
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
		n.runSyncSession(peer, sess, seq)
	}()
}

// runSyncSession executes caller-side Sync transfer to peer.
func (n *Node) runSyncSession(peer *discovery.Peer, sess *PeerReconcileSession, seq uint64) {
	if peer == nil || sess == nil {
		return
	}

	timeout := n.SyncConfig().Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(n.syncCtx, timeout)
	defer cancel()

	stream, err := n.comm.OpenSyncStream(ctx, peer.Addr)
	if err != nil || stream == nil {
		log.Error("Failed to open sync stream", "addr", peer.Addr, "err", err, "streamIsNil", stream == nil)
		sess.ResetIfSeq(seq)
		return
	}

	if err := n.executeBidirectionalSync(ctx, stream, peer, sess, seq, true); err != nil {
		log.Error("Outbound sync session failed", "addr", peer.Addr, "err", err)
		sess.ResetIfSeq(seq)
		return
	}
}

// syncBootstrap executes a synchronous outbound Sync stream to a
// peer address of the form (host:port) using negotiated deltas,
// ingesting initial certificates and notes.
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

func (n *Node) runSyncStreams(
	ctx context.Context,
	stream syncStream,
	sess *PeerReconcileSession,
	isCaller bool,
) (*pb.SyncComplete, error) {

	type ingressResult struct {
		complete *pb.SyncComplete
		err      error
	}

	// sess.PeerID() is always equal to peer.Id if peer is not nil.
	// When peer is nil at bootstrap time, sess.PeerID() is the remote
	// host:port address
	peerID := sess.PeerID()

	deltas := sess.Deltas()
	cfg := n.SyncConfig()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	egressCh := make(chan error, 1)

	var callerCompleteCh chan struct{}
	if !isCaller {
		callerCompleteCh = make(chan struct{})
	}

	ingressCh := make(chan ingressResult, 1)

	go func() {
		egressCh <- n.sendEgress(ctx, stream, deltas, isCaller, cfg, callerCompleteCh)
	}()

	go func() {
		comp, err := n.recvIngress(ctx, stream, deltas, isCaller, cfg, callerCompleteCh, peerID)
		ingressCh <- ingressResult{complete: comp, err: err}
	}()

	var egressErr error
	var ingressErr error
	var remoteComplete *pb.SyncComplete

	for range 2 {
		select {
		case egressErr = <-egressCh:
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
		return nil, egressErr
	}
	if ingressErr != nil {
		return nil, ingressErr
	}

	return remoteComplete, nil
}

// executeBidirectionalSync executes the symmetric streaming transfer engine.
// It is invoked on both the Caller (outbound) and the Responder (inbound).
func (n *Node) executeBidirectionalSync(
	ctx context.Context,
	stream syncStream,
	peer *discovery.Peer,
	sess *PeerReconcileSession,
	seq uint64,
	isCaller bool,
) error {
	if sess == nil {
		return errors.New("sync: session (sess) cannot be nil")
	}
	if stream == nil {
		sess.ResetIfSeq(seq)
		return errors.New("sync: stream cannot be nil")
	}

	remoteComplete, err := n.runSyncStreams(ctx, stream, sess, isCaller)
	if err != nil {
		sess.ResetIfSeq(seq)
		return err
	}

	if remoteComplete != nil {
		peer.SetFingerprints(
			remoteComplete.GetFingerprintData(),
			remoteComplete.GetFingerprintAccusations(),
			remoteComplete.GetFingerprintView(),
		)
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
			if c, found := n.CertStore().GetByDigest(digestmaps.DigestSymbol(d)); found && c != nil {
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
			if note, found := n.view.NoteStore().GetByDigest(digestmaps.DigestSymbol(d)); found && note != nil {
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
			if acc, found := n.view.AccusationStore().GetByDigest(digestmaps.DigestSymbol(d)); found && acc != nil {
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
			rc, sizeHint, ok, err := reconciler.OpenItemReader(digestmaps.DigestSymbol(d))
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

// validateDataHeader verifies that an incoming DataItemHeader is authorized by the session allowlist
// and within the configured maximum item size limit, returning the validated digest.
func validateDataHeader(
	header *pb.DataItemHeader,
	expectedData map[uint64]struct{},
	cfg SyncConfig,
	peerID string,
) (uint64, error) {
	if header == nil {
		return 0, nil
	}

	digest := header.GetDigest()
	if len(expectedData) == 0 {
		log.Error("Security/Protocol violation: remote peer pushed DataHeader when zero items expected",
			"remotePeer", peerID,
			"digest", fmt.Sprintf("%016x", digest),
		)
		return 0, fmt.Errorf("%w: remote peer pushed DataHeader %016x when 0 items expected", ErrUnexpectedSyncFrame, digest)
	}
	if _, exists := expectedData[digest]; !exists {
		log.Warn("Sync ingress: received unexpected digest not in allowlist",
			"remotePeer", peerID,
			"digest", fmt.Sprintf("%016x", digest),
		)
		return 0, fmt.Errorf("%w: %016x", ErrUnexpectedDigest, digest)
	}
	if cfg.MaxItemBytes > 0 && header.GetTotalSize() > cfg.MaxItemBytes {
		log.Warn("Sync ingress: item header exceeds size limit",
			"remotePeer", peerID,
			"digest", fmt.Sprintf("%016x", digest),
			"totalSize", header.GetTotalSize(),
			"limit", cfg.MaxItemBytes,
		)
		return 0, fmt.Errorf(
			"%w: item %016x header size %d exceeds maximum allowed size of %d bytes",
			ErrItemSizeLimitExceeded, digest, header.GetTotalSize(), cfg.MaxItemBytes,
		)
	}
	return digest, nil
}

// appendDataChunk enforces size limits and writes chunk payload into the in-progress buffer.
func appendDataChunk(chunk *pb.DataItemChunk, buf *bytes.Buffer, digest uint64, maxItemBytes int64) error {
	if chunk == nil || len(chunk.GetData()) == 0 {
		return nil
	}
	if maxItemBytes > 0 && int64(buf.Len()+len(chunk.GetData())) > maxItemBytes {
		return fmt.Errorf("%w: item %016x exceeds maximum allowed size of %d bytes", ErrItemSizeLimitExceeded, digest, maxItemBytes)
	}
	buf.Write(chunk.GetData())
	return nil
}

// ingestDataEnd validates the end digest against the header digest and writes assembled bytes to the DataReconciler.
func (n *Node) ingestDataEnd(end *pb.DataItemEnd, buf *bytes.Buffer, digest uint64, peerID string) error {
	if end != nil && end.GetDigest() != digest {
		log.Error("Sync framing violation: data end digest does not match header",
			"remotePeer", peerID,
			"endDigest", fmt.Sprintf("%016x", end.GetDigest()),
			"headerDigest", fmt.Sprintf("%016x", digest),
		)
		return fmt.Errorf("data end digest %016x != header digest %016x", end.GetDigest(), digest)
	}
	if reconciler := n.GetDataReconciler(); reconciler != nil {
		if err := reconciler.IngestItem(digestmaps.DigestSymbol(digest), buf); err != nil {
			return fmt.Errorf("failed to ingest item %016x: %w", digest, err)
		}
	}
	return nil
}

// recvDataItem reads chunks for a single DataItem until DataEnd is received,
// validating chunk sizes and ingesting the assembled bytes into the DataReconciler.
func (n *Node) recvDataItem(
	ctx context.Context,
	stream syncStream,
	header *pb.DataItemHeader,
	expectedData map[uint64]struct{},
	cfg SyncConfig,
	peerID string,
) error {
	digest, err := validateDataHeader(header, expectedData, cfg, peerID)
	if err != nil {
		return err
	}
	if header == nil {
		return nil
	}

	var buf bytes.Buffer
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		frame, err := stream.Recv()
		if err != nil {
			return handleStreamRecvError(err, peerID, true, digest)
		}
		if frame == nil {
			continue
		}

		switch payload := frame.Payload.(type) {
		case *pb.SyncFrame_DataChunk:
			if err := appendDataChunk(payload.DataChunk, &buf, digest, cfg.MaxItemBytes); err != nil {
				return err
			}
		case *pb.SyncFrame_DataEnd:
			if err := n.ingestDataEnd(payload.DataEnd, &buf, digest, peerID); err != nil {
				return err
			}
			delete(expectedData, digest)
			return nil
		default:
			log.Error("Sync framing violation: received non-chunk frame while reading data item",
				"remotePeer", peerID,
				"activeDigest", fmt.Sprintf("%016x", digest),
			)
			return fmt.Errorf("%w: received unexpected frame while item %016x is active", ErrFramingViolation, digest)
		}
	}
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

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		frame, err := stream.Recv()
		if err != nil {
			return nil, handleStreamRecvError(err, peerID, false, 0)
		}
		if frame == nil {
			continue
		}

		switch payload := frame.Payload.(type) {
		case *pb.SyncFrame_Certificates:
			if payload.Certificates != nil && len(payload.Certificates.GetItems()) > 0 {
				n.mergeCertificates(payload.Certificates.GetItems())
			}
		case *pb.SyncFrame_Notes:
			if payload.Notes != nil && len(payload.Notes.GetItems()) > 0 {
				n.mergeNotes(payload.Notes.GetItems())
			}
		case *pb.SyncFrame_Accusations:
			if payload.Accusations != nil && len(payload.Accusations.GetItems()) > 0 {
				n.mergeAccusations(payload.Accusations.GetItems())
			}
		case *pb.SyncFrame_DataHeader:
			if err := n.recvDataItem(ctx, stream, payload.DataHeader, expectedData, cfg, peerID); err != nil {
				return nil, err
			}
		case *pb.SyncFrame_DataChunk:
			log.Error("Sync framing violation: received DataChunk without active DataHeader",
				"remotePeer", peerID,
			)
			return nil, fmt.Errorf("%w: received DataChunk without active DataHeader", ErrFramingViolation)
		case *pb.SyncFrame_DataEnd:
			log.Error("Sync framing violation: received DataEnd without active DataHeader",
				"remotePeer", peerID,
			)
			return nil, fmt.Errorf("%w: received DataEnd without active DataHeader", ErrFramingViolation)
		case *pb.SyncFrame_Complete:
			if payload.Complete != nil {
				return payload.Complete, nil
			}
		}
	}
}

func handleStreamRecvError(err error, peerID string, hasActiveData bool, activeDigest uint64) error {
	if err == io.EOF {
		return handleStreamTruncation(peerID, hasActiveData, activeDigest)
	}
	return err
}

func handleStreamTruncation(peerID string, hasActiveData bool, activeDigest uint64) error {
	if hasActiveData {
		log.Error("Sync stream truncated: EOF received mid-item",
			"remotePeer", peerID,
			"activeDigest", fmt.Sprintf("%016x", activeDigest),
		)
		return fmt.Errorf("%w: stream closed unexpectedly mid-item %016x", io.ErrUnexpectedEOF, activeDigest)
	}
	log.Error("Sync stream truncated: EOF received before SyncComplete",
		"remotePeer", peerID,
	)
	return fmt.Errorf("%w: stream closed before receiving SyncComplete", io.ErrUnexpectedEOF)
}
