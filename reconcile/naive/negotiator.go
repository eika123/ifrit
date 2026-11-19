package naive

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"

	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
)

const (
	// ProtocolName is the wire protocol identifier for full-digest-exchange reconciliation.
	ProtocolName      = "naive/1"
	DefaultBatchSize  = 32768
	DefaultMaxDigests = 1 << 20

	// Binary wire layout for naive/1 Phase 1 frames:
	//   Initiator batch: [digest:8B] * N
	//   Responder diff:  [fingerprint:8B][reqCount:4B][availCount:4B][req:8B*reqCount][avail:8B*availCount]
	digestSizeBytes      = digestmaps.DigestSymbolSize
	fingerprintSizeBytes = digestmaps.DigestSymbolSize
	countFieldSizeBytes  = int(unsafe.Sizeof(uint32(0)))
	diffReqCountOffset   = fingerprintSizeBytes
	diffAvailCountOffset = diffReqCountOffset + countFieldSizeBytes
	diffHeaderSizeBytes  = diffAvailCountOffset + countFieldSizeBytes
)

// Option configures a naive Negotiator.
type Option func(*Negotiator)

// WithBatchSize sets the number of digests packed into each Phase 1 frame.
func WithBatchSize(n int) Option {
	return func(neg *Negotiator) {
		if n > 0 {
			neg.BatchSize = n
		}
	}
}

// WithMaxDigests sets the maximum number of distinct caller digests accepted per session.
func WithMaxDigests(n int) Option {
	return func(neg *Negotiator) {
		if n > 0 {
			neg.MaxDigests = n
		}
	}
}

// Negotiator implements 1-round full-digest-exchange Phase 1 reconciliation over reconcile.NegotiationStream.
type Negotiator struct {
	BatchSize  int
	MaxDigests int
}

// NewNegotiator constructs a naive Negotiator with sensible defaults.
func NewNegotiator(opts ...Option) *Negotiator {
	n := &Negotiator{
		BatchSize:  DefaultBatchSize,
		MaxDigests: DefaultMaxDigests,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(n)
		}
	}
	return n
}

// Name returns the wire protocol name ("naive/1").
func (*Negotiator) Name() string { return ProtocolName }

func (n *Negotiator) batchSize() int {
	if n != nil && n.BatchSize > 0 {
		return n.BatchSize
	}
	return DefaultBatchSize
}

func (n *Negotiator) maxDigests() int {
	if n != nil && n.MaxDigests > 0 {
		return n.MaxDigests
	}
	return DefaultMaxDigests
}

// Initiate streams all local digests in binary batches, half-closes Phase 1,
// and reads the responder's (requested, available, fingerprint) diff batches.
func (n *Negotiator) Initiate(ctx context.Context, stream reconcile.NegotiationStream, set reconcile.Set) (reconcile.Diff, error) {
	localDigests := set.DigestsCopy()
	batchSize := n.batchSize()

	for i := 0; i < len(localDigests); i += batchSize {
		if err := ctx.Err(); err != nil {
			return reconcile.Diff{}, err
		}
		end := min(i+batchSize, len(localDigests))
		buf := make([]byte, (end-i)*digestSizeBytes)
		for j, d := range localDigests[i:end] {
			binary.BigEndian.PutUint64(buf[j*digestSizeBytes:], uint64(d))
		}
		if err := stream.Send(buf); err != nil {
			if err == io.EOF {
				// Server closed the stream early (e.g. ResourceExhausted); read real status via stream.Recv().
				break
			}
			return reconcile.Diff{}, err
		}
	}
	if err := stream.CloseSend(); err != nil && err != io.EOF {
		return reconcile.Diff{}, err
	}

	var diff reconcile.Diff
	for {
		if err := ctx.Err(); err != nil {
			return diff, err
		}
		payload, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return diff, err
		}
		fp, req, avail, err := decodeDiffPage(payload)
		if err != nil {
			return diff, err
		}
		if len(fp) > 0 {
			diff.RemoteFP = fp
		}
		diff.Requested = append(diff.Requested, req...)
		diff.Available = append(diff.Available, avail...)
	}
	return diff, nil
}

// Respond reads caller digest batches until Phase 1 EOF (enforcing MaxDigests),
// computes A\B and B\A against set, streams binary diff pages, and half-closes Phase 1.
func (n *Negotiator) Respond(ctx context.Context, stream reconcile.NegotiationStream, set reconcile.Set) (reconcile.Diff, error) {
	maxDigests := n.maxDigests()
	callerDigests := make(map[digestmaps.DigestSymbol]struct{})

	for {
		if err := ctx.Err(); err != nil {
			return reconcile.Diff{}, err
		}
		payload, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return reconcile.Diff{}, err
		}
		if len(payload)%digestSizeBytes != 0 {
			return reconcile.Diff{}, fmt.Errorf("%w: naive digest batch length %d is not a multiple of %d", reconcile.ErrFramingViolation, len(payload), digestSizeBytes)
		}
		count := len(payload) / digestSizeBytes
		for i := range count {
			d := digestmaps.DigestSymbol(binary.BigEndian.Uint64(payload[i*digestSizeBytes:]))
			if _, exists := callerDigests[d]; !exists {
				if len(callerDigests) >= maxDigests {
					return reconcile.Diff{}, fmt.Errorf("%w: digest count exceeds %d", reconcile.ErrSessionLimitExceeded, maxDigests)
				}
				callerDigests[d] = struct{}{}
			}
		}
	}

	localDigests := set.DigestsCopy()
	localSet := make(map[digestmaps.DigestSymbol]struct{}, len(localDigests))
	for _, d := range localDigests {
		localSet[d] = struct{}{}
	}

	var requested []digestmaps.DigestSymbol
	for d := range callerDigests {
		if _, ok := localSet[d]; !ok {
			requested = append(requested, d)
		}
	}

	var available []digestmaps.DigestSymbol
	for _, d := range localDigests {
		if _, ok := callerDigests[d]; !ok {
			available = append(available, d)
		}
	}

	fp := digestmaps.EncodeDigestSymbol(set.Fingerprint())
	batchSize := n.batchSize()
	if len(requested) == 0 && len(available) == 0 {
		if err := stream.Send(encodeDiffPage(fp, nil, nil)); err != nil {
			return reconcile.Diff{}, err
		}
	} else {
		maxLen := max(len(requested), len(available))
		for i := 0; i < maxLen; i += batchSize {
			var reqSlice, availSlice []digestmaps.DigestSymbol
			if i < len(requested) {
				reqSlice = requested[i:min(i+batchSize, len(requested))]
			}
			if i < len(available) {
				availSlice = available[i:min(i+batchSize, len(available))]
			}
			if err := stream.Send(encodeDiffPage(fp, reqSlice, availSlice)); err != nil {
				return reconcile.Diff{}, err
			}
		}
	}

	if err := stream.CloseSend(); err != nil {
		return reconcile.Diff{}, err
	}
	return reconcile.Diff{
		Requested: requested,
		Available: available,
		RemoteFP:  fp,
	}, nil
}

func encodeDiffPage(fp []byte, req, avail []digestmaps.DigestSymbol) []byte {
	buf := make([]byte, diffHeaderSizeBytes+digestSizeBytes*(len(req)+len(avail)))
	copy(buf[:fingerprintSizeBytes], fp)
	binary.BigEndian.PutUint32(buf[diffReqCountOffset:diffAvailCountOffset], uint32(len(req)))
	binary.BigEndian.PutUint32(buf[diffAvailCountOffset:diffHeaderSizeBytes], uint32(len(avail)))
	off := diffHeaderSizeBytes
	for _, d := range req {
		binary.BigEndian.PutUint64(buf[off:], uint64(d))
		off += digestSizeBytes
	}
	for _, d := range avail {
		binary.BigEndian.PutUint64(buf[off:], uint64(d))
		off += digestSizeBytes
	}
	return buf
}

func decodeDiffPage(payload []byte) (fp []byte, req, avail []digestmaps.DigestSymbol, err error) {
	if len(payload) < diffHeaderSizeBytes {
		return nil, nil, nil, fmt.Errorf("%w: naive diff page truncated (%d bytes)", reconcile.ErrFramingViolation, len(payload))
	}
	reqCount := uint64(binary.BigEndian.Uint32(payload[diffReqCountOffset:diffAvailCountOffset]))
	availCount := uint64(binary.BigEndian.Uint32(payload[diffAvailCountOffset:diffHeaderSizeBytes]))
	expectedLen := uint64(diffHeaderSizeBytes) + uint64(digestSizeBytes)*(reqCount+availCount)
	if expectedLen < uint64(diffHeaderSizeBytes) || expectedLen != uint64(len(payload)) {
		return nil, nil, nil, fmt.Errorf("%w: naive diff page length mismatch (got %d, want %d)", reconcile.ErrFramingViolation, len(payload), expectedLen)
	}
	fp = append([]byte(nil), payload[:fingerprintSizeBytes]...)
	off := diffHeaderSizeBytes
	if reqCount > 0 {
		req = make([]digestmaps.DigestSymbol, reqCount)
		for i := range req {
			req[i] = digestmaps.DigestSymbol(binary.BigEndian.Uint64(payload[off:]))
			off += digestSizeBytes
		}
	}
	if availCount > 0 {
		avail = make([]digestmaps.DigestSymbol, availCount)
		for i := range avail {
			avail[i] = digestmaps.DigestSymbol(binary.BigEndian.Uint64(payload[off:]))
			off += digestSizeBytes
		}
	}
	return fp, req, avail, nil
}
