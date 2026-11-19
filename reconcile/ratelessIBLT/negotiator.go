package ratelessIBLT

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"

	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	"github.com/yangl1996/riblt"
)

const (
	// ProtocolName is the wire protocol identifier for Rateless IBLT reconciliation.
	ProtocolName = "riblt/1"

	respFlagNeedMore byte = 0
	respFlagDecoded  byte = 1

	// Binary wire layout for riblt/1 Phase 1 frames:
	//   Initiator coded batch: [symbol:8B][hash:8B][count:8B] * N
	//   Responder need-more:   [flag=0:1B]
	//   Responder decoded:     [flag=1:1B][fingerprint:8B][reqCount:4B][availCount:4B][req:8B*reqCount][avail:8B*availCount]
	respFlagSizeBytes    = int(unsafe.Sizeof(byte(0)))
	digestSizeBytes      = digestmaps.DigestSymbolSize
	hashSizeBytes        = int(unsafe.Sizeof(uint64(0)))
	count64SizeBytes     = int(unsafe.Sizeof(int64(0)))
	fingerprintSizeBytes = digestmaps.DigestSymbolSize
	countFieldSizeBytes  = int(unsafe.Sizeof(uint32(0)))

	codedSymbolHashOffset  = digestSizeBytes
	codedSymbolCountOffset = codedSymbolHashOffset + hashSizeBytes
	codedSymbolBytes       = codedSymbolCountOffset + count64SizeBytes

	decodedFPOffset         = respFlagSizeBytes
	decodedReqCountOffset   = decodedFPOffset + fingerprintSizeBytes
	decodedAvailCountOffset = decodedReqCountOffset + countFieldSizeBytes
	decodedHeaderSizeBytes  = decodedAvailCountOffset + countFieldSizeBytes
)

// Option configures a ratelessIBLT Negotiator.
type Option func(*Negotiator)

// WithBatchSize sets the number of coded symbols packed per Phase 1 frame.
func WithBatchSize(n int) Option {
	return func(neg *Negotiator) {
		if n > 0 {
			neg.BatchSize = n
		}
	}
}

// WithMaxSymbols sets the maximum number of coded symbols accepted per session.
func WithMaxSymbols(n int) Option {
	return func(neg *Negotiator) {
		if n > 0 {
			neg.MaxSymbols = n
		}
	}
}

// Negotiator implements Rateless IBLT Phase 1 reconciliation over reconcile.NegotiationStream.
// If the provided reconcile.Set implements SketchStore[DigestSymbol], its precomputed
// sketch prefix is used for O(M) fast-path decoding; otherwise a rateless encoder/decoder
// is built on the fly from set.DigestsCopy().
type Negotiator struct {
	BatchSize  int
	MaxSymbols int
}

// NewNegotiator constructs a ratelessIBLT Negotiator with sensible defaults.
func NewNegotiator(opts ...Option) *Negotiator {
	n := &Negotiator{
		BatchSize:  DefaultSymbolBatchSize,
		MaxSymbols: DefaultMaxSymbols,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(n)
		}
	}
	return n
}

// Name returns the wire protocol name ("riblt/1").
func (*Negotiator) Name() string { return ProtocolName }

func (n *Negotiator) batchSize() int {
	if n != nil && n.BatchSize > 0 {
		return n.BatchSize
	}
	return DefaultSymbolBatchSize
}

func (n *Negotiator) maxSymbols() int {
	if n != nil && n.MaxSymbols > 0 {
		return n.MaxSymbols
	}
	return DefaultMaxSymbols
}

// Initiate executes the RIBLT initiator protocol over stream.
func (n *Negotiator) Initiate(_ context.Context, stream reconcile.NegotiationStream, set reconcile.Set) (reconcile.Diff, error) {
	diff, err := ReconcileClient(streamClientTransport{stream: stream}, sketchStoreFor(set), n.batchSize())
	if err != nil {
		return reconcile.Diff{}, err
	}
	return reconcile.Diff{
		Requested:    diff.Requested,
		Available:    diff.Available,
		RemoteFP:     diff.RemoteFingerprint,
		UsedFallback: diff.UsedFallback,
	}, nil
}

// Respond executes the RIBLT responder protocol over stream.
func (n *Negotiator) Respond(_ context.Context, stream reconcile.NegotiationStream, set reconcile.Set) (reconcile.Diff, error) {
	fp := digestmaps.EncodeDigestSymbol(set.Fingerprint())
	tr := streamServerTransport{
		stream: stream,
		fp:     fp,
	}
	diff, err := ReconcileServer(tr, sketchStoreFor(set), n.maxSymbols())
	if err != nil {
		return reconcile.Diff{}, err
	}
	if err := stream.CloseSend(); err != nil {
		return reconcile.Diff{}, err
	}
	return reconcile.Diff{
		Requested:    diff.Requested,
		Available:    diff.Available,
		RemoteFP:     fp,
		UsedFallback: diff.UsedFallback,
	}, nil
}

// plainSetSketchAdapter is an internal fallback that adapts any plain reconcile.Set
// (e.g. digestmaps.DigestSet or naive.ReconcilableStore) to SketchStore[DigestSymbol].
//
// Tradeoff: this adapter provides NO incremental sketch maintenance (SnapshotSketch
// returns nil). Each sync builds an on-demand riblt.Encoder or riblt.Decoder from
// set.DigestsCopy() in O(N) CPU while preserving O(|Delta|) rateless wire bandwidth.
// Callers that want incremental sketch updates and O(M) snapshot reconciliation should
// wrap their store with NewReconcilableStore / WrapStore instead.
type plainSetSketchAdapter struct {
	set reconcile.Set
}

func (a plainSetSketchAdapter) SnapshotSketch() riblt.Sketch[digestmaps.DigestSymbol] { return nil }

func (a plainSetSketchAdapter) MakeEncoder() riblt.Encoder[digestmaps.DigestSymbol] {
	enc := riblt.Encoder[digestmaps.DigestSymbol]{}
	for _, d := range a.set.DigestsCopy() {
		enc.AddSymbol(d)
	}
	return enc
}

func (a plainSetSketchAdapter) MakeDecoder() riblt.Decoder[digestmaps.DigestSymbol] {
	dec := riblt.Decoder[digestmaps.DigestSymbol]{}
	for _, d := range a.set.DigestsCopy() {
		dec.AddSymbol(d)
	}
	return dec
}

// sketchStoreFor adapts the protocol-agnostic reconcile.Set to SketchStore:
//   - Fast path (incremental): if set implements SketchStore[DigestSymbol] (i.e. *Store
//     or *ReconcilableStore), its incrementally maintained riblt.Sketch is used for O(M)
//     snapshot reconciliation without scanning N elements.
//   - Fallback path (on-demand): otherwise set is wrapped in plainSetSketchAdapter so
//     riblt/1 still interoperates with plain ReverseIndexStore backends (e.g. mixed
//     naive/riblt peers), paying O(N) CPU per sync for on-demand encoding/decoding.
func sketchStoreFor(set reconcile.Set) SketchStore[digestmaps.DigestSymbol] {
	if ss, ok := set.(SketchStore[digestmaps.DigestSymbol]); ok {
		return ss
	}
	return plainSetSketchAdapter{set: set}
}

type streamClientTransport struct {
	stream reconcile.NegotiationStream
}

// SendCoded serializes a batch of RIBLT coded symbols as contiguous big-endian
// (Symbol, Hash, Count) tuples and transmits them as a single Phase 1 frame.
func (t streamClientTransport) SendCoded(batch []riblt.CodedSymbol[digestmaps.DigestSymbol]) error {
	buf := make([]byte, len(batch)*codedSymbolBytes)
	for i, cs := range batch {
		off := i * codedSymbolBytes
		binary.BigEndian.PutUint64(buf[off:], uint64(cs.HashedSymbol.Symbol))
		binary.BigEndian.PutUint64(buf[off+codedSymbolHashOffset:], cs.HashedSymbol.Hash)
		binary.BigEndian.PutUint64(buf[off+codedSymbolCountOffset:], uint64(cs.Count))
	}
	return t.stream.Send(buf)
}

// RecvResponse reads and decodes the next Phase 1 responder frame from stream.
// Returns (decoded=false, nil, nil, nil, eof=false, nil) for a NeedMore signal,
// (decoded=true, req, avail, fp, eof=false, nil) for a Decoded diff page, or
// (..., eof=true, nil) when the responder closes Phase 1.
func (t streamClientTransport) RecvResponse() (bool, []digestmaps.DigestSymbol, []digestmaps.DigestSymbol, []byte, bool, error) {
	payload, err := t.stream.Recv()
	if err == io.EOF {
		return false, nil, nil, nil, true, nil
	}
	if err != nil {
		return false, nil, nil, nil, false, err
	}
	if len(payload) == 0 {
		return false, nil, nil, nil, false, fmt.Errorf("%w: empty riblt response frame", reconcile.ErrFramingViolation)
	}
	switch payload[0] {
	case respFlagNeedMore:
		if len(payload) != respFlagSizeBytes {
			return false, nil, nil, nil, false, fmt.Errorf("%w: malformed riblt need-more frame (%d bytes)", reconcile.ErrFramingViolation, len(payload))
		}
		return false, nil, nil, nil, false, nil
	case respFlagDecoded:
		if len(payload) < decodedHeaderSizeBytes {
			return false, nil, nil, nil, false, fmt.Errorf("%w: truncated riblt decoded frame (%d bytes)", reconcile.ErrFramingViolation, len(payload))
		}
		reqCount := uint64(binary.BigEndian.Uint32(payload[decodedReqCountOffset:decodedAvailCountOffset]))
		availCount := uint64(binary.BigEndian.Uint32(payload[decodedAvailCountOffset:decodedHeaderSizeBytes]))
		expectedLen := uint64(decodedHeaderSizeBytes) + uint64(digestSizeBytes)*(reqCount+availCount)
		if expectedLen < uint64(decodedHeaderSizeBytes) || expectedLen != uint64(len(payload)) {
			return false, nil, nil, nil, false, fmt.Errorf("%w: riblt decoded frame length mismatch (got %d, want %d)", reconcile.ErrFramingViolation, len(payload), expectedLen)
		}
		fp := append([]byte(nil), payload[decodedFPOffset:decodedReqCountOffset]...)
		off := decodedHeaderSizeBytes
		var req, avail []digestmaps.DigestSymbol
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
		return true, req, avail, fp, false, nil
	default:
		return false, nil, nil, nil, false, fmt.Errorf("%w: unknown riblt response flag %d", reconcile.ErrFramingViolation, payload[0])
	}
}

// CloseSend half-closes the initiator's Phase 1 send direction without closing the underlying stream.
func (t streamClientTransport) CloseSend() error {
	return t.stream.CloseSend()
}

type streamServerTransport struct {
	stream reconcile.NegotiationStream
	fp     []byte
}

// RecvCoded reads the next Phase 1 frame from stream and decodes a batch of packed
// RIBLT coded symbols (each codedSymbolBytes wide: Symbol, Hash, Count).
// Returns (nil, true, nil) when the initiator signals Phase 1 EOF, or an error
// wrapping reconcile.ErrFramingViolation if the payload size is not a multiple
// of codedSymbolBytes.
func (t streamServerTransport) RecvCoded() ([]riblt.CodedSymbol[digestmaps.DigestSymbol], bool, error) {
	payload, err := t.stream.Recv()
	if err == io.EOF {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(payload)%codedSymbolBytes != 0 {
		return nil, false, fmt.Errorf("%w: riblt coded batch length %d is not a multiple of %d", reconcile.ErrFramingViolation, len(payload), codedSymbolBytes)
	}
	n := len(payload) / codedSymbolBytes
	syms := make([]riblt.CodedSymbol[digestmaps.DigestSymbol], n)
	for i := range n {
		off := i * codedSymbolBytes
		syms[i] = riblt.CodedSymbol[digestmaps.DigestSymbol]{
			HashedSymbol: riblt.HashedSymbol[digestmaps.DigestSymbol]{
				Symbol: digestmaps.DigestSymbol(binary.BigEndian.Uint64(payload[off:])),
				Hash:   binary.BigEndian.Uint64(payload[off+codedSymbolHashOffset:]),
			},
			Count: int64(binary.BigEndian.Uint64(payload[off+codedSymbolCountOffset:])),
		}
	}
	return syms, false, nil
}

// SendNeedMore sends a 1-byte NeedMore signal asking the initiator to enter rateless fallback.
func (t streamServerTransport) SendNeedMore() error {
	return t.stream.Send([]byte{respFlagNeedMore})
}

// SendDiffPage encodes and sends one Decoded diff page carrying the responder's
// fingerprint along with a slice of requested (A\B) and available (B\A) digests.
func (t streamServerTransport) SendDiffPage(req, avail []riblt.HashedSymbol[digestmaps.DigestSymbol]) error {
	buf := make([]byte, decodedHeaderSizeBytes+digestSizeBytes*(len(req)+len(avail)))
	buf[0] = respFlagDecoded
	copy(buf[decodedFPOffset:decodedReqCountOffset], t.fp)
	binary.BigEndian.PutUint32(buf[decodedReqCountOffset:decodedAvailCountOffset], uint32(len(req)))
	binary.BigEndian.PutUint32(buf[decodedAvailCountOffset:decodedHeaderSizeBytes], uint32(len(avail)))
	off := decodedHeaderSizeBytes
	for _, hs := range req {
		binary.BigEndian.PutUint64(buf[off:], uint64(hs.Symbol))
		off += digestSizeBytes
	}
	for _, hs := range avail {
		binary.BigEndian.PutUint64(buf[off:], uint64(hs.Symbol))
		off += digestSizeBytes
	}
	return t.stream.Send(buf)
}
