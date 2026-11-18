package ratelessIBLT

// Collection of generic helpers and interfaces -- use these to write your
// reconciler stubs on top of for example gRPC / protobuf
//
// For use in Practical Rateless Set Reconciliation,
// The client/caller streams coded symbols to the server/callee.
// Let the set on the client be called A, and the set on the server be called B.
//
// The server tries to decode for each symbol. When decoding succeeds,
// the server knows the symmetric delta symbols. In a trivial application
// Where the symbols are the sole symbols of interest, the server may just
// respond with the symbols the client is missing. However, to do something
// interesting we have a two-phase sync of data after this session:
//
// Since we exchange actual data (for example video snippets, files or
// database records) after the digest delta calculation on the server,
// The server must stream both A \ B and B \ A back to the client.
// After this, a second phase data sync begins.

import (
	"io"
	"slices"
	"sync"

	"github.com/eika123/ifrit/digestmaps"
	"github.com/yangl1996/riblt"
)

// SketchStore provides O(M) sketch snapshots and fallback rateless codecs
// for a reconcilable set.
type SketchStore[S digestmaps.Symbol[S]] interface {
	SnapshotSketch() riblt.Sketch[S]
	MakeEncoder() riblt.Encoder[S]
	MakeDecoder() riblt.Decoder[S]
}

// ReconcileDiff holds the decoded symmetric difference (A\B and B\A).
type ReconcileDiff[S digestmaps.Symbol[S]] struct {
	Requested    []S // A \ B: symbols caller has that responder lacks
	Available    []S // B \ A: symbols responder has that caller lacks
	UsedFallback bool
}

// ReconcileClientTransport abstracts the wire stream for the reconciliation initiator.
type ReconcileClientTransport[S digestmaps.Symbol[S]] interface {
	SendCoded(batch []riblt.CodedSymbol[S]) error
	RecvResponse() (decoded bool, req, avail []S, eof bool, err error)
	CloseSend() error
}

// ReconcileServerTransport abstracts the wire stream for the reconciliation responder.
type ReconcileServerTransport[S digestmaps.Symbol[S]] interface {
	RecvCoded() (batch []riblt.CodedSymbol[S], eof bool, err error)
	SendNeedMore() error
	SendDiffPage(req, avail []riblt.HashedSymbol[S]) error
}

type reconcileResult[S digestmaps.Symbol[S]] struct {
	diff ReconcileDiff[S]
	err  error
}

// ReconcileClient runs the two-stage RIBLT reconciliation initiator protocol:
// streaming the precomputed sketch prefix first and falling back to full rateless
// encoding only if the responder signals that the diff exceeded sketch capacity.
func ReconcileClient[S digestmaps.Symbol[S]](
	tr ReconcileClientTransport[S],
	store SketchStore[S],
	batchSize int,
) (ReconcileDiff[S], error) {
	decodedCh := make(chan struct{})
	needMoreCh := make(chan struct{})
	doneCh := make(chan reconcileResult[S], 1)
	go receiveReconcileResponses(tr, decodedCh, needMoreCh, doneCh)

	sketch := store.SnapshotSketch()
	if len(sketch) > 0 {
		diff, fallback, err := sendSketch(tr, sketch, batchSize, decodedCh, needMoreCh, doneCh)
		if !fallback || err != nil {
			return diff, err
		}
	}

	diff, err := sendRatelessSymbols(tr, store, len(sketch), batchSize, decodedCh, doneCh)
	diff.UsedFallback = true
	return diff, err
}

func receiveReconcileResponses[S digestmaps.Symbol[S]](
	tr ReconcileClientTransport[S],
	decodedCh chan struct{},
	needMoreCh chan struct{},
	doneCh chan<- reconcileResult[S],
) {
	var decodedOnce sync.Once
	var needMoreOnce sync.Once
	var agg ReconcileDiff[S]

	for {
		decoded, req, avail, eof, err := tr.RecvResponse()
		if eof {
			doneCh <- reconcileResult[S]{diff: agg}
			return
		}
		if err != nil {
			doneCh <- reconcileResult[S]{err: err}
			return
		}

		if decoded {
			decodedOnce.Do(func() { close(decodedCh) })
		} else if len(req) == 0 && len(avail) == 0 {
			needMoreOnce.Do(func() { close(needMoreCh) })
		}
		agg.Requested = append(agg.Requested, req...)
		agg.Available = append(agg.Available, avail...)
	}
}

func sendSketch[S digestmaps.Symbol[S]](
	tr ReconcileClientTransport[S],
	sketch riblt.Sketch[S],
	batchSize int,
	decodedCh <-chan struct{},
	needMoreCh <-chan struct{},
	doneCh <-chan reconcileResult[S],
) (ReconcileDiff[S], bool, error) {
	for i := 0; i < len(sketch); i += batchSize {
		end := min(i+batchSize, len(sketch))
		if done, diff, err := sendCodedBatch(tr, sketch[i:end], doneCh); done || err != nil {
			return diff, false, err
		}
	}

	select {
	case <-decodedCh:
		_ = tr.CloseSend()
		res := <-doneCh
		return res.diff, false, res.err
	case res := <-doneCh:
		_ = tr.CloseSend()
		return res.diff, false, res.err
	case <-needMoreCh:
		return ReconcileDiff[S]{}, true, nil
	}
}

func sendRatelessSymbols[S digestmaps.Symbol[S]](
	tr ReconcileClientTransport[S],
	store SketchStore[S],
	skip int,
	batchSize int,
	decodedCh <-chan struct{},
	doneCh <-chan reconcileResult[S],
) (ReconcileDiff[S], error) {
	enc := store.MakeEncoder()
	for range skip {
		enc.ProduceNextCodedSymbol()
	}

	batch := make([]riblt.CodedSymbol[S], batchSize)
	for {
		select {
		case <-decodedCh:
			_ = tr.CloseSend()
			res := <-doneCh
			return res.diff, res.err
		case res := <-doneCh:
			_ = tr.CloseSend()
			return res.diff, res.err
		default:
		}

		for i := range batchSize {
			batch[i] = enc.ProduceNextCodedSymbol()
		}
		if done, diff, err := sendCodedBatch(tr, batch, doneCh); done || err != nil {
			return diff, err
		}
	}
}

func sendCodedBatch[S digestmaps.Symbol[S]](
	tr ReconcileClientTransport[S],
	batch []riblt.CodedSymbol[S],
	doneCh <-chan reconcileResult[S],
) (bool, ReconcileDiff[S], error) {
	if err := tr.SendCoded(batch); err != nil {
		// If server closes the stream while client is sending, Send returns io.EOF;
		// read the real response or error from the Recv() goroutine.
		if err == io.EOF {
			res := <-doneCh
			return true, res.diff, res.err
		}
		return false, ReconcileDiff[S]{}, err
	}
	return false, ReconcileDiff[S]{}, nil
}

// ReconcileServer runs the responder side of the two-stage RIBLT protocol.
func ReconcileServer[S digestmaps.Symbol[S]](
	tr ReconcileServerTransport[S],
	store SketchStore[S],
) error {
	localSketch := store.SnapshotSketch()
	var buffered []riblt.CodedSymbol[S]

	if len(localSketch) > 0 {
		var handled bool
		var err error
		buffered, handled, err = trySketchReconcile(tr, localSketch)
		if handled || err != nil {
			return err
		}
	}

	return decodeRatelessFallback(tr, store, buffered)
}

func trySketchReconcile[S digestmaps.Symbol[S]](
	tr ReconcileServerTransport[S],
	localSketch riblt.Sketch[S],
) ([]riblt.CodedSymbol[S], bool, error) {
	buffered := make([]riblt.CodedSymbol[S], 0, len(localSketch))
	for len(buffered) < len(localSketch) {
		syms, eof, err := tr.RecvCoded()
		if err != nil {
			return nil, false, err
		}
		if eof {
			break
		}
		buffered = append(buffered, syms...)
	}

	if len(buffered) == len(localSketch) {
		diff := slices.Clone(riblt.Sketch[S](buffered))
		diff.Subtract(localSketch)
		if remote, local, ok := diff.Decode(); ok {
			return nil, true, streamDiffPages(tr, remote, local)
		}
		if err := tr.SendNeedMore(); err != nil {
			return nil, false, err
		}
	}
	return buffered, false, nil
}

func decodeRatelessFallback[S digestmaps.Symbol[S]](
	tr ReconcileServerTransport[S],
	store SketchStore[S],
	buffered []riblt.CodedSymbol[S],
) error {
	dec := store.MakeDecoder()
	for _, cs := range buffered {
		dec.AddCodedSymbol(cs)
	}
	if len(buffered) > 0 {
		dec.TryDecode()
		if dec.Decoded() {
			return streamDiffPages(tr, dec.Remote(), dec.Local())
		}
	}

	for {
		syms, eof, err := tr.RecvCoded()
		if err != nil {
			return err
		}
		if eof {
			return nil
		}
		for _, cs := range syms {
			dec.AddCodedSymbol(cs)
		}
		dec.TryDecode()
		if dec.Decoded() {
			return streamDiffPages(tr, dec.Remote(), dec.Local())
		}
	}
}

func streamDiffPages[S digestmaps.Symbol[S]](
	tr ReconcileServerTransport[S],
	remote, local []riblt.HashedSymbol[S],
) error {
	const digestPageSize = 4096

	if len(remote)+len(local) <= digestPageSize {
		return tr.SendDiffPage(remote, local)
	}

	for i := 0; i < len(remote); i += digestPageSize {
		end := min(i+digestPageSize, len(remote))
		if err := tr.SendDiffPage(remote[i:end], nil); err != nil {
			return err
		}
	}

	for i := 0; i < len(local); i += digestPageSize {
		end := min(i+digestPageSize, len(local))
		if err := tr.SendDiffPage(nil, local[i:end]); err != nil {
			return err
		}
	}
	return nil
}
