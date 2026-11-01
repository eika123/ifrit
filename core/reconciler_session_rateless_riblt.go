package core

import (
	"encoding/binary"
	"fmt"

	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
	"github.com/yangl1996/riblt"
)

//  Define Reconcileable Store to riblt Encoder/Decoder sitting in the middle between two communicating nodes
//
// In iblt, a Symbol is an interface defined on any type T that implements the methods
//
// -  T.XOR(other T) --> T,
// -  T.Hash() --> uint64
//
// Alice: setA --> EncoderA(setA)
//                  v   -- ProduceNextCodedSymbol() : -> msgA1,
//								...								fill up a network packet
//                  v   -- ProduceNextCodedSymbol() : -> msgAk,

// 						-- network[msgA1,...,msgAk] -->  DecodeB(msgA1,...,msgAk) --> setB: Bob

// DigestSymbol is aliased from revIdxStore.DigestSymbol.
type DigestSymbol = revIdxStore.DigestSymbol

// -----------------------------------------------------------------------------
type RIBLTSession[T any, S Symbol[S]] struct {
	store        ReverseIndexStore[T, S]
	storeDigests []S
	encoder      riblt.Encoder[S]
	decoder      riblt.Decoder[S]

	// encodeSymbol encodes a symbol to a byte slice.
	encodeSymbol    func(S) []byte
	decodeSymbol    func([]byte) S
	symbolSize      uint32
	receivedSymbols int

	manualOverride bool
	manualLocal    []S
	manualRemote   []S
}

var _ ReconcilerSession[string, DigestSymbol] = (*RIBLTSession[string, DigestSymbol])(nil)

// NewRIBLTSession constructs a new RIBLT reconciliation session backed by the given store.
// Returns ErrNilStore if store is nil.
func NewRIBLTSession[T any, S Symbol[S]](store ReverseIndexStore[T, S],
	symbolSize uint32,
	encodeSymbol func(S) []byte,
	decodeSymbol func([]byte) S) (*RIBLTSession[T, S], error) {
	if store == nil {
		return nil, ErrNilStore
	}
	session := &RIBLTSession[T, S]{
		store:        store,
		storeDigests: store.DigestsCopy(),
		symbolSize:   symbolSize,
		encodeSymbol: encodeSymbol,
		decodeSymbol: decodeSymbol,
	}

	session.initCodecs()

	return session, nil
}

type RIBLTSessionFactory[T any, S Symbol[S]] struct {
	SymbolSize   uint32
	EncodeSymbol func(S) []byte
	DecodeSymbol func([]byte) S
}

// NewCustomRIBLTSessionFactory constructs an RIBLT session factory with customized symbol sizes and codecs.
func NewCustomRIBLTSessionFactory[T any, S Symbol[S]](
	symbolSize uint32,
	encode func(S) []byte,
	decode func([]byte) S,
) *RIBLTSessionFactory[T, S] {
	return &RIBLTSessionFactory[T, S]{
		SymbolSize:   symbolSize,
		EncodeSymbol: encode,
		DecodeSymbol: decode,
	}
}

// NewRIBLTSessionFactory constructs a SessionFactory backed by rateless IBLT using standard 64-bit digest symbols.
func NewRIBLTSessionFactory[T any]() *RIBLTSessionFactory[T, revIdxStore.DigestSymbol] {
	return NewCustomRIBLTSessionFactory[T, revIdxStore.DigestSymbol](
		8,
		func(s revIdxStore.DigestSymbol) []byte {
			buf := make([]byte, 8)
			binary.LittleEndian.PutUint64(buf, uint64(s))
			return buf
		},
		func(b []byte) revIdxStore.DigestSymbol {
			return revIdxStore.DigestSymbol(binary.LittleEndian.Uint64(b))
		},
	)
}

// NewSession implements SessionFactory[T, S]
func (f *RIBLTSessionFactory[T, S]) NewSession(store ReverseIndexStore[T, S]) (ReconcilerSession[T, S], error) {
	return NewRIBLTSession[T](store, f.SymbolSize, f.EncodeSymbol, f.DecodeSymbol)
}

func (session *RIBLTSession[T, S]) initCodecs() {
	session.encoder = riblt.Encoder[S]{}
	session.decoder = riblt.Decoder[S]{}
	for _, dig := range session.storeDigests {
		session.encoder.AddSymbol(dig)
		session.decoder.AddSymbol(dig)
	}
}

func hashDigestsToDigests[S Symbol[S]](h []riblt.HashedSymbol[S]) []S {
	res := make([]S, len(h))
	for i, hs := range h {
		res[i] = hs.Symbol
	}
	return res
}

func (s *RIBLTSession[T, S]) RemoteDigests() []S {
	if s.manualOverride {
		return s.manualRemote
	}
	return hashDigestsToDigests(s.decoder.Remote())
}

func (s *RIBLTSession[T, S]) LocalDigests() []S {
	if s.manualOverride {
		return s.manualLocal
	}
	return hashDigestsToDigests(s.decoder.Local())
}

// SetResolvedDiffs directly sets the resolved local and remote diffs and marks the session as done.
func (s *RIBLTSession[T, S]) SetResolvedDiffs(localDiff, remoteDiff []S) {
	s.manualLocal = localDiff
	s.manualRemote = remoteDiff
	s.manualOverride = true
	s.receivedSymbols = 1
}

// DiffDigests returns the union of RemoteDigests and LocalDigests (the symmetric difference).
func (s *RIBLTSession[T, S]) DiffDigests() []S {
	return DiffDigests(s.LocalDigests(), s.RemoteDigests())
}

// LocalElements returns the local elements from the underlying store corresponding to LocalDigests.
func (s *RIBLTSession[T, S]) LocalElements() []T {
	return SessionLocalElements(s.store, s.LocalDigests())
}

func (s *RIBLTSession[T, S]) ProcessIncomingDigests(incoming []S) {
	for _, d := range incoming {
		s.decoder.AddSymbol(d)
	}
}

func (s *RIBLTSession[T, S]) Done() bool {
	if s.manualOverride {
		return true
	}
	return s.receivedSymbols > 0 && s.decoder.Decoded()
}

func (s *RIBLTSession[T, S]) GenerateNextMessage() ([]byte, error) {
	codedSymbol := s.encoder.ProduceNextCodedSymbol()

	buf := make([]byte, s.symbolSize+16)
	copy(buf[:s.symbolSize], s.encodeSymbol(codedSymbol.Symbol))
	binary.LittleEndian.PutUint64(buf[s.symbolSize:s.symbolSize+8], codedSymbol.Hash)
	binary.LittleEndian.PutUint64(buf[s.symbolSize+8:], uint64(codedSymbol.Count))
	return buf, nil
}

// assumes message is a single incoming coded symbol
func (s *RIBLTSession[T, S]) ProcessIncomingMessage(msg []byte) error {
	expectedLen := s.symbolSize + 16
	if uint32(len(msg)) < expectedLen {
		return fmt.Errorf("message too short: expected at least %d bytes, got %d", expectedLen, len(msg))
	}
	sym := riblt.CodedSymbol[S]{
		HashedSymbol: riblt.HashedSymbol[S]{
			Symbol: s.decodeSymbol(msg[:s.symbolSize]),
			Hash:   binary.LittleEndian.Uint64(msg[s.symbolSize : s.symbolSize+8]),
		},
		Count: int64(binary.LittleEndian.Uint64(msg[s.symbolSize+8 : expectedLen])),
	}
	s.decoder.AddCodedSymbol(sym)
	s.decoder.TryDecode()
	s.receivedSymbols++
	return nil
}
