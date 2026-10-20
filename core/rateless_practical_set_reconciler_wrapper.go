// Wraps the rateless practical set reconciliation pacakge https://github.com/yangl1996/riblt
// to fit the current interface ReconcileableStore expected by Ifrit.

package core

import (
	"encoding/binary"
	"fmt"

	"github.com/dchest/siphash"
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

type sym[S any] interface {
	riblt.Symbol[S]
}

// -------------------- Conrecte implementation of a symbol -------------------
type DigestSymbol uint64

// XOR implements riblt.Symbol[DigestSymbol]
func (d DigestSymbol) XOR(other DigestSymbol) DigestSymbol {
	return d ^ other
}

// Hash implements riblt.Symbol[DigestSymbol] (must be non-homomorphic to XOR)
func (d DigestSymbol) Hash() uint64 {
	buf := [8]byte{}
	binary.LittleEndian.PutUint64(buf[:], uint64(d))
	return siphash.Hash(50683, 19283, buf[:])
}

// -----------------------------------------------------------------------------
type RIBLTSession[T any, S Symbol[S]] struct {
	store   ReverseIndexStore[T, S]
	encoder riblt.Encoder[S]
	decoder riblt.Decoder[S]

	// encodeSymbol encodes a symbol to a byte slice.
	encodeSymbol    func(S) []byte
	decodeSymbol    func([]byte) S
	symbolSize      uint32
	receivedSymbols int
}

func newRIBLTSession[T any, S Symbol[S]](store ReverseIndexStore[T, S],
	symbolSize uint32,
	encodeSymbol func(S) []byte,
	decodeSymbol func([]byte) S) *RIBLTSession[T, S] {
	session := &RIBLTSession[T, S]{
		store:        store,
		symbolSize:   symbolSize,
		encodeSymbol: encodeSymbol,
		decodeSymbol: decodeSymbol,
	}

	session.initCodecs()

	return session
}

type RIBLTSessionFactory[T any, S Symbol[S]] struct {
	SymbolSize   uint32
	EncodeSymbol func(S) []byte
	DecodeSymbol func([]byte) S
}

// A factory of factories for RIBLT; use this to construct your applications session factory when using rIBLT
func RIBLTSessionFactoryConstructor[T any, S Symbol[S]](
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

// NewSession implements SessionFactory[S]
func (f *RIBLTSessionFactory[T, S]) NewSession(store ReverseIndexStore[T, S]) ReconcilerSession[T, S] {
	return newRIBLTSession(store.Copy(), f.SymbolSize, f.EncodeSymbol, f.DecodeSymbol)
}

func (session *RIBLTSession[T, S]) initCodecs() {
	digests := session.store.Digests()
	session.encoder = riblt.Encoder[S]{}
	session.decoder = riblt.Decoder[S]{}
	for _, dig := range digests {
		session.encoder.AddSymbol(dig)
		session.decoder.AddSymbol(dig)
	}
}

func hashDigestsToDigests[S sym[S]](h []riblt.HashedSymbol[S]) []S {
	res := make([]S, len(h))
	for i, hs := range h {
		res[i] = hs.Symbol
	}
	return res
}

func (s *RIBLTSession[T, S]) RemoteDigests() []S { return hashDigestsToDigests(s.decoder.Remote()) }
func (s *RIBLTSession[T, S]) LocalDigests() []S  { return hashDigestsToDigests(s.decoder.Local()) }

func (s *RIBLTSession[T, S]) Done() bool {
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
