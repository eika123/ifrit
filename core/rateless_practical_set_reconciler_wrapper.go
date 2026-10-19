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

type RIBLTSession[S sym[S]] struct {
	store   ReverseIndexStore[S]
	encoder riblt.Encoder[S]
	decoder riblt.Decoder[S]

	// encodeSymbol encodes a symbol to a byte slice.
	encodeSymbol    func(S) []byte
	decodeSymbol    func([]byte) S
	symbolSize      uint32
	receivedSymbols int
}

func NewRIBLTSession[S sym[S]](store ReverseIndexStore[S],
	symbolSize uint32,
	encodeSymbol func(S) []byte,
	decodeSymbol func([]byte) S) *RIBLTSession[S] {
	session := &RIBLTSession[S]{
		store:        store,
		symbolSize:   symbolSize,
		encodeSymbol: encodeSymbol,
		decodeSymbol: decodeSymbol,
	}

	session.newEncoder()
	session.newDecoder()

	return session
}

func (s *RIBLTSession[S]) newEncoder() {
	s.encoder = riblt.Encoder[S]{}

	d := s.store.Elements()
	for _, item := range d {
		s.encoder.AddSymbol(item)
	}
}

func (s *RIBLTSession[S]) newDecoder() {
	s.decoder = riblt.Decoder[S]{}
	d := s.store.Elements()
	for _, item := range d {
		s.decoder.AddSymbol(item)
	}
}

func hashDigestsToDigests[S sym[S]](h []riblt.HashedSymbol[S]) []S {
	res := make([]S, len(h))
	for i, hs := range h {
		res[i] = hs.Symbol
	}
	return res
}
func (s *RIBLTSession[S]) RemoteDigests() []S { return hashDigestsToDigests(s.decoder.Remote()) }
func (s *RIBLTSession[S]) LocalDigests() []S  { return hashDigestsToDigests(s.decoder.Local()) }

func (s *RIBLTSession[S]) Done() bool {
	return s.receivedSymbols > 0 && s.decoder.Decoded()
}

func (s *RIBLTSession[S]) GenerateNextMessage() ([]byte, error) {
	codedSymbol := s.encoder.ProduceNextCodedSymbol()

	buf := make([]byte, s.symbolSize+16)
	copy(buf[:s.symbolSize], s.encodeSymbol(codedSymbol.Symbol))
	binary.LittleEndian.PutUint64(buf[s.symbolSize:s.symbolSize+8], codedSymbol.Hash)
	binary.LittleEndian.PutUint64(buf[s.symbolSize+8:], uint64(codedSymbol.Count))
	return buf, nil
}

func (s *RIBLTSession[S]) ProcessIncomingMessage(msg []byte) error {
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
