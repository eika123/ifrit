// Wraps the rateless practical set reconciliation pacakge https://github.com/yangl1996/riblt
// to fit the current interface ReconcileableStore expected by Ifrit.

package core

import (
	"encoding/binary"

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
// Alice
// NodeA: 	SetA = {a1, a2,..., aN} of type ReconcileableStore
// 		    - create encoder and feed SetA into it
// 		    - create decoder for Bobs replies
//
//
//
//
//
//
//			- create encoder and feed SetB into it
// 			- create decoder for Alices messages
// NodeB: SetB = {b1, b2,..., bN}
// Bob

type sym[S any] riblt.Symbol[S]

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

type Reconciler[T any] interface {
	ReverseIndexStore[T]
	RemoteDigests()
	LocalDigests()
}

type ReconcilerRIBLT[S sym[S]] struct {
	store ReverseIndexStore[S]
}

func NewRIBLTReconciler[S sym[S]]() ReconcilerRIBLT[S] {
	return ReconcilerRIBLT[S]{
		store: newDigestSet(S.Hash),
	}
}

func (s *ReconcilerRIBLT[S]) NewEncoder() riblt.Encoder[S] {
	encoder := riblt.Encoder[S]{}

	d := s.store.Elements()
	for _, item := range d {
		encoder.AddSymbol(item)
	}

	return encoder
}

func (s *ReconcilerRIBLT[S]) NewDecoder() riblt.Decoder[S] {
	decoder := riblt.Decoder[S]{}
	d := s.store.Elements()
	for _, item := range d {
		decoder.AddSymbol(item)
	}

	return decoder
}

// implement rest of the ReconcileableStore interface
func (s *ReconcilerRIBLT[S]) AddElement(elem S) bool {
	return s.store.AddElement(elem)
}
