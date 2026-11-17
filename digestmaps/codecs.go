package digestmaps

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/yangl1996/riblt"
)

var (
	ErrInvalidDigestLength = errors.New("expect digestSymbol to be 8 bytes")
	ErrDecodeSymbol        = errors.New("failed decoding symbol")
)

type SymbolEncoder[S Symbol[S]] func(S) []byte
type SymbolDecoder[S Symbol[S]] func([]byte) (S, error)

type RawHashedSymbol interface {
	GetSymbol() []byte
	GetHash() uint64
}

type RawCodedSymbol[H RawHashedSymbol] interface {
	GetHashedSymbol() H
	GetCount() int64
}

func EncodeDigestSymbol(sym DigestSymbol) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(sym))
	return buf
}

func DecodeDigestSymbol(sym []byte) (DigestSymbol, error) {
	if len(sym) != 8 {
		return 0, ErrInvalidDigestLength
	}
	return DigestSymbol(binary.BigEndian.Uint64(sym)), nil
}

// ///////////////////////////////////////////////////////////////
// DecodeSymbols parameterizes R over RawHashedSymbol because Go slices are invariant
// ([]*T cannot be passed as []RawHashedSymbol), whereas DecodeHashedSymbol takes a
// single value and accepts RawHashedSymbol directly.

// Sends hashed symbols from a protobuf wire (or anything satisfying the RawHashedSymbol interface)
// into an riblt.Symbol
func DecodeSymbols[S Symbol[S], R RawHashedSymbol](
	rawHashedSymbols []R,
	decode SymbolDecoder[S],
) ([]S, error) {
	out := make([]S, len(rawHashedSymbols))
	var err error
	for i, s := range rawHashedSymbols {
		if out[i], err = decode(s.GetSymbol()); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrDecodeSymbol, err)
		}
	}
	return out, nil
}

func DecodeHashedSymbol[S Symbol[S]](
	rawHashedSymbol RawHashedSymbol,
	decode SymbolDecoder[S],
) (riblt.HashedSymbol[S], error) {
	sym, err := decode(rawHashedSymbol.GetSymbol())
	if err != nil {
		var zero riblt.HashedSymbol[S]
		return zero, fmt.Errorf("%w: %w", ErrDecodeSymbol, err)
	}
	return riblt.HashedSymbol[S]{
		Symbol: sym,
		Hash:   rawHashedSymbol.GetHash(),
	}, nil
}

/////////////////////////////////////////////////////////////////

func EncodeHashedSymbol[S Symbol[S], Out RawHashedSymbol](
	sym riblt.HashedSymbol[S],
	encode SymbolEncoder[S],
	build func(symbol []byte, hash uint64) Out,
) Out {
	return build(encode(sym.Symbol), sym.Hash)
}

func EncodeHashedSymbols[S Symbol[S], Out RawHashedSymbol](
	syms []riblt.HashedSymbol[S],
	encode SymbolEncoder[S],
	build func(symbol []byte, hash uint64) Out,
) []Out {
	out := make([]Out, len(syms))
	for i, s := range syms {
		out[i] = EncodeHashedSymbol(s, encode, build)
	}
	return out
}

func DecodeCodedSymbols[S Symbol[S], H RawHashedSymbol, C RawCodedSymbol[H]](
	raw []C,
	decode SymbolDecoder[S],
) ([]riblt.CodedSymbol[S], error) {
	out := make([]riblt.CodedSymbol[S], len(raw))
	for i, s := range raw {
		hs, err := DecodeHashedSymbol(s.GetHashedSymbol(), decode)
		if err != nil {
			return nil, err
		}
		out[i] = riblt.CodedSymbol[S]{
			HashedSymbol: hs,
			Count:        s.GetCount(),
		}
	}
	return out, nil
}
