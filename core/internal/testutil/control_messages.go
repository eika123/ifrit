package testutil

import (
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/eika123/ifrit/crypto"
	pb "github.com/eika123/ifrit/protobuf"
	"github.com/golang/protobuf/proto"
)

// NewNote builds and ECDSA-signs a protobuf Note for tests.
func NewNote(id string, epoch uint64, mask uint32, priv *ecdsa.PrivateKey) *pb.Note {
	if priv == nil {
		panic("testutil.NewNote: private key is nil")
	}
	noteMsg := &pb.Note{
		Epoch: epoch,
		Id:    []byte(id),
		Mask:  mask,
	}
	b, err := proto.Marshal(noteMsg)
	if err != nil {
		panic(err)
	}
	hash := crypto.HashContent(b)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	if err != nil {
		panic(err)
	}
	noteMsg.Signature = &pb.Signature{
		R: r.Bytes(),
		S: s.Bytes(),
	}
	return noteMsg
}

// NewUnsignedNote builds an unsigned protobuf Note (with an empty Signature) for tests.
func NewUnsignedNote(id string, epoch uint64, mask uint32) *pb.Note {
	return &pb.Note{
		Epoch:     epoch,
		Id:        []byte(id),
		Mask:      mask,
		Signature: &pb.Signature{},
	}
}

// NewAccusation builds and ECDSA-signs a protobuf Accusation for tests.
func NewAccusation(epoch uint64, accused, accuser string, ringNum uint32, priv *ecdsa.PrivateKey) *pb.Accusation {
	if priv == nil {
		panic("testutil.NewAccusation: private key is nil")
	}
	accMsg := &pb.Accusation{
		Epoch:   epoch,
		Accuser: []byte(accuser),
		Accused: []byte(accused),
		RingNum: ringNum,
	}
	b, err := proto.Marshal(accMsg)
	if err != nil {
		panic(err)
	}
	hash := crypto.HashContent(b)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	if err != nil {
		panic(err)
	}
	accMsg.Signature = &pb.Signature{
		R: r.Bytes(),
		S: s.Bytes(),
	}
	return accMsg
}

// NewUnsignedAccusation builds an unsigned protobuf Accusation (with an empty Signature) for tests.
func NewUnsignedAccusation(epoch uint64, accused, accuser string, ringNum uint32) *pb.Accusation {
	return &pb.Accusation{
		Epoch:     epoch,
		Accuser:   []byte(accuser),
		Accused:   []byte(accused),
		RingNum:   ringNum,
		Signature: &pb.Signature{},
	}
}
