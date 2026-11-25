package discovery

import (
	"fmt"

	pb "github.com/eika123/ifrit/protobuf"
	gpb "github.com/golang/protobuf/proto"
)

type Note struct {
	epoch uint64
	mask  uint32
	id    string
	*signature
}

func (n Note) CryptographicIdentity() []byte {
	return fmt.Appendf(nil, "%s:%d:%d", n.id, n.epoch, n.mask)
}

// UnsignedBytes returns the canonical unsigned protobuf serialization of n
// used for ECDSA signing and verification.
func (n *Note) UnsignedBytes() ([]byte, error) {
	return gpb.Marshal(&pb.Note{
		Epoch: n.epoch,
		Id:    []byte(n.id),
		Mask:  n.mask,
	})
}

func (n Note) IsRingDisabled(ringNum, numRings uint32) bool {
	idx := int(ringNum) - 1

	maxIdx := uint32(numRings - 1)

	if idx > int(maxIdx) || idx < 0 {
		return false
	}

	return !hasBit(n.mask, uint32(idx))
}

func (n *Note) Equal(epoch uint64) bool {
	return n.epoch == epoch
}

// check if argument other is newer (larger) than n.epoch
func (n *Note) IsMoreRecent(other uint64) bool {
	return n.epoch < other
}

func (n *Note) Epoch() uint64 {
	return n.epoch
}

func (n *Note) Mask() uint32 {
	return n.mask
}

func (n *Note) Id() string {
	return n.id
}

func (n *Note) HasSignature() bool {
	return n != nil && n.signature != nil
}

func (n *Note) Signature() (r, s []byte) {
	if n == nil || n.signature == nil {
		return nil, nil
	}
	return n.signature.r, n.signature.s
}

func (n *Note) ToPbMsg() *pb.Note {
	msg := &pb.Note{
		Epoch: n.epoch,
		Id:    []byte(n.id),
		Mask:  n.mask,
	}
	if n.signature != nil {
		msg.Signature = &pb.Signature{
			R: n.r,
			S: n.s,
		}
	}
	return msg
}

// NoteFromPb unconditionally constructs an internal Note from a protobuf Note message,
// safely handling nil signatures or empty fields.
func NoteFromPb(pbNote *pb.Note) *Note {
	if pbNote == nil {
		return nil
	}
	n := &Note{
		epoch: pbNote.GetEpoch(),
		mask:  pbNote.GetMask(),
		id:    string(pbNote.GetId()),
	}
	if sign := pbNote.GetSignature(); sign != nil {
		n.signature = &signature{
			r: sign.GetR(),
			s: sign.GetS(),
		}
	}
	return n
}
