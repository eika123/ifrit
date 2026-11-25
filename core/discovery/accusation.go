package discovery

import (
	"errors"
	"fmt"

	pb "github.com/eika123/ifrit/protobuf"
	gpb "github.com/golang/protobuf/proto"
)

var (
	errNoPrivKey = errors.New("Provided private key was nil")
)

type Accusation struct {
	ringNum uint32
	epoch   uint64
	accuser string
	accused string
	*signature
}

// CryptographicIdentity returns the deterministic byte slice uniquely identifying
// this accusation across all rings and epochs.
func (a Accusation) CryptographicIdentity() []byte {
	return fmt.Appendf(nil, "%s:%s:%d:%d", a.accused, a.accuser, a.ringNum, a.epoch)
}

// UnsignedBytes returns the canonical unsigned protobuf serialization of a
// used for ECDSA signing and verification.
func (a *Accusation) UnsignedBytes() ([]byte, error) {
	return gpb.Marshal(&pb.Accusation{
		Epoch:   a.epoch,
		Accuser: []byte(a.accuser),
		Accused: []byte(a.accused),
		RingNum: a.ringNum,
	})
}

// Checks that for this accusation a:
//   - a.accused == accused
//   - a.accuser == accuser
//   - a.ringNum == ringNum
//   - a.epoch == epoch
func (a Accusation) Equal(accused, accuser string, ringNum uint32, epoch uint64) bool {
	return a.accused == accused && a.accuser == accuser && a.ringNum == ringNum && a.epoch == epoch
}

// check if the argument 'other' is more recent (larger) than a.epoch
func (a Accusation) IsMoreRecent(other uint64) bool {
	return a.epoch < other
}

func (a Accusation) IsAccuser(id string) bool {
	return a.accuser == id
}

func (a Accusation) Accused() string {
	return a.accused
}

func (a Accusation) Accuser() string {
	return a.accuser
}

func (a Accusation) RingNum() uint32 {
	return a.ringNum
}

func (a Accusation) Epoch() uint64 {
	return a.epoch
}

func (a Accusation) Signature() (r, s []byte) {
	if a.signature == nil {
		return nil, nil
	}
	return a.r, a.s
}

func (a *Accusation) HasSignature() bool {
	return a != nil && a.signature != nil
}

// Converts the internal Accusation struct to a protobuf Accusation message.
func (a Accusation) ToPbMsg() *pb.Accusation {
	msg := &pb.Accusation{
		Epoch:   a.epoch,
		Accuser: []byte(a.accuser),
		Accused: []byte(a.accused),
		RingNum: a.ringNum,
	}
	if a.signature != nil {
		msg.Signature = &pb.Signature{
			R: a.r,
			S: a.s,
		}
	}
	return msg
}

// AccusationFromPb unconditionally constructs an internal Accusation from a protobuf Accusation message,
// safely handling nil signatures or empty fields.
func AccusationFromPb(pbAcc *pb.Accusation) *Accusation {
	if pbAcc == nil {
		return nil
	}
	a := &Accusation{
		epoch:   pbAcc.GetEpoch(),
		ringNum: pbAcc.GetRingNum(),
		accuser: string(pbAcc.GetAccuser()),
		accused: string(pbAcc.GetAccused()),
	}
	if sign := pbAcc.GetSignature(); sign != nil {
		a.signature = &signature{
			r: sign.GetR(),
			s: sign.GetS(),
		}
	}
	return a
}
