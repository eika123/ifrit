package discovery

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	pb "github.com/joonnna/ifrit/protobuf"
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

// ID returns the canonical string identifier for this accusation,
// binding (accused, accuser, ringNum, epoch).
func (a Accusation) ID() string {
	return fmt.Sprintf("%s:%s:%d:%d", a.accused, a.accuser, a.ringNum, a.epoch)
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

// Converts the internal Accusation struct to a protobuf Accusation message.
func (a Accusation) ToPbMsg() *pb.Accusation {
	return &pb.Accusation{
		Epoch:   a.epoch,
		Accuser: []byte(a.accuser),
		Accused: []byte(a.accused),
		RingNum: a.ringNum,
		Signature: &pb.Signature{
			R: a.r,
			S: a.s,
		},
	}
}

/*

########## METHODS ONLY USED FOR TESTING BELOW THIS LINE ##########

*/

// ONLY for testing
func NewAccusation(epoch uint64, accused, accuser string, ringNum uint32, priv *ecdsa.PrivateKey) *pb.Accusation {
	a := &Accusation{
		accused: accused,
		accuser: accuser,
		epoch:   epoch,
		ringNum: ringNum,
	}

	err := signAcc(a, priv)
	if err != nil {
		panic(err)
	}

	return a.ToPbMsg()
}

// ONLY for testing
func NewUnsignedAccusation(epoch uint64, accused, accuser string, ringNum uint32) *pb.Accusation {
	a := &Accusation{
		accused:   accused,
		accuser:   accuser,
		epoch:     epoch,
		ringNum:   ringNum,
		signature: &signature{},
	}

	return a.ToPbMsg()
}

// ONLY for testing
func signAcc(a *Accusation, privKey *ecdsa.PrivateKey) error {
	if privKey == nil {
		return errNoPrivKey
	}

	accMsg := &pb.Accusation{
		Epoch:   a.epoch,
		Accuser: []byte(a.accuser),
		Accused: []byte(a.accused),
		RingNum: a.ringNum,
	}

	b, err := proto.Marshal(accMsg)
	if err != nil {
		return err
	}

	hash := hashContent(b)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash)
	if err != nil {
		return err
	}

	a.signature = &signature{
		r: r.Bytes(),
		s: s.Bytes(),
	}

	return nil
}
