package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	log "github.com/inconshreveable/log15"
	pb "github.com/joonnna/ifrit/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type AccTestSuite struct {
	suite.Suite
}

func TestAccTestSuite(t *testing.T) {
	r := log.Root()

	//r.SetHandler(log.CallerFileHandler(log.StreamHandler(os.Stdout, log.TerminalFormat())))

	r.SetHandler(log.DiscardHandler())
	suite.Run(t, new(AccTestSuite))
}

func (suite *AccTestSuite) TestEqual() {
	acc := &Accusation{
		accused: "testid1",
		accuser: "testid2",
		ringNum: 3,
		epoch:   5,
	}

	assert.True(suite.T(), acc.Equal(acc.accused, acc.accuser, acc.ringNum, acc.epoch), "accusation compare returns true with 2 equal accusations")

	assert.False(suite.T(), acc.Equal(acc.accused, "wrong_accuser", acc.ringNum, acc.epoch), "accusation compare returns true when accuser is wrong")

	assert.False(suite.T(), acc.Equal("wrong_accused", acc.accuser, acc.ringNum, acc.epoch), "accusation compare returns true when accused is wrong")

	assert.False(suite.T(), acc.Equal(acc.accused, acc.accuser, acc.ringNum-1, acc.epoch), "accusation compare returns true when ringNum is wrong")

	assert.False(suite.T(), acc.Equal(acc.accused, acc.accuser, acc.ringNum, acc.epoch-1), "accusation compare returns true when epoch is wrong")
}

func (suite *AccTestSuite) TestIsMoreRecent() {
	acc := &Accusation{
		epoch: 5,
	}

	assert.True(suite.T(), acc.IsMoreRecent(acc.epoch+1), "returns false when epoch is higher than accusation epoch")

	assert.False(suite.T(), acc.IsMoreRecent(acc.epoch-1), "returns true when epoch is lower than accusation epoch")

	assert.False(suite.T(), acc.IsMoreRecent(acc.epoch), "returns true when epoch is equal to the accusation epoch")
}

func (suite *AccTestSuite) TestIsAccuser() {
	acc := &Accusation{
		accuser: "testid1",
	}

	assert.True(suite.T(), acc.IsAccuser(acc.accuser), "returns false when id is the accuser")

	assert.False(suite.T(), acc.IsAccuser(acc.accuser+"test"), "returns true when id is not the accuser")
}

func (suite *AccTestSuite) TestToPbMsg() {
	acc := &Accusation{
		accused: "testid1",
		accuser: "testid2",
		ringNum: 3,
		epoch:   5,
		signature: &signature{
			r: []byte("testR"),
			s: []byte("testS"),
		},
	}

	gossipAcc := acc.ToPbMsg()

	require.NotNil(suite.T(), gossipAcc, "returned protobuf message is nil")

	assert.Equal(suite.T(), acc.accused, string(gossipAcc.GetAccused()), "Protobuf message has different accused field.")

	assert.Equal(suite.T(), acc.accuser, string(gossipAcc.GetAccuser()), "Protobuf message has different accuser field.")

	assert.Equal(suite.T(), acc.epoch, gossipAcc.GetEpoch(), "Protobuf message has different epoch field.")

	assert.Equal(suite.T(), acc.ringNum, gossipAcc.GetRingNum(), "Protobuf message has different ringNum field.")

	assert.Equal(suite.T(), acc.signature.r, gossipAcc.Signature.GetR(), "Protobuf message has different signature r field.")

	assert.Equal(suite.T(), acc.signature.s, gossipAcc.Signature.GetS(), "Protobuf message has different signature s field.")
}

func (suite *AccTestSuite) TestSign() {
	acc := &Accusation{
		accused: "testid1",
		accuser: "testid2",
		ringNum: 5,
		epoch:   3,
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(suite.T(), err, "Failed to generate private key")

	assert.Error(suite.T(), signAcc(acc, nil), "Returns no error with no private key")

	assert.Nil(suite.T(), acc.signature, "Signature is not nil before signing")

	assert.NoError(suite.T(), signAcc(acc, privKey), "Returns error with non-nil private key")

	assert.NotNil(suite.T(), acc.signature, "Signature is still nil after signing accusation")

	assert.NotNil(suite.T(), acc.signature.r, "Signature r component is still nil after signing accusation")

	assert.NotNil(suite.T(), acc.signature.s, "Signature s component is still nil after signing accusation")
}

func (suite *AccTestSuite) TestCryptographicIdentity() {
	a1 := &Accusation{
		accused: "node-1",
		accuser: "node-2",
		ringNum: 1,
		epoch:   5,
	}
	a2 := &Accusation{
		accused: "node-1",
		accuser: "node-2",
		ringNum: 2,
		epoch:   5,
	}

	assert.Equal(suite.T(), []byte("node-1:node-2:1:5"), a1.CryptographicIdentity())
	assert.Equal(suite.T(), []byte("node-1:node-2:2:5"), a2.CryptographicIdentity())
	assert.NotEqual(suite.T(), a1.CryptographicIdentity(), a2.CryptographicIdentity())
}

func (suite *AccTestSuite) TestAccusationFromPb() {
	assert.Nil(suite.T(), AccusationFromPb(nil))

	// Accusation without signature
	pbUnsigned := &pb.Accusation{
		Accused: []byte("node-accused"),
		Accuser: []byte("node-accuser"),
		RingNum: 3,
		Epoch:   7,
	}
	a1 := AccusationFromPb(pbUnsigned)
	require.NotNil(suite.T(), a1)
	assert.Equal(suite.T(), "node-accused", a1.Accused())
	assert.Equal(suite.T(), "node-accuser", a1.Accuser())
	assert.Equal(suite.T(), uint32(3), a1.RingNum())
	assert.Equal(suite.T(), uint64(7), a1.Epoch())
	assert.Nil(suite.T(), a1.signature)

	// Round-trip ToPbMsg without panic on nil signature
	pbRoundTrip := a1.ToPbMsg()
	assert.Equal(suite.T(), pbUnsigned.GetAccused(), pbRoundTrip.GetAccused())
	assert.Equal(suite.T(), pbUnsigned.GetAccuser(), pbRoundTrip.GetAccuser())
	assert.Equal(suite.T(), pbUnsigned.GetRingNum(), pbRoundTrip.GetRingNum())
	assert.Equal(suite.T(), pbUnsigned.GetEpoch(), pbRoundTrip.GetEpoch())
	assert.Nil(suite.T(), pbRoundTrip.GetSignature())

	// Accusation with signature
	pbSigned := &pb.Accusation{
		Accused: []byte("node-accused"),
		Accuser: []byte("node-accuser"),
		RingNum: 2,
		Epoch:   8,
		Signature: &pb.Signature{
			R: []byte("acc-r-bytes"),
			S: []byte("acc-s-bytes"),
		},
	}
	a2 := AccusationFromPb(pbSigned)
	require.NotNil(suite.T(), a2)
	assert.Equal(suite.T(), "node-accused", a2.Accused())
	assert.Equal(suite.T(), "node-accuser", a2.Accuser())
	assert.Equal(suite.T(), uint32(2), a2.RingNum())
	assert.Equal(suite.T(), uint64(8), a2.Epoch())
	require.NotNil(suite.T(), a2.signature)
	assert.Equal(suite.T(), []byte("acc-r-bytes"), a2.signature.r)
	assert.Equal(suite.T(), []byte("acc-s-bytes"), a2.signature.s)

	pbSignedRoundTrip := a2.ToPbMsg()
	require.NotNil(suite.T(), pbSignedRoundTrip.GetSignature())
	assert.Equal(suite.T(), []byte("acc-r-bytes"), pbSignedRoundTrip.GetSignature().GetR())
	assert.Equal(suite.T(), []byte("acc-s-bytes"), pbSignedRoundTrip.GetSignature().GetS())
}
