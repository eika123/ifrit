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

type NoteTestSuite struct {
	suite.Suite
}

func TestNoteTestSuite(t *testing.T) {
	r := log.Root()

	//r.SetHandler(log.CallerFileHandler(log.StreamHandler(os.Stdout, log.TerminalFormat())))

	r.SetHandler(log.DiscardHandler())
	suite.Run(t, new(NoteTestSuite))
}

func (suite *NoteTestSuite) TestSameEpoch() {
	n := &Note{
		epoch: 3,
	}

	assert.True(suite.T(), n.Equal(n.epoch), "Returns false when epochs are equal")

	assert.False(suite.T(), n.Equal(n.epoch+1), "Returns true when epochs are not equal")
}

func (suite *NoteTestSuite) TestIsMoreRecent() {
	n := &Note{
		epoch: 5,
	}

	assert.True(suite.T(), n.IsMoreRecent(n.epoch+1), "returns false when epoch is higher than note epoch")

	assert.False(suite.T(), n.IsMoreRecent(n.epoch-1), "returns true when epoch is lower than note epoch")

	assert.False(suite.T(), n.IsMoreRecent(n.epoch), "returns true when epoch is equal to the note epoch")
}

func (suite *NoteTestSuite) TestToPbMsg() {
	n := &Note{
		id:    "testid1",
		mask:  1,
		epoch: 3,
		signature: &signature{
			r: []byte("testR"),
			s: []byte("testS"),
		},
	}

	gossipNote := n.ToPbMsg()
	require.NotNil(suite.T(), gossipNote, "Protobuf message is nil")

	assert.Equal(suite.T(), n.id, string(gossipNote.GetId()), "Protobuf id is not equal")

	assert.Equal(suite.T(), n.mask, gossipNote.GetMask(), "Protobuf mask is not equal")

	assert.Equal(suite.T(), n.epoch, gossipNote.GetEpoch(), "Protobuf epoch is not equal")

	assert.Equal(suite.T(), n.signature.r, gossipNote.GetSignature().GetR(), "Protobuf signature r component is not equal")

	assert.Equal(suite.T(), n.signature.s, gossipNote.GetSignature().GetS(), "Protobuf signature s component is not equal")
}

func (suite *NoteTestSuite) TestSign() {
	n := &Note{
		id:    "testid1",
		mask:  1,
		epoch: 3,
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(suite.T(), err, "Failed to generate private key")

	assert.Error(suite.T(), signNote(n, nil), "Returns no error with no private key")

	assert.Nil(suite.T(), n.signature, "Signature is not nil before signing")

	assert.NoError(suite.T(), signNote(n, privKey), "Returns error with non-nil private key")

	assert.NotNil(suite.T(), n.signature, "Signature is still nil after signing accusation")

	assert.NotNil(suite.T(), n.signature.r, "Signature r component is still nil after signing accusation")

	assert.NotNil(suite.T(), n.signature.s, "Signature s component is still nil after signing accusation")
}

func (suite *NoteTestSuite) TestCryptographicIdentity() {
	n1 := &Note{
		id:    "node-1",
		epoch: 5,
		mask:  1,
	}
	n2 := &Note{
		id:    "node-1",
		epoch: 5,
		mask:  2,
	}

	assert.Equal(suite.T(), []byte("node-1:5:1"), n1.CryptographicIdentity())
	assert.Equal(suite.T(), []byte("node-1:5:2"), n2.CryptographicIdentity())
	assert.NotEqual(suite.T(), n1.CryptographicIdentity(), n2.CryptographicIdentity())
	assert.Equal(suite.T(), "node-1", n1.Id())
}

func (suite *NoteTestSuite) TestNoteFromPb() {
	assert.Nil(suite.T(), NoteFromPb(nil))

	// Note without signature
	pbUnsigned := &pb.Note{
		Id:    []byte("node-unsigned"),
		Epoch: 10,
		Mask:  7,
	}
	n1 := NoteFromPb(pbUnsigned)
	require.NotNil(suite.T(), n1)
	assert.Equal(suite.T(), "node-unsigned", n1.Id())
	assert.Equal(suite.T(), uint64(10), n1.Epoch())
	assert.Equal(suite.T(), uint32(7), n1.Mask())
	assert.Nil(suite.T(), n1.signature)

	// Round-trip ToPbMsg without panic on nil signature
	pbRoundTrip := n1.ToPbMsg()
	assert.Equal(suite.T(), pbUnsigned.GetId(), pbRoundTrip.GetId())
	assert.Equal(suite.T(), pbUnsigned.GetEpoch(), pbRoundTrip.GetEpoch())
	assert.Equal(suite.T(), pbUnsigned.GetMask(), pbRoundTrip.GetMask())
	assert.Nil(suite.T(), pbRoundTrip.GetSignature())

	// Note with signature
	pbSigned := &pb.Note{
		Id:    []byte("node-signed"),
		Epoch: 15,
		Mask:  3,
		Signature: &pb.Signature{
			R: []byte("sig-r-bytes"),
			S: []byte("sig-s-bytes"),
		},
	}
	n2 := NoteFromPb(pbSigned)
	require.NotNil(suite.T(), n2)
	assert.Equal(suite.T(), "node-signed", n2.Id())
	assert.Equal(suite.T(), uint64(15), n2.Epoch())
	assert.Equal(suite.T(), uint32(3), n2.Mask())
	require.NotNil(suite.T(), n2.signature)
	assert.Equal(suite.T(), []byte("sig-r-bytes"), n2.signature.r)
	assert.Equal(suite.T(), []byte("sig-s-bytes"), n2.signature.s)

	pbSignedRoundTrip := n2.ToPbMsg()
	require.NotNil(suite.T(), pbSignedRoundTrip.GetSignature())
	assert.Equal(suite.T(), []byte("sig-r-bytes"), pbSignedRoundTrip.GetSignature().GetR())
	assert.Equal(suite.T(), []byte("sig-s-bytes"), pbSignedRoundTrip.GetSignature().GetS())
}
