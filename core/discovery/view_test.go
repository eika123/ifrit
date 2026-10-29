package discovery

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ViewTestSuite struct {
	suite.Suite

	v *View
}

func TestViewTestSuite(t *testing.T) {
	r := log.Root()

	r.SetHandler(log.CallerFileHandler(log.StreamHandler(os.Stdout, log.TerminalFormat())))
	//r.SetHandler(log.DiscardHandler())

	suite.Run(t, new(ViewTestSuite))
}

func (suite *ViewTestSuite) SetupTest() {
	privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(suite.T(), err, "Failed to generate private key.")

	cert := validCert("selfId", privKey.Public())

	v, err := NewView(10, cert, &cmStub{}, &signerStub{})
	require.NoError(suite.T(), err, "Failed to create view.")

	suite.v = v
}

func (suite *ViewTestSuite) TestNewView() {
	privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(suite.T(), err, "Failed to generate private key.")

	cert := validCert("selfId", privKey.Public())

	var numRings uint32 = 10

	expectedByz := (numRings - 1) / 2

	v, err := NewView(numRings, cert, &cmStub{}, &signerStub{})
	require.NoError(suite.T(), err, "Failed to create view.")
	require.Equal(suite.T(), expectedByz, v.maxByz, "Max byzantine not set correctly.")

	v2, err := NewView(2, cert, &cmStub{}, &signerStub{})
	require.NoError(suite.T(), err, "Failed to create view.")
	require.Equal(suite.T(), uint32(0), v2.maxByz, "Max byzantine should be zero with 2 rings.")

	v3, err := NewView(1, cert, &cmStub{}, &signerStub{})
	require.NoError(suite.T(), err, "Failed to create view.")
	require.Equal(suite.T(), uint32(0), v3.maxByz, "Max byzantine should be zero with 1 ring.")

	v4, err := NewView(3, cert, &cmStub{}, &signerStub{})
	require.NoError(suite.T(), err, "Failed to create view.")
	require.Equal(suite.T(), uint32(1), v4.maxByz, "Max byzantine should be 1 with 3 rings (k=2t+1).")

	_, err = NewView(0, cert, &cmStub{}, &signerStub{})
	require.Error(suite.T(), err, "Should return error with 0 rings.")

	_, err = NewView(numRings, nil, &cmStub{}, &signerStub{})
	require.Error(suite.T(), err, "Should return error with no certificate.")

}

func (suite *ViewTestSuite) TestNumRings() {
	assert.Equal(suite.T(), suite.v.rings.numRings, suite.v.NumRings(), "Does not return the correct numrings.")
}

func (suite *ViewTestSuite) TestSelf() {
	assert.Equal(suite.T(), suite.v.self, suite.v.Self(), "Does not return the correct self instance.")
}

func (suite *ViewTestSuite) TestPeer() {
	p := &Peer{
		Id: "testId",
	}

	suite.v.AddTestPeer(p)

	assert.Equal(suite.T(), p, suite.v.Peer(p.Id), "Did not find correct peer.")

	assert.Nil(suite.T(), suite.v.Peer("non-existing-id"), "Non-exisiting id should return nil.")

}

func (suite *ViewTestSuite) TestFull() {
	emptyView := suite.v.Full()

	assert.NotNil(suite.T(), emptyView, "Empty view should not be nil.")

	assert.Zero(suite.T(), len(emptyView), "Should be zero with empty view.")

	for i := 0; i < 10; i++ {
		p := &Peer{
			Id: fmt.Sprintf("testId%d", i),
		}

		suite.v.AddTestPeer(p)

		view := suite.v.Full()

		require.NotNil(suite.T(), view, "Should not ever be nil.")
		require.Equal(suite.T(), i+1, len(view), "Does not return entire view.")
	}
}

func (suite *ViewTestSuite) TestExists() {
	assert.False(suite.T(), suite.v.Exists("non-existing-id"), "Non-exisiting id should return false.")

	p := &Peer{
		Id: "TestId",
	}

	suite.v.AddTestPeer(p)

	assert.True(suite.T(), suite.v.Exists(p.Id), "Should return true on existing id.")
}

func (suite *ViewTestSuite) TestLive() {
	emptyView := suite.v.Live()

	assert.NotNil(suite.T(), emptyView, "Empty view should not be nil.")

	assert.Zero(suite.T(), len(emptyView), "Should be zero with empty view.")

	for i := 0; i < 10; i++ {
		p := &Peer{
			Id: fmt.Sprintf("testId%d", i),
		}

		suite.v.AddTestLivePeer(p)

		view := suite.v.Live()

		require.NotNil(suite.T(), view, "Should not ever be nil.")
		require.Equal(suite.T(), i+1, len(view), "Does not return entire view.")
	}
}

func (suite *ViewTestSuite) TestAddFull() {
	p := &Peer{
		Id: "TestId",
	}

	suite.v.AddTestPeer(p)

	privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(suite.T(), err, "Failed to generate private key.")

	certId := "otherId"
	cert := validCert(certId, privKey.Public())

	assert.EqualError(suite.T(), suite.v.AddFull(p.Id, cert), errPeerAlreadyExists.Error(), "Should return error when adding duplicate peer.")

	assert.Error(suite.T(), suite.v.AddFull(certId, nil), "Should return error with nil certr.")

	assert.NoError(suite.T(), suite.v.AddFull(certId, cert), "Should not return error with valid parameters.")
	assert.True(suite.T(), suite.v.Exists(certId), "Peer not added to map.")
	fp, err := suite.v.Fingerprint()
	require.NoError(suite.T(), err)
	assert.NotZero(suite.T(), fp, "View fingerprint should be non-zero.")
	assert.Equal(suite.T(), 2, suite.v.ViewStore().Size(), "ViewStore should contain added peers.")
}

func (suite *ViewTestSuite) TestMyNeighbours() {
	neighbours := suite.v.MyNeighbours()
	require.NotNil(suite.T(), neighbours, "Returned nil slice.")
	require.Zero(suite.T(), len(neighbours), "Should return none when only myself in view.")

	for i := 0; i < 10; i++ {
		p := &Peer{
			Id: fmt.Sprintf("testId%d", i),
		}

		suite.v.AddLive(p)
	}

	neighbours = suite.v.MyNeighbours()
	require.NotNil(suite.T(), neighbours, "Returned nil slice.")
	require.True(suite.T(), len(neighbours) >= 2, "Should always have 2 or more neighbours.")

	for _, peer := range neighbours {
		require.NotEqual(suite.T(), suite.v.self, peer, "Should not return self as neighbour with peers present in the live view.")
	}
}

func (suite *ViewTestSuite) TestGossipPartners() {
	var j uint32

	view := suite.v

	// Test behaviour when alone, should never return myself.

	require.Equal(suite.T(), uint32(1), view.currGossipRing, "Should start with gossip partners on ring 1.")
	for j = 0; j < view.rings.numRings; j++ {
		prev := view.currGossipRing

		partners := view.GossipPartners()
		require.NotNil(suite.T(), partners, "Should never return nil slice.")
		require.Zero(suite.T(), len(partners), "Should be empty when only myself in view.")

		if j == view.rings.numRings-1 {
			require.Equal(suite.T(), uint32(1), view.currGossipRing, "Gossip ring not reset to 1 upon reaching numRings.")
		} else {
			require.Equal(suite.T(), uint32(prev+1), view.currGossipRing, "Gossip ring not incremented.")
		}

	}

	for i := 0; i < 10; i++ {
		p := &Peer{
			Id: fmt.Sprintf("testId%d", i),
		}

		view.AddLive(p)
	}

	require.Equal(suite.T(), uint32(1), view.currGossipRing, "Should start with gossip partners on ring 1.")
	for j = 0; j < view.rings.numRings; j++ {
		prev := view.currGossipRing

		partners := view.GossipPartners()
		require.NotNil(suite.T(), partners, "Should never return nil slice.")
		require.Equal(suite.T(), 2, len(partners), "Should always have 2 neigbours per ring.")

		if j == view.rings.numRings-1 {
			require.Equal(suite.T(), uint32(1), view.currGossipRing, "Gossip ring not reset to 1 upon reaching numRings.")
		} else {
			require.Equal(suite.T(), uint32(prev+1), view.currGossipRing, "Gossip ring not incremented.")
		}

	}
}

func (suite *ViewTestSuite) TestMonitorTarget() {
	var j uint32

	view := suite.v

	// Test behaviour when alone, should never return myself.

	require.Equal(suite.T(), uint32(1), view.currMonitorRing, "Should start monitoring on ring 1.")
	for j = 0; j < view.rings.numRings; j++ {
		prev := view.currMonitorRing

		target, ringNum := view.MonitorTarget()
		require.Nil(suite.T(), target, "Should return nil when alone, the target was myself.")
		require.Equal(suite.T(), j+1, ringNum, "Should return ringNumber even if target was nil.")

		if j == view.rings.numRings-1 {
			require.Equal(suite.T(), uint32(1), view.currMonitorRing, "Monitor ring not reset to 1 upon reaching numRings.")
		} else {
			require.Equal(suite.T(), uint32(prev+1), view.currMonitorRing, "Monitor ring not incremented.")
		}

	}

	for i := 0; i < 10; i++ {
		p := &Peer{
			Id: fmt.Sprintf("testId%d", i),
		}

		view.AddLive(p)
	}

	require.Equal(suite.T(), uint32(1), view.currMonitorRing, "Should start monitoring on ring 1.")
	for j = 0; j < view.rings.numRings; j++ {
		prev := view.currMonitorRing

		target, ringNum := view.MonitorTarget()
		require.NotNil(suite.T(), target, "Should never return nil with peers present in live view.")
		require.NotEqual(suite.T(), view.self, target, "Should never return myself as monitor target.")
		require.Equal(suite.T(), j+1, ringNum, "Returned ringNumber does not match current ring.")

		if j == view.rings.numRings-1 {
			require.Equal(suite.T(), uint32(1), view.currMonitorRing, "Monitor ring not reset to 1 upon reaching numRings.")
		} else {
			require.Equal(suite.T(), uint32(prev+1), view.currMonitorRing, "Monitor ring not incremented.")
		}
	}
}

func (suite *ViewTestSuite) TestAddLive() {
	view := suite.v

	p := &Peer{
		Id: "testId",
	}

	view.AddLive(p)

	assert.Equal(suite.T(), 1, view.LiveStore().Size(), "Peer not added to liveStore.")
	assert.True(suite.T(), view.IsAlive(p), "Peer is not present in liveStore.")

	view.AddLive(p)
	assert.Equal(suite.T(), 1, view.LiveStore().Size(), "Adding peer twice does not alter state.")
	assert.True(suite.T(), view.IsAlive(p), "Adding peer twice does not alter state.")
}

func (suite *ViewTestSuite) TestRingNeighbours() {
	var i uint32

	view := suite.v

	for i = 1; i <= view.rings.numRings; i++ {
		succ, prev := view.MyRingNeighbours(i)
		require.Nil(suite.T(), succ, "Should return nil successor with empty view.")
		require.Nil(suite.T(), prev, "Should return nil predecessor with empty view.")
	}

	for j := 0; j < 10; j++ {
		p := &Peer{
			Id: fmt.Sprintf("testId%d", i),
		}

		view.AddLive(p)
	}

	for i = 1; i <= view.rings.numRings; i++ {
		succ, prev := view.MyRingNeighbours(i)
		require.NotNil(suite.T(), succ, "Should never return nil successor with non-empty view.")
		require.NotNil(suite.T(), prev, "Should never return nil predecessor with non-empty view.")
		require.NotEqual(suite.T(), succ, view.self, "Should never return self as neighbour.")
		require.NotEqual(suite.T(), prev, view.self, "Should never return self as neighbour.")
	}

}

func (suite *ViewTestSuite) TestRemoveLive() {
	view := suite.v

	p := &Peer{
		Id: "testId",
	}

	view.AddTestLivePeer(p)

	view.RemoveLive(p)

	assert.Zero(suite.T(), view.LiveStore().Size(), "Peer not removed from liveStore.")
	assert.False(suite.T(), view.IsAlive(p), "Peer still in liveStore after being removed.")

	view.RemoveLive(p)
	assert.Zero(suite.T(), view.LiveStore().Size(), "Removing peer twice alters state.")
	assert.False(suite.T(), view.IsAlive(p), "Removing peer twice alters state.")

	nonExistingId := "does-not-exist"

	view.RemoveLiveId(nonExistingId)
	assert.Zero(suite.T(), view.LiveStore().Size(), "Removing non-existing id alters state.")
	assert.False(suite.T(), view.IsAliveId(nonExistingId), "Removing non-existing id alters state.")

	view.RemoveLive(nil)
	assert.Zero(suite.T(), view.LiveStore().Size(), "Removing nil peer alters state.")
}

func (suite *ViewTestSuite) TestStartTimer() {
	view := suite.v

	accused := &Peer{
		Id: "testId",
	}

	accuser := &Peer{
		Id: "testId2",
	}

	note := &Note{
		id: accused.Id,
	}

	assert.EqualError(suite.T(), view.StartTimer(nil, note, accuser), errAccusedIsNil.Error(), "Should return error when accused is nil.")

	assert.EqualError(suite.T(), view.StartTimer(accused, nil, accuser), errNoNote.Error(), "Should return error when note is nil.")

	assert.EqualError(suite.T(), view.StartTimer(accused, note, nil), errObsIsNil.Error(), "Should return error when accuser is nil.")

	wrongNote := &Note{
		id: "non-existing-id",
	}

	assert.EqualError(suite.T(), view.StartTimer(accused, wrongNote, accuser), errWrongNote.Error(), "Should return error when the note does not belong to the accused.")

	assert.NoError(suite.T(), view.StartTimer(accused, note, accuser), "Failed to start timer with valid parameters.")

	prevTimeStamp, ok := view.timeoutMap[accused.Id]
	require.True(suite.T(), ok, "Timestamp not added.")

	assert.NoError(suite.T(), view.StartTimer(accused, note, accuser), "Starting same timer twice should not return error.")

	newTimeStamp, ok := view.timeoutMap[accused.Id]
	require.True(suite.T(), ok, "Timestamp not added.")

	assert.Equal(suite.T(), prevTimeStamp, newTimeStamp, "Should not start a new timer when starting the same timer twice.")

	// Clean before testing multiple timeouts.
	view.timeoutMap = make(map[string]*timeout)

	for i := 0; i < 100; i++ {
		accused := &Peer{
			Id: fmt.Sprintf("testAccused%d", i),
		}

		accuser := &Peer{
			Id: fmt.Sprintf("testAccuser%d", i),
		}

		note := &Note{
			id: accused.Id,
		}

		require.NoError(suite.T(), view.StartTimer(accused, note, accuser), "Should not return error when starting timer with correct parameters.")
		require.Equal(suite.T(), i+1, len(view.timeoutMap), "Timeouts not added correctly.")
	}
}

func (suite *ViewTestSuite) TestHasTimer() {
	view := suite.v

	assert.False(suite.T(), view.HasTimerId("non-existing-id"), "Should return false when there exists no timeout for the given id.")
	assert.False(suite.T(), view.HasTimer(nil), "Should return false for nil peer.")
	assert.False(suite.T(), view.HasTimer(&Peer{Id: "non-existing-id"}), "Should return false for non-existing peer.")

	t := &timeout{
		accused: &Peer{
			Id: "testId",
		},
	}

	view.timeoutMap[t.accused.Id] = t

	assert.True(suite.T(), view.HasTimer(t.accused), "Should return true when there exists a timeout for the given peer.")
	assert.True(suite.T(), view.HasTimerId(t.accused.Id), "Should return true when there exists a timeout for the given id.")
}

func (suite *ViewTestSuite) TestDeleteTimeout() {
	view := suite.v

	t := &timeout{
		accused: &Peer{
			Id: "testId",
		},
	}

	view.timeoutMap[t.accused.Id] = t

	view.DeleteTimeout(t.accused)

	_, ok := view.timeoutMap[t.accused.Id]
	assert.False(suite.T(), ok, "Timeout not removed.")
	assert.Zero(suite.T(), len(view.timeoutMap), "Map still has entries.")

	view.DeleteTimeoutId("non-existing-id")
	assert.Zero(suite.T(), len(view.timeoutMap), "Deleting non-existing id changes state.")

	view.DeleteTimeout(nil)
	assert.Zero(suite.T(), len(view.timeoutMap), "Deleting nil peer changes state.")
}

func (suite *ViewTestSuite) TestAllTimeouts() {
	view := suite.v

	timeouts := view.allTimeouts()
	require.NotNil(suite.T(), timeouts, "Should never return nil, even if there are no timeouts.")
	assert.Zero(suite.T(), len(timeouts), "Should be zero when there are no timeouts.")

	for i := 0; i < 10; i++ {
		t := &timeout{
			accused: &Peer{
				Id: fmt.Sprintf("testId%d", i),
			},
		}

		view.timeoutMap[t.accused.Id] = t

		ts := view.allTimeouts()
		require.NotNil(suite.T(), ts, "Should never be nil.")
		require.Equal(suite.T(), i+1, len(ts), "Timeouts not added correctly.")
	}
}

func (suite *ViewTestSuite) TestCheckTimeouts() {
	view := suite.v

	view.checkTimeouts()
	assert.Zero(suite.T(), len(view.timeoutMap), "Does not alter state when there are no timeouts.")

	accused := &Peer{
		Id: ("testAccused"),
	}

	accuser := &Peer{
		Id: "testAccuser",
	}

	note := &Note{
		id: accused.Id,
	}

	// 100.0 seconds
	view.removalTimeout = 100.0

	t := &timeout{
		accused:   accused,
		observer:  accuser,
		lastNote:  note,
		timeStamp: time.Now(),
	}

	view.timeoutMap[accused.Id] = t

	view.checkTimeouts()
	require.Equal(suite.T(), 1, len(view.timeoutMap), "Timeout removed before expiration.")

	_, ok := view.timeoutMap[accused.Id]
	require.True(suite.T(), ok, "Timeout removed from map before expiration.")

	// 10 years in the past
	t.timeStamp = t.timeStamp.AddDate(-10, 0, 0)

	view.checkTimeouts()
	require.Zero(suite.T(), len(view.timeoutMap), "Timeout not removed after expiration.")

	_, ok = view.timeoutMap[accused.Id]
	require.False(suite.T(), ok, "Timeout not removed from map after expiration.")
}

func (suite *ViewTestSuite) TestShouldRebuttal() {
	view := suite.v

	currentEpoch := view.self.note.epoch

	var accuseRing uint32 = 1

	assert.False(suite.T(), view.ShouldRebuttal(currentEpoch+1, accuseRing), "Should return false with invalid epoch.")

	assert.False(suite.T(), view.ShouldRebuttal(currentEpoch-1, accuseRing), "Should return false with invalid epoch.")

	prevNote := view.self.note

	assert.True(suite.T(), view.ShouldRebuttal(currentEpoch, accuseRing), "Should return false with invalid epoch.")

	assert.NotEqual(suite.T(), prevNote, view.self.note, "Old note not replaced.")
	assert.True(suite.T(), view.self.note.IsRingDisabled(accuseRing, view.NumRings()),
		"Ring not deactivated in mask.")
	assert.True(suite.T(), view.ValidMask(view.self.note.mask), "Mask is not valid after disabling.")
}

func (suite *ViewTestSuite) TestShouldBeNeighbour() {
	view := suite.v

	assert.True(suite.T(), view.ShouldBeNeighbour("testId"), "Should be neighbours with everyone when alone.")
}

func (suite *ViewTestSuite) TestFindNeighbours() {
	view := suite.v

	neighbours := view.FindNeighbours("testId")
	require.NotNil(suite.T(), neighbours, "Should never return nil.")
	require.Equal(suite.T(), 1, len(neighbours), "Should only return myself when alone.")
	assert.Equal(suite.T(), view.self, neighbours[0], "Did not return myself as neighbour.")

	for i := 0; i < 10; i++ {
		p := &Peer{
			Id: fmt.Sprintf("testId%d", i),
		}

		view.AddLive(p)

		n := view.FindNeighbours(p.Id)
		require.NotNil(suite.T(), n, "Should never return nil.")

		if i == 0 {
			require.Equal(suite.T(), 1, len(n), "Should only return myself when we are 2 in live view.")
		} else {
			require.True(suite.T(), len(n) >= 2, "Should always have 2 or more neighbours when there are more than 2 in the live view.")
		}
	}
}

func (suite *ViewTestSuite) TestValidAccuser() {
	view := suite.v

	p := &Peer{
		Id: "testId",
	}

	view.AddLive(p)

	assert.False(suite.T(), view.ValidAccuser(p, view.self, view.rings.numRings+1),
		"Should return false with invalid ring number.")

	assert.True(suite.T(), view.ValidAccuser(p, view.self, view.rings.numRings),
		"Should return true with valid parameters.")

}

func (suite *ViewTestSuite) TestIsAlive() {
	view := suite.v

	assert.False(suite.T(), view.IsAliveId("non-existing-id"), "Non-existing id should return false.")
	assert.False(suite.T(), view.IsAlive(nil), "Nil peer should return false.")
	assert.False(suite.T(), view.IsAlive(&Peer{Id: "non-existing-id"}), "Non-existing peer should return false.")

	p := &Peer{
		Id: "testId",
	}

	view.AddTestLivePeer(p)

	assert.True(suite.T(), view.IsAlive(p), "Existing peer should return true.")
	assert.True(suite.T(), view.IsAliveId(p.Id), "Id of live peer should return true.")
}

func (suite *ViewTestSuite) TestIncrementGossipRing() {
	var i uint32
	view := suite.v

	require.Equal(suite.T(), uint32(1), view.currGossipRing, "Should start at 1.")

	for i = 1; i <= view.rings.numRings; i++ {
		view.incrementGossipRing()

		if i == view.rings.numRings {
			require.Equal(suite.T(), uint32(1), view.currGossipRing, "Wrap around not working.")
		} else {
			require.Equal(suite.T(), i+1, view.currGossipRing, "Gossip ring not incremented.")
		}
	}
}

func (suite *ViewTestSuite) TestIncrementMonitorRing() {
	var i uint32
	view := suite.v

	require.Equal(suite.T(), uint32(1), view.currMonitorRing, "Should start at 1.")

	for i = 1; i <= view.rings.numRings; i++ {
		view.incrementMonitorRing()

		if i == view.rings.numRings {
			require.Equal(suite.T(), uint32(1), view.currMonitorRing, "Wrap around not working.")
		} else {
			require.Equal(suite.T(), i+1, view.currMonitorRing,
				"Monitor ring not incremented.")
		}
	}
}

func (suite *ViewTestSuite) TestSelfNote() {
	view := suite.v

	localNote := view.self.note

	note := view.selfNote()
	require.NotNil(suite.T(), note, "Should never be nil.")

	assert.Equal(suite.T(), localNote.epoch, note.GetEpoch(), "Not equal epochs.")

	assert.Equal(suite.T(), localNote.epoch, note.GetEpoch(), "Not equal epochs.")
	assert.Equal(suite.T(), localNote.id, string(note.GetId()), "Not equal ids.")
	assert.Equal(suite.T(), localNote.mask, note.GetMask(), "Not equal masks.")
	assert.Equal(suite.T(), localNote.signature.r, note.GetSignature().GetR(), "Not equal signature component r.")
	assert.Equal(suite.T(), localNote.signature.s, note.GetSignature().GetS(), "Not equal signature component s.")
}

func (suite *ViewTestSuite) TestState() {
	view := suite.v

	emptyState := view.State()
	require.NotNil(suite.T(), emptyState, "Should never be nil.")

	hosts := emptyState.GetExistingHosts()
	note := emptyState.GetOwnNote()

	require.NotNil(suite.T(), hosts, "Should never be nil.")
	require.NotNil(suite.T(), note, "Should never be nil.")

	require.Zero(suite.T(), len(hosts), "Should be no hosts when alone.")

	for i := 0; i < 20; i++ {
		p := &Peer{
			Id: fmt.Sprintf("testId%d", i),
		}

		hasNote := false

		if i%2 == 0 {
			hasNote = true
			p.note = &Note{
				id:    p.Id,
				epoch: 1,
			}
		}

		view.AddTestPeer(p)

		s := view.State()

		hosts := s.GetExistingHosts()
		note := s.GetOwnNote()
		require.NotNil(suite.T(), hosts, "Should never be nil.")
		require.NotNil(suite.T(), note, "Should never be nil.")

		require.Equal(suite.T(), i+1, len(hosts), "Peers not added to state message.")

		epoch, ok := hosts[hex.EncodeToString([]byte(p.Id))]
		require.True(suite.T(), ok, "Peer not added to state message.")

		if hasNote {
			require.Equal(suite.T(), uint64(1), epoch, "Wrong epoch added.")
		} else {
			require.Zero(suite.T(), epoch, "Epoch not set to zero with no note.")
		}
	}
}

func (suite *ViewTestSuite) TestValidMask() {
	view := suite.v

	assert.True(suite.T(), view.ValidMask(view.self.note.mask), "Returned false with valid mask.")

	assert.False(suite.T(), view.ValidMask(view.self.note.mask+1), "Returned true with invalid mask.")
}

func (suite *ViewTestSuite) TestIsRingDisabled() {
	var i, disableIdx uint32

	view := suite.v

	for i = 1; i <= view.rings.numRings; i++ {
		require.False(suite.T(), view.self.note.IsRingDisabled(i, view.NumRings()),
			"Returned true on an active ring.")
	}

	disableIdx = 0

	view.self.note.mask = clearBit(view.self.note.mask, disableIdx)

	assert.True(suite.T(), view.self.note.IsRingDisabled(disableIdx+1, view.NumRings()), "Returned false on a disabled ring.")
}

func (suite *ViewTestSuite) TestDeactivateRing() {
	var i, j, deactivated, ringNum uint32

	view := suite.v

	_, err := view.deactivateRing(view.rings.numRings + 1)
	require.EqualError(suite.T(), err, errNonExistingRing.Error(), "Should fail with invalid ring number.")

	ringNum = 1
	view.self.note.mask = clearBit(view.self.note.mask, ringNum)
	_, err = view.deactivateRing(ringNum + 1)
	require.EqualError(suite.T(), err, errAlreadyDeactivated.Error(), "Should fail when deactivating an already deactivated ring.")

	require.Equal(suite.T(), uint32(0), view.deactivatedRings, "Should start at 0.")
	view.self.note.mask = setBit(view.self.note.mask, ringNum)

	mask := view.self.note.mask
	for i = 1; i <= view.rings.numRings; i++ {
		mask, err = view.deactivateRing(i)
		require.NoError(suite.T(), err, "Valid disables should not fail.")

		if i > view.maxByz {
			require.Equal(suite.T(), view.maxByz, view.deactivatedRings, "Deactivated rings not equal to maxbyz.")
			require.False(suite.T(), hasBit(mask, i-1), "Bit not deactivated.")

			deactivated = 0
			for j = 0; j < view.rings.numRings; j++ {
				if !hasBit(mask, j) {
					deactivated++
				}
			}

			require.Equal(suite.T(), view.deactivatedRings, deactivated, "Deactivated counter does not reflect actual value.")
			require.True(suite.T(), deactivated <= view.maxByz, "Deactivated too many rings.")

		} else {
			require.Equal(suite.T(), i, view.deactivatedRings, "Deactivated rings not incremented.")
			require.False(suite.T(), hasBit(mask, i-1), "Bit not deactivated.")
		}
		view.self.note.mask = mask
	}

	// Reset before maxByz zero test
	for i = 0; i < view.rings.numRings; i++ {
		view.self.note.mask = setBit(view.self.note.mask, i)
	}
	view.deactivatedRings = 0

	view.maxByz = 0

	_, err = view.deactivateRing(0)
	assert.EqualError(suite.T(), err, errZeroDeactivate.Error(), "Should fail with maxbyz set to zero.")
}

func (suite *ViewTestSuite) TestValidMaskInternal() {
	var i uint32

	mask := suite.v.self.note.mask
	numRings := suite.v.rings.numRings
	maxByz := suite.v.maxByz

	assert.NoError(suite.T(), validMask(mask, numRings, maxByz),
		"Should not fail with valid mask.")
	assert.Error(suite.T(), validMask(0, numRings, maxByz),
		"Should always fail with mask set to zero.")

	for i = 0; i < numRings; i++ {
		mask = clearBit(mask, i)
		if i >= maxByz {
			require.Error(suite.T(), validMask(mask, numRings, maxByz),
				"Should fail with too many deactivations.")
		} else {
			require.NoError(suite.T(), validMask(mask, numRings, maxByz),
				"Should not fail with valid amounts of deactivations.")
		}
	}
}

func (suite *ViewTestSuite) TestSetBit() {
	var mask, i uint32

	for i = 0; i < 32; i++ {
		mask = setBit(mask, i)
		require.True(suite.T(), hasBit(mask, i), "Should return true on set bit.")
	}

}

func (suite *ViewTestSuite) TestClearBit() {
	var i uint32

	mask := suite.v.self.note.mask

	for i = 0; i < 32; i++ {
		mask = clearBit(mask, i)
		require.False(suite.T(), hasBit(mask, i), "Should return false on cleared bit.")
	}
}

func (suite *ViewTestSuite) TestHasBit() {
	var mask, i uint32

	for i = 0; i < 32; i++ {
		mask = setBit(mask, i)
		require.True(suite.T(), hasBit(mask, i), "Should return true on set bit.")
	}
}

func (suite *ViewTestSuite) TestRemovalTimeoutConfiguration() {
	defer viper.Reset()

	privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(suite.T(), err)
	cert := validCert("timeoutPeer", privKey.Public())

	// 1. Default when unset should be 60.0 and 10s interval
	viper.Reset()
	vDefault, err := NewView(10, cert, &cmStub{}, &signerStub{})
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), 60.0, vDefault.removalTimeout)
	assert.Equal(suite.T(), 10*time.Second, vDefault.updateTimeout)

	// 2. Configured removal_timeout
	viper.Reset()
	viper.Set("removal_timeout", 45.0)
	viper.Set("view_update_interval", 15)
	vRemoval, err := NewView(10, cert, &cmStub{}, &signerStub{})
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), 45.0, vRemoval.removalTimeout)
	assert.Equal(suite.T(), 15*time.Second, vRemoval.updateTimeout)
}

func (suite *ViewTestSuite) TestCheckTimeoutsSuspicionWindow() {
	// Ensure default removalTimeout is in effect
	require.Equal(suite.T(), 60.0, suite.v.removalTimeout)

	accused := &Peer{
		Id:   "accusedPeer",
		Addr: "accusedAddr",
	}
	suite.v.AddTestLivePeer(accused)

	accuser := &Peer{
		Id: "accuserPeer",
	}

	note := &Note{
		id: accused.Id,
	}

	// Recent accusation (within the 60-second window)
	suite.v.timeoutMap[accused.Id] = &timeout{
		accused:   accused,
		observer:  accuser,
		lastNote:  note,
		timeStamp: time.Now(),
	}

	// First tick should NOT evict the peer
	suite.v.checkTimeouts()
	assert.Contains(suite.T(), suite.v.timeoutMap, accused.Id, "Peer should not be evicted immediately on tick")
	assert.True(suite.T(), suite.v.IsAlive(accused), "Peer should remain in liveStore during suspicion window")

	// Expire timeout by setting timestamp past 60s
	suite.v.timeoutMap[accused.Id].timeStamp = time.Now().Add(-65 * time.Second)
	suite.v.checkTimeouts()
	assert.NotContains(suite.T(), suite.v.timeoutMap, accused.Id, "Peer should be evicted after removal_timeout expires")
	assert.False(suite.T(), suite.v.IsAlive(accused), "Peer should be removed from liveStore after timeout")
}

func (suite *ViewTestSuite) TestLiveSubsetOfView() {
	view := suite.v

	// Initially empty: subset should hold
	assert.True(suite.T(), view.LiveSubsetOfView(), "Empty live store should be subset of view")

	p1 := &Peer{Id: "peer1"}
	p2 := &Peer{Id: "peer2"}

	// Admitted to full view
	view.AddTestPeer(p1)
	view.AddTestPeer(p2)
	assert.True(suite.T(), view.LiveSubsetOfView())

	// p1 becomes live
	view.AddTestLivePeer(p1)
	assert.True(suite.T(), view.LiveSubsetOfView(), "p1 is in both live and view")

	// rogue peer only in live
	rogue := &Peer{Id: "rogue"}
	view.AddTestLivePeer(rogue)
	assert.False(suite.T(), view.LiveSubsetOfView(), "rogue peer is live but not in full view")

	// remove rogue peer
	view.LiveStore().Remove(rogue)
	assert.True(suite.T(), view.LiveSubsetOfView(), "subset holds after rogue peer removed")
}

func validCert(id string, pub crypto.PublicKey) *x509.Certificate {
	return &x509.Certificate{
		SubjectKeyId: []byte(id),
		Subject: pkix.Name{
			Locality: []string{"rpcAddr", "pingAddr", "httpAddr"},
		},
		PublicKey: pub,
	}
}

type cmStub struct {
}

func (cm *cmStub) CloseConn(addr string) {

}

type signerStub struct {
}

func (s *signerStub) Sign(data []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}

type mockSigner struct {
	priv *ecdsa.PrivateKey
}

func (m *mockSigner) Sign(data []byte) ([]byte, []byte, error) {
	if m.priv != nil {
		h := sha256.Sum256(data)
		r, s, err := ecdsa.Sign(rand.Reader, m.priv, h[:])
		if err != nil {
			return nil, nil, err
		}
		return r.Bytes(), s.Bytes(), nil
	}
	return []byte("dummy-r"), []byte("dummy-s"), nil
}

func (suite *ViewTestSuite) TestViewCreateAccusation() {
	signer := &mockSigner{}
	peerId := "accusedPeer"
	peer := &Peer{Id: peerId, Addr: "127.0.0.1:1000"}
	note := &Note{id: peerId, epoch: 5}

	// Successful creation
	err := suite.v.CreateAccusation(peer, note, 1, signer)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), suite.v.HasAccusation(peerId, suite.v.self.Id, 1, 5))
	assert.NotNil(suite.T(), suite.v.Accusation(peerId, suite.v.self.Id, 1, 5))

	// Duplicate creation returns ErrAccAlreadyExists
	err = suite.v.CreateAccusation(peer, note, 1, signer)
	assert.Equal(suite.T(), ErrAccAlreadyExists, err)

	// Invalid ring returns errInvalidRing
	err = suite.v.CreateAccusation(peer, note, 0, signer)
	assert.Equal(suite.T(), errInvalidRing, err)

	err = suite.v.CreateAccusation(peer, note, suite.v.NumRings()+1, signer)
	assert.Equal(suite.T(), errInvalidRing, err)
}

func (suite *ViewTestSuite) TestViewAddAccusation() {
	peerId := "remoteAccused"
	accuserId := "remoteAccuser"

	// Missing signatures
	err := suite.v.AddAccusation(peerId, accuserId, 1, 1, nil, []byte("s"))
	assert.Equal(suite.T(), errAccuserSign, err)

	err = suite.v.AddAccusation(peerId, accuserId, 1, 1, []byte("r"), nil)
	assert.Equal(suite.T(), errAccuserSign, err)

	// Missing IDs
	err = suite.v.AddAccusation("", accuserId, 1, 1, []byte("r"), []byte("s"))
	assert.Equal(suite.T(), errAccusedId, err)

	err = suite.v.AddAccusation(peerId, "", 1, 1, []byte("r"), []byte("s"))
	assert.Equal(suite.T(), errAccuserId, err)

	// Invalid ring
	err = suite.v.AddAccusation(peerId, accuserId, 1, 0, []byte("r"), []byte("s"))
	assert.Equal(suite.T(), errInvalidRing, err)

	// Valid addition
	err = suite.v.AddAccusation(peerId, accuserId, 2, 2, []byte("r"), []byte("s"))
	require.NoError(suite.T(), err)
	assert.True(suite.T(), suite.v.HasAccusation(peerId, accuserId, 2, 2))
}

func (suite *ViewTestSuite) TestViewAccusationActiveAndRebuttal() {
	peerId := "rebuttalPeer"
	peer := &Peer{
		Id:   peerId,
		Addr: "127.0.0.1:1001",
		note: &Note{id: peerId, epoch: 2},
	}
	suite.v.AddTestPeer(peer)

	// Peer currently has note epoch 2
	assert.False(suite.T(), suite.v.IsAccused(peer))

	// Add accusation matching epoch 2
	err := suite.v.AddAccusation(peerId, "accuser1", 2, 1, []byte("r"), []byte("s"))
	require.NoError(suite.T(), err)

	// Accusation is active because acc.epoch (2) >= peer.note.epoch (2)
	assert.True(suite.T(), suite.v.IsAccused(peer))
	assert.Len(suite.T(), suite.v.ActiveAccusationsForPeer(peer), 1)
	assert.Equal(suite.T(), uint64(2), suite.v.RingAccusation(peerId, 1).Epoch())

	// Peer rebuts by issuing note epoch 3
	peer.note = &Note{id: peerId, epoch: 3}

	// Under grow-only model, accusation at epoch 2 is NEVER deleted,
	// but IsAccused becomes false because acc.epoch (2) < peer.note.epoch (3)
	assert.False(suite.T(), suite.v.IsAccused(peer))
	assert.Empty(suite.T(), suite.v.ActiveAccusationsForPeer(peer))
	assert.Len(suite.T(), suite.v.AccusationsForPeer(peerId), 1) // still in store!

	// Peer fails again at epoch 3, new accusation arrives
	err = suite.v.AddAccusation(peerId, "accuser1", 3, 1, []byte("r3"), []byte("s3"))
	require.NoError(suite.T(), err)

	// Both epoch 2 and epoch 3 exist in the grow-only store
	assert.Len(suite.T(), suite.v.AccusationsForPeer(peerId), 2)
	assert.True(suite.T(), suite.v.IsAccused(peer))
	assert.Len(suite.T(), suite.v.ActiveAccusationsForPeer(peer), 1)
	assert.Equal(suite.T(), uint64(3), suite.v.RingAccusation(peerId, 1).Epoch())
}

func (suite *ViewTestSuite) TestViewActiveAccusationsMultiRingAndRebuttalPruning() {
	peerId := "multiRingPeer"
	peer := &Peer{
		Id:   peerId,
		Addr: "127.0.0.1:2001",
		note: &Note{id: peerId, epoch: 1},
	}
	suite.v.AddTestPeer(peer)

	// Initially not accused
	assert.False(suite.T(), suite.v.IsAccused(peer))
	assert.Empty(suite.T(), suite.v.ActiveAccusationsForPeer(peer))

	// Accuse on Ring 1 and Ring 2 at epoch 1
	err := suite.v.AddAccusation(peerId, "accuser-ring1", 1, 1, []byte("r1"), []byte("s1"))
	require.NoError(suite.T(), err)
	err = suite.v.AddAccusation(peerId, "accuser-ring2", 1, 2, []byte("r2"), []byte("s2"))
	require.NoError(suite.T(), err)

	// Both rings active
	assert.True(suite.T(), suite.v.IsAccused(peer))
	activeAccs := suite.v.ActiveAccusationsForPeer(peer)
	assert.Len(suite.T(), activeAccs, 2)
	assert.NotNil(suite.T(), suite.v.RingAccusation(peerId, 1))
	assert.NotNil(suite.T(), suite.v.RingAccusation(peerId, 2))
	assert.Nil(suite.T(), suite.v.RingAccusation(peerId, 3))

	// Peer rebuts with new note via AddNote at epoch 2
	applied, err := suite.v.AddNote(peer, 1, 2, []byte("r_reb"), []byte("s_reb"))
	require.NoError(suite.T(), err)
	assert.True(suite.T(), applied)

	// Rebuttal prunes all epoch 1 accusations from active index
	assert.False(suite.T(), suite.v.IsAccused(peer))
	assert.Empty(suite.T(), suite.v.ActiveAccusationsForPeer(peer))
	assert.Nil(suite.T(), suite.v.RingAccusation(peerId, 1))
	assert.Nil(suite.T(), suite.v.RingAccusation(peerId, 2))

	// Historical store retains both epoch 1 accusations
	assert.Len(suite.T(), suite.v.AccusationsForPeer(peerId), 2)

	// New accusation arrives targeting epoch 2 on Ring 2
	err = suite.v.AddAccusation(peerId, "accuser-ring2", 2, 2, []byte("r_new"), []byte("s_new"))
	require.NoError(suite.T(), err)

	// Now only Ring 2 is active at epoch 2
	assert.True(suite.T(), suite.v.IsAccused(peer))
	activeNow := suite.v.ActiveAccusationsForPeer(peer)
	require.Len(suite.T(), activeNow, 1)
	assert.Equal(suite.T(), uint32(2), activeNow[0].RingNum())
	assert.Equal(suite.T(), uint64(2), activeNow[0].Epoch())
	assert.Nil(suite.T(), suite.v.RingAccusation(peerId, 1))
	assert.NotNil(suite.T(), suite.v.RingAccusation(peerId, 2))

	// Historical store has all 3 accusations
	assert.Len(suite.T(), suite.v.AccusationsForPeer(peerId), 3)
}

func (suite *ViewTestSuite) TestViewAccusationFingerprintAndCompare() {
	v1 := suite.v
	privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(suite.T(), err)
	cert := validCert("otherSelf", privKey.Public())
	v2, err := NewView(10, cert, &cmStub{}, &signerStub{})
	require.NoError(suite.T(), err)

	// Both start with empty accusation stores -> fingerprint 0
	assert.Equal(suite.T(), revIdxStore.DigestSymbol(0), v1.AccusationFingerprint())
	assert.Equal(suite.T(), revIdxStore.DigestSymbol(0), v2.AccusationFingerprint())

	// Add accusation to v1
	err = v1.AddAccusation("peerX", "peerY", 1, 1, []byte("r"), []byte("s"))
	require.NoError(suite.T(), err)
	fp1 := v1.AccusationFingerprint()
	assert.NotEqual(suite.T(), revIdxStore.DigestSymbol(0), fp1)

	// Add same accusation to v2
	err = v2.AddAccusation("peerX", "peerY", 1, 1, []byte("r"), []byte("s"))
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), fp1, v2.AccusationFingerprint())
}

func (suite *ViewTestSuite) TestViewNotesVersionVectorFingerprintAndMonotonicity() {
	v := suite.v
	initialFP, err := v.Fingerprint()
	require.NoError(suite.T(), err)
	assert.NotEqual(suite.T(), revIdxStore.DigestSymbol(0), initialFP, "Initial fingerprint must include self note")

	// Create a test peer
	p := &Peer{Id: "test-peer-1"}
	applied, err := v.AddNote(p, 1, 1, []byte("r1"), []byte("s1"))
	require.NoError(suite.T(), err)
	assert.True(suite.T(), applied)

	fpAfterNote1, err := v.Fingerprint()
	require.NoError(suite.T(), err)
	assert.NotEqual(suite.T(), initialFP, fpAfterNote1, "Adding a note must alter view fingerprint")

	// Adding older or equal epoch must be rejected and preserve fingerprint
	appliedStale, err := v.AddNote(p, 1, 1, []byte("r1"), []byte("s1"))
	require.NoError(suite.T(), err)
	assert.False(suite.T(), appliedStale, "Equal epoch note must be rejected")
	fpDuplicate, err := v.Fingerprint()
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), fpAfterNote1, fpDuplicate, "Fingerprint must not change on duplicate note")

	// Adding newer epoch (rebuttal) must advance version vector and alter fingerprint
	appliedNewer, err := v.AddNote(p, 1, 2, []byte("r2"), []byte("s2"))
	require.NoError(suite.T(), err)
	assert.True(suite.T(), appliedNewer, "Higher epoch note must be accepted")
	fpAfterNote2, err := v.Fingerprint()
	require.NoError(suite.T(), err)
	assert.NotEqual(suite.T(), fpAfterNote1, fpAfterNote2, "Rebuttal epoch must alter view fingerprint")

	// Verify retrieval from VersionVector
	key := v.hashId("test-peer-1")
	notesVV, err := v.Notes()
	require.NoError(suite.T(), err)
	note, found := notesVV.GetByDigest(key)
	assert.True(suite.T(), found)
	assert.Equal(suite.T(), uint64(2), note.Epoch())

	// Test NoteByDigest and NotesByDigests
	singleNote, foundSingle, err := v.NoteByDigest(key)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), foundSingle)
	assert.NotNil(suite.T(), singleNote)

	batchNotes, allFound, err := v.NotesByDigests([]revIdxStore.DigestSymbol{key})
	require.NoError(suite.T(), err)
	assert.True(suite.T(), allFound)
	assert.Len(suite.T(), batchNotes, 1)

	// Test uninitialized view errors
	uninitV := &View{}
	_, err = uninitV.Fingerprint()
	assert.Equal(suite.T(), ErrNotesNotInitialized, err)

	_, err = uninitV.Notes()
	assert.Equal(suite.T(), ErrNotesNotInitialized, err)

	_, err = uninitV.NoteDigests()
	assert.Equal(suite.T(), ErrNotesNotInitialized, err)

	_, _, err = uninitV.NoteByDigest(123)
	assert.Equal(suite.T(), ErrNotesNotInitialized, err)

	_, _, err = uninitV.NotesByDigests([]revIdxStore.DigestSymbol{123})
	assert.Equal(suite.T(), ErrNotesNotInitialized, err)

	_, err = uninitV.AddNote(p, 1, 1, []byte("r"), []byte("s"))
	assert.Equal(suite.T(), ErrNotesNotInitialized, err)

	err = uninitV.RemoveTestFull("test")
	assert.Equal(suite.T(), ErrNotesNotInitialized, err)
}
