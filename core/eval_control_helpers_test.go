package core

import (
	"math"

	"github.com/stretchr/testify/require"

	"github.com/joonnna/ifrit/core/discovery"
	proto "github.com/joonnna/ifrit/protobuf"
)

func (suite *HandlerTestSuite) TestMergeNotes() {
	node := suite.n
	p := node.view.Live()[0]
	priv := suite.privMap[p.Id]

	initialFp := node.view.NoteStore().Fingerprint()

	// 1. Valid Note (higher epoch)
	validPb := discovery.NewNote(p.Id, 2, math.MaxUint32, priv)
	node.mergeNotes([]*proto.Note{validPb})

	rawValid := discovery.NoteFromPb(validPb)
	stored, found := node.view.NoteStore().Contains(rawValid)
	require.True(suite.T(), found, "Valid note must be present in NoteStore")
	require.Equal(suite.T(), rawValid.Epoch(), stored.Epoch())
	activeNote, found := node.view.ActiveNote(p.Id)
	require.True(suite.T(), found)
	require.Equal(suite.T(), uint64(2), activeNote.Epoch(), "Valid note must update peer active note")
	fpAfterValid := node.view.NoteStore().Fingerprint()
	require.NotEqual(suite.T(), initialFp, fpAfterValid)

	// 2. Note with invalid signature: MUST be stored in NoteStore, but peer active note MUST NOT update
	badSigPb := discovery.NewNote(p.Id, 3, math.MaxUint32, priv)
	badSigPb.Signature = &proto.Signature{R: []byte("tampered_r"), S: []byte("tampered_s")}
	node.mergeNotes([]*proto.Note{badSigPb})

	rawBadSig := discovery.NoteFromPb(badSigPb)
	_, found = node.view.NoteStore().Contains(rawBadSig)
	require.True(suite.T(), found, "Note with invalid signature MUST be ingested into NoteStore")
	activeNote, found = node.view.ActiveNote(p.Id)
	require.True(suite.T(), found)
	require.Equal(suite.T(), uint64(2), activeNote.Epoch(), "Invalid signature note must NOT update active peer note")

	// 3. Note from completely unknown peer: MUST be stored in NoteStore
	unknownPb := discovery.NewNote("unknown-peer-id-999", 5, math.MaxUint32, priv)
	node.mergeNotes([]*proto.Note{unknownPb})

	rawUnknown := discovery.NoteFromPb(unknownPb)
	_, found = node.view.NoteStore().Contains(rawUnknown)
	require.True(suite.T(), found, "Note from unknown peer MUST be ingested into NoteStore")

	// 4. Note with invalid mask (violates Byzantine threshold): MUST be stored in NoteStore
	badMaskPb := discovery.NewNote(p.Id, 4, 0, priv)
	node.mergeNotes([]*proto.Note{badMaskPb})

	rawBadMask := discovery.NoteFromPb(badMaskPb)
	_, found = node.view.NoteStore().Contains(rawBadMask)
	require.True(suite.T(), found, "Note with invalid mask MUST be ingested into NoteStore")

	// 5. Stale / Older epoch note: MUST be stored in NoteStore
	stalePb := discovery.NewNote(p.Id, 1, math.MaxUint32, priv)
	node.mergeNotes([]*proto.Note{stalePb})

	rawStale := discovery.NoteFromPb(stalePb)
	_, found = node.view.NoteStore().Contains(rawStale)
	require.True(suite.T(), found, "Stale epoch note MUST be ingested into NoteStore")

	// 6. Malformed note without signature: MUST be stored in NoteStore
	unsignedPb := &proto.Note{
		Id:    []byte("malformed-node"),
		Epoch: 100,
		Mask:  1,
	}
	node.mergeNotes([]*proto.Note{unsignedPb})

	rawUnsigned := discovery.NoteFromPb(unsignedPb)
	_, found = node.view.NoteStore().Contains(rawUnsigned)
	require.True(suite.T(), found, "Unsigned/corrupt note MUST be ingested into NoteStore")

	// 7. Idempotence: Duplicate note insertion preserves NoteStore fingerprint
	fpBeforeDup := node.view.NoteStore().Fingerprint()
	node.mergeNotes([]*proto.Note{unsignedPb})
	require.Equal(suite.T(), fpBeforeDup, node.view.NoteStore().Fingerprint(), "Duplicate note must preserve XOR fingerprint")
}

func (suite *HandlerTestSuite) TestMergeAccusations() {
	node := suite.n
	p := node.view.Live()[0]
	succ, prev := node.view.MyRingNeighbours(1)
	priv := suite.privMap[prev.Id]

	initialFp := node.view.AccusationStore().Fingerprint()

	succNote, found := node.view.ActiveNote(succ.Id)
	require.True(suite.T(), found)
	pNote, found := node.view.ActiveNote(p.Id)
	require.True(suite.T(), found)

	// 1. Valid Accusation
	validAccPb := discovery.NewAccusation(succNote.Epoch(), succ.Id, prev.Id, 1, priv)
	node.mergeAccusations([]*proto.Accusation{validAccPb})

	rawValid := discovery.AccusationFromPb(validAccPb)
	stored, found := node.view.AccusationStore().Contains(rawValid)
	require.True(suite.T(), found, "Valid accusation must be stored in AccusationStore")
	require.Equal(suite.T(), rawValid.Epoch(), stored.Epoch())
	fpAfterValid := node.view.AccusationStore().Fingerprint()
	require.NotEqual(suite.T(), initialFp, fpAfterValid)

	// 2. Accusation with invalid signature: MUST be ingested into AccusationStore
	badSigAccPb := discovery.NewAccusation(succNote.Epoch(), succ.Id, prev.Id, 1, priv)
	badSigAccPb.Signature = &proto.Signature{R: []byte("tampered_r"), S: []byte("tampered_s")}
	node.mergeAccusations([]*proto.Accusation{badSigAccPb})

	rawBadSig := discovery.AccusationFromPb(badSigAccPb)
	_, found = node.view.AccusationStore().Contains(rawBadSig)
	require.True(suite.T(), found, "Accusation with invalid signature MUST be ingested into AccusationStore")

	// 3. Accusation targeting unknown peer: MUST be ingested into AccusationStore
	unknownAccPb := discovery.NewAccusation(1, "unknown-accused", prev.Id, 1, priv)
	node.mergeAccusations([]*proto.Accusation{unknownAccPb})

	rawUnknown := discovery.AccusationFromPb(unknownAccPb)
	_, found = node.view.AccusationStore().Contains(rawUnknown)
	require.True(suite.T(), found, "Accusation targeting unknown peer MUST be ingested into AccusationStore")

	// 4. Accusation from unknown accuser: MUST be ingested into AccusationStore
	unknownAccuserPb := discovery.NewAccusation(pNote.Epoch(), p.Id, "unknown-accuser", 1, priv)
	node.mergeAccusations([]*proto.Accusation{unknownAccuserPb})

	rawUnknownAccuser := discovery.AccusationFromPb(unknownAccuserPb)
	_, found = node.view.AccusationStore().Contains(rawUnknownAccuser)
	require.True(suite.T(), found, "Accusation from unknown accuser MUST be ingested into AccusationStore")

	// 5. Accusation targeting mismatched epoch: MUST be ingested into AccusationStore
	mismatchedEpochPb := discovery.NewAccusation(9999, succ.Id, prev.Id, 1, priv)
	node.mergeAccusations([]*proto.Accusation{mismatchedEpochPb})

	rawMismatched := discovery.AccusationFromPb(mismatchedEpochPb)
	_, found = node.view.AccusationStore().Contains(rawMismatched)
	require.True(suite.T(), found, "Accusation targeting mismatched epoch MUST be ingested into AccusationStore")

	// 6. Malformed accusation without signature: MUST be ingested into AccusationStore
	unsignedAccPb := &proto.Accusation{
		Accused: []byte("malformed-accused"),
		Accuser: []byte("malformed-accuser"),
		RingNum: 1,
		Epoch:   10,
	}
	node.mergeAccusations([]*proto.Accusation{unsignedAccPb})

	rawUnsigned := discovery.AccusationFromPb(unsignedAccPb)
	_, found = node.view.AccusationStore().Contains(rawUnsigned)
	require.True(suite.T(), found, "Unsigned/corrupt accusation MUST be ingested into AccusationStore")

	// 7. Idempotence: Duplicate accusation preserves AccusationStore fingerprint
	fpBeforeDup := node.view.AccusationStore().Fingerprint()
	node.mergeAccusations([]*proto.Accusation{unsignedAccPb})
	require.Equal(suite.T(), fpBeforeDup, node.view.AccusationStore().Fingerprint(), "Duplicate accusation must preserve XOR fingerprint")
}

func (suite *HandlerTestSuite) TestMergeCertificates() {

}

func (suite *HandlerTestSuite) TestEvalAccusation() {
	var ringNum uint32 = 1
	var randomPeer *discovery.Peer

	node := suite.n

	succ, prev := node.view.MyRingNeighbours(ringNum)

	for _, p := range node.view.Live() {
		if p.Id != succ.Id && p.Id != prev.Id {
			randomPeer = p
			break
		}
	}

	node.view.ClearTestNote(randomPeer)

	selfId := node.self.Id

	tests := []struct {
		acc     *proto.Accusation
		accuser *discovery.Peer
		accused *discovery.Peer
		out     error

		timer     bool
		rebuttal  bool
		prevNote  *discovery.Note
		isAccused bool
	}{
		{
			acc:       discovery.NewAccusation(1, selfId, succ.Id, 1, suite.privMap[succ.Id]),
			accuser:   succ,
			accused:   node.self,
			out:       errInvalidAccuser,
			timer:     false,
			rebuttal:  false,
			isAccused: false,
		},

		{
			acc:       discovery.NewUnsignedAccusation(1, selfId, prev.Id, 1),
			accuser:   prev,
			accused:   node.self,
			out:       errInvalidSignature,
			timer:     false,
			rebuttal:  false,
			isAccused: false,
		},

		{
			// Stale epoch (0 < current epoch 1) against self is invalid and should not trigger rebuttal.
			acc:       discovery.NewAccusation(0, selfId, prev.Id, 1, suite.privMap[prev.Id]),
			accuser:   prev,
			accused:   node.self,
			out:       errInvalidSelfAccusation,
			timer:     false,
			rebuttal:  false,
			isAccused: false,
		},

		{
			// Accusation matching current epoch (1) triggers rebuttal and advances epoch.
			acc: discovery.NewAccusation(1, selfId, prev.Id, 1,
				suite.privMap[prev.Id]),
			accuser:   prev,
			accused:   node.self,
			out:       nil,
			timer:     false,
			rebuttal:  true,
			prevNote:  node.view.SelfNote(),
			isAccused: false,
		},

		{
			// Catch-up: accusation with higher epoch (10 > current epoch 2, e.g. after restart)
			// should advance the local epoch beyond it (11) and trigger rebuttal.
			acc: discovery.NewAccusation(10, selfId, prev.Id, 1,
				suite.privMap[prev.Id]),
			accuser:   prev,
			accused:   node.self,
			out:       nil,
			timer:     false,
			rebuttal:  true,
			prevNote:  node.view.SelfNote(),
			isAccused: false,
		},

		{
			acc: discovery.NewAccusation(1, succ.Id, prev.Id, 1,
				suite.privMap[prev.Id]),
			accuser:   prev,
			accused:   succ,
			out:       errInvalidAccuser,
			timer:     false,
			rebuttal:  false,
			isAccused: false,
		},

		{
			acc:       discovery.NewAccusation(2, succ.Id, selfId, 1, suite.priv),
			accuser:   node.self,
			accused:   succ,
			out:       errInvalidEpoch,
			timer:     false,
			rebuttal:  false,
			isAccused: false,
		},

		{
			acc:       discovery.NewUnsignedAccusation(1, succ.Id, selfId, 1),
			accuser:   node.self,
			accused:   succ,
			out:       errInvalidSignature,
			timer:     false,
			rebuttal:  false,
			isAccused: false,
		},

		{
			acc:       discovery.NewAccusation(1, succ.Id, selfId, 1, suite.priv),
			accuser:   node.self,
			accused:   succ,
			out:       nil,
			timer:     true,
			rebuttal:  false,
			isAccused: true,
		},

		{
			acc:       discovery.NewAccusation(1, succ.Id, selfId, 1, suite.priv),
			accuser:   node.self,
			accused:   succ,
			out:       errAccAlreadyExists,
			timer:     true,
			rebuttal:  false,
			isAccused: true,
		},
	}

	for i, t := range tests {
		origSign := t.acc.GetSignature()
		require.Equalf(suite.T(), t.out, node.evalAccusation(t.acc, t.accuser, t.accused),
			"Invalid output for test %d.", i)
		if origSign != nil {
			require.NotNilf(suite.T(), t.acc.GetSignature(),
				"evalAccusation must restore accusation signature for test %d.", i)
		}

		if t.accused != nil {
			require.Equalf(suite.T(), t.timer, node.view.HasTimer(t.accused),
				"Invalid timer state for test %d.", i)

			require.Equalf(suite.T(), t.isAccused, node.view.IsAccused(t.accused),
				"Invalid accusation state for test %d.", i)
		}

		if t.rebuttal {
			require.NotEqualf(suite.T(), t.prevNote, node.view.SelfNote(),
				"Note not changed after rebuttal for test %d.", i)
		}

		node.view.DeleteTimeout(succ)
		node.view.DeleteTimeout(prev)
		node.view.DeleteTimeout(node.self)
		node.view.DeleteTimeout(randomPeer)
	}

}

func (suite *HandlerTestSuite) TestEvalNote() {
	node := suite.n

	mask := uint32(math.MaxUint32)

	live := node.view.Live()
	peer := live[0]
	peer2 := live[1]
	peer3 := live[2]

	node.view.ClearTestNote(peer2)

	acc := discovery.NewAccusation(2, peer3.Id, peer2.Id, 1, suite.privMap[peer2.Id])
	node.view.AddTestAccusation(acc)

	peer3Note, _ := node.view.ActiveNote(peer3.Id)
	err := node.view.StartTimer(peer3, peer3Note, peer2)
	require.NoError(suite.T(), err, "Failed to start timer.")

	peerNote, _ := node.view.ActiveNote(peer.Id)
	peer2Note, _ := node.view.ActiveNote(peer2.Id)

	tests := []struct {
		note *proto.Note
		out  error

		noteHolder  *discovery.Peer
		isAccused   bool
		isAlive     bool
		timer       bool
		replaceNote bool
		prevNote    *discovery.Note
	}{
		{
			note:        discovery.NewNote("Non-existing Id", 1, mask, suite.privMap[peer.Id]),
			out:         errNoPeer,
			noteHolder:  peer,
			isAccused:   false,
			isAlive:     false,
			timer:       false,
			replaceNote: false,
		},

		{
			note:        discovery.NewNote(peer.Id, 1, mask, suite.privMap[peer.Id]),
			out:         errOldNote,
			noteHolder:  peer,
			isAccused:   false,
			isAlive:     false,
			timer:       false,
			replaceNote: false,
		},

		{
			note:        discovery.NewNote(peer.Id, 2, 0, suite.privMap[peer.Id]),
			out:         errInvalidMask,
			noteHolder:  peer,
			isAccused:   false,
			isAlive:     false,
			timer:       false,
			replaceNote: false,
		},

		{
			note:        discovery.NewUnsignedNote(peer.Id, 2, mask),
			out:         errInvalidSignature,
			noteHolder:  peer,
			isAccused:   false,
			isAlive:     false,
			timer:       false,
			replaceNote: false,
		},

		{
			note:        discovery.NewNote(peer.Id, 2, mask, suite.privMap[peer.Id]),
			out:         nil,
			noteHolder:  peer,
			isAccused:   false,
			isAlive:     true,
			timer:       false,
			replaceNote: true,
			prevNote:    peerNote,
		},

		{
			note:        discovery.NewNote(peer2.Id, 1, mask, suite.privMap[peer2.Id]),
			out:         nil,
			noteHolder:  peer2,
			isAccused:   false,
			isAlive:     true,
			timer:       false,
			replaceNote: true,
			prevNote:    peer2Note,
		},

		{
			note:        discovery.NewUnsignedNote(peer3.Id, 2, mask),
			out:         errInvalidSignature,
			noteHolder:  peer3,
			isAccused:   true,
			isAlive:     false,
			timer:       true,
			replaceNote: false,
		},

		{
			note:        discovery.NewNote(peer3.Id, 2, mask, suite.privMap[peer3.Id]),
			out:         nil,
			noteHolder:  peer3,
			isAccused:   true,
			isAlive:     false,
			timer:       true,
			replaceNote: false,
		},

		{
			note:        discovery.NewNote(peer3.Id, 3, mask, suite.privMap[peer3.Id]),
			out:         nil,
			noteHolder:  peer3,
			isAccused:   false,
			isAlive:     true,
			timer:       false,
			replaceNote: true,
			prevNote:    peer3Note,
		},
	}

	for i, t := range tests {
		node.view.RemoveLive(peer)
		node.view.RemoveLive(peer2)
		node.view.RemoveLive(peer3)

		origSign := t.note.GetSignature()
		require.Equalf(suite.T(), t.out, node.evalNote(t.note),
			"Invalid output for test %d.", i)
		if origSign != nil {
			require.NotNilf(suite.T(), t.note.GetSignature(),
				"evalNote must restore note signature for test %d.", i)
		}
		require.Equalf(suite.T(), t.isAccused, node.view.IsAccused(t.noteHolder),
			"Invalid accusation state for test %d.", i)
		require.Equalf(suite.T(), t.isAlive, node.view.IsAlive(t.noteHolder),
			"Invalid live state for test %d.", i)
		require.Equalf(suite.T(), t.timer, node.view.HasTimer(t.noteHolder),
			"Invalid timer state for test %d.", i)

		if t.replaceNote {
			currNote, _ := node.view.ActiveNote(t.noteHolder.Id)
			require.NotEqualf(suite.T(), t.prevNote, currNote,
				"Invalid timer state for test %d.", i)
		}

	}
}

func (suite *HandlerTestSuite) TestSpread_OrphanedNotePromotedOnCertArrival() {
	node := suite.n

	// Generate key and certificate for an unknown peer
	priv, err := genKeys()
	require.NoError(suite.T(), err)
	cert := genCert(priv, 10)
	peerId := string(cert.SubjectKeyId[:])

	require.False(suite.T(), node.view.Exists(peerId), "Peer must not initially exist in full view")

	note := discovery.NewNote(peerId, 1, math.MaxUint32, priv)

	// Step 1: Ingest note before certificate into Tier 1 raw noteStore
	node.view.NoteStore().Insert(discovery.NoteFromPb(note))

	// Verify note was ingested in Tier 1 NoteStore, but peer is not in full view or alive
	require.False(suite.T(), node.view.Exists(peerId), "Peer must still not exist in full view")
	_, hasActiveNote := node.view.ActiveNote(peerId)
	require.False(suite.T(), hasActiveNote, "Peer must not have an active note before cert is known")

	// Step 2: Certificate arrives via mergeCertificates
	node.mergeCertificates([]*proto.Certificate{{Raw: cert.Raw}})

	// Verify certificate admitted peer, and orphaned note was automatically promoted!
	require.True(suite.T(), node.view.Exists(peerId), "Peer must now exist in full view")
	promotedNote, hasActiveNote := node.view.ActiveNote(peerId)
	require.True(suite.T(), hasActiveNote, "Orphaned note must be promoted to active note upon cert arrival")
	require.Equal(suite.T(), note.GetEpoch(), promotedNote.Epoch())

	peer := node.view.Peer(peerId)
	require.NotNil(suite.T(), peer)
	require.True(suite.T(), node.view.IsAlive(peer), "Peer must now be marked alive")
}

func (suite *HandlerTestSuite) TestAccusation_PromotedWhenPeerNoteArrivesLater() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	require.NotNil(suite.T(), succ)

	// Step 1: Clear succ's active note so an incoming accusation cannot be evaluated yet
	node.view.ClearTestNote(succ)
	_, hasNote := node.view.ActiveNote(succ.Id)
	require.False(suite.T(), hasNote, "Succ must not have an active note")

	// Step 2: Ingest accusation into AccusationStore (node.self is succ's predecessor on ring 1)
	accEpoch := uint64(2)
	acc := discovery.NewAccusation(accEpoch, succ.Id, node.self.Id, 1, suite.priv)
	node.mergeAccusations([]*proto.Accusation{acc})

	// Verify accusation is in Tier 1 store, but NOT yet active/promoted
	rawAcc := discovery.AccusationFromPb(acc)
	_, found := node.view.AccusationStore().Contains(rawAcc)
	require.True(suite.T(), found, "Accusation must be persisted in Tier 1 AccusationStore")
	require.False(suite.T(), node.view.IsAccused(succ), "Succ must not be marked accused before note arrives")

	// Step 3: Now succ's active note arrives via mergeNotes
	succNote := discovery.NewNote(succ.Id, accEpoch, math.MaxUint32, suite.privMap[succ.Id])
	node.mergeNotes([]*proto.Note{succNote})

	// Verify note was promoted AND orphaned accusation was automatically promoted
	_, hasNote = node.view.ActiveNote(succ.Id)
	require.True(suite.T(), hasNote, "Succ note must be promoted")
	require.True(suite.T(), node.view.IsAccused(succ), "Orphaned accusation must be automatically promoted upon note arrival")
	require.True(suite.T(), node.view.HasTimer(succ), "Suspicion timer must be active for accused peer")
}

func (suite *HandlerTestSuite) TestAccusation_PromotedWhenPeerCertificateArrivesLater() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	require.NotNil(suite.T(), succ)

	succNote, hasNote := node.view.ActiveNote(succ.Id)
	require.True(suite.T(), hasNote)

	succCertBytes := succ.Certificate()
	succId := succ.Id

	// Step 1: Remove accused (succ) from full view so incoming accusation cannot be verified yet
	err := node.view.RemoveTestFull(succId)
	require.NoError(suite.T(), err)
	require.False(suite.T(), node.view.Exists(succId), "Succ must not exist in full view")

	// Re-insert succ's note into Tier 1 noteStore so it can be promoted when certificate arrives
	node.view.NoteStore().Insert(discovery.NoteFromPb(succNote.ToPbMsg()))

	// Step 2: Ingest accusation into AccusationStore (node.self is predecessor on ring 1)
	acc := discovery.NewAccusation(succNote.Epoch(), succId, node.self.Id, 1, suite.priv)
	node.mergeAccusations([]*proto.Accusation{acc})

	// Verify accusation is in Tier 1 store, but NOT active/promoted
	rawAcc := discovery.AccusationFromPb(acc)
	_, found := node.view.AccusationStore().Contains(rawAcc)
	require.True(suite.T(), found, "Accusation must be persisted in Tier 1 AccusationStore")
	require.False(suite.T(), node.view.IsAccused(succ), "Succ must not be marked accused before succ cert arrives")

	// Step 3: Now accused peer's certificate arrives via mergeCertificates
	node.mergeCertificates([]*proto.Certificate{{Raw: succCertBytes}})

	// Verify succ peer is back in full view AND orphaned accusation was promoted
	require.True(suite.T(), node.view.Exists(succId), "Succ must now be in full view")
	require.True(suite.T(), node.view.IsAccused(succ), "Orphaned accusation must be automatically promoted upon cert arrival")
	require.True(suite.T(), node.view.HasTimer(succ), "Suspicion timer must be active for accused peer")
}
