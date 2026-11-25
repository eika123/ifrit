package testutil

import (
	"crypto/ecdsa"
	"errors"
	"math"
	"testing"

	"github.com/eika123/ifrit/core/discovery"
	pb "github.com/eika123/ifrit/protobuf"
	"github.com/stretchr/testify/require"
)

// AddTestNote signs a full-mask note for p at epoch and inserts it into v.
func AddTestNote(v *discovery.View, p *discovery.Peer, priv *ecdsa.PrivateKey, epoch uint64) {
	n := NewNote(p.Id, epoch, math.MaxUint32, priv)
	v.AddNote(p, n.GetMask(), n.GetEpoch(), n.GetSignature().GetR(), n.GetSignature().GetS())
}

// AddTestAccusation inserts a protobuf accusation into v via the production AddAccusation path.
func AddTestAccusation(t testing.TB, v *discovery.View, a *pb.Accusation) {
	t.Helper()
	err := v.AddAccusation(
		string(a.GetAccused()),
		string(a.GetAccuser()),
		a.GetEpoch(),
		a.GetRingNum(),
		a.GetSignature().GetR(),
		a.GetSignature().GetS(),
	)
	require.NoError(t, err)
}

// CompareViews checks that two discovery views agree on full membership, active notes,
// live membership, and accusations.
func CompareViews(v, other *discovery.View) error {
	for _, p := range v.Full() {
		id := p.Id
		if id != other.Self().Id {
			if p2 := other.Peer(id); p2 == nil || p2.Id != id {
				return errors.New("Peer not present in both views.")
			}
		}

		note1, has1 := v.ActiveNote(id)
		note2, has2 := other.ActiveNote(id)

		if !has1 && !has2 {
			continue
		}
		if !has1 || !has2 {
			return errors.New("Did not have note for peer in both views.")
		}
		if !note1.Equal(note2.Epoch()) {
			return errors.New("Did not have same note for peer in both views.")
		}
	}

	for _, p := range v.Live() {
		if p.Id == other.Self().Id {
			continue
		}
		if !other.IsAlive(p) {
			return errors.New("Did not have peer in both live views.")
		}
	}

	accs1 := v.AccusationStore().Elements()
	accs2 := other.AccusationStore().Elements()
	if len(accs1) != len(accs2) {
		return errors.New("Accusation counts mismatch in views.")
	}

	for _, a := range accs1 {
		a2, ok := other.AccusationStore().Contains(a)
		if !ok || !a.Equal(a2.Accused(), a2.Accuser(), a2.RingNum(), a2.Epoch()) {
			return errors.New("Accusation not equal in both views.")
		}
	}

	return nil
}
