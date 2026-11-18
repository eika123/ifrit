package core

import (
	"bytes"
	"encoding/binary"

	"github.com/eika123/ifrit/core/discovery"
	"github.com/eika123/ifrit/crypto/pki"
	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	log "github.com/inconshreveable/log15"
)

func (n *Node) SetFingerprint(fp []byte) {
	n.self.SetFingerprintData(fp)
}

func (n *Node) Fingerprint() []byte {
	return n.self.FingerprintData()
}

func (n *Node) SetFingerprintData(fp []byte) {
	n.self.SetFingerprintData(fp)
}

func (n *Node) FingerprintData() []byte {
	if selfFp := n.self.FingerprintData(); len(selfFp) > 0 {
		return selfFp
	}
	n.dataReconcilerMutex.RLock()
	fingerprintpFn := n.dataStoreFP
	n.dataReconcilerMutex.RUnlock()
	if fingerprintpFn != nil {
		return fingerprintpFn()
	}
	return nil
}

func (n *Node) AccusationFingerprint() digestmaps.DigestSymbol {
	return n.view.AccusationFingerprint()
}

func (n *Node) AccusationFingerprintBytes() []byte {
	fp := n.view.AccusationFingerprint()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(fp))
	return buf[:]
}

func (n *Node) ViewFingerprint() digestmaps.DigestSymbol {
	fp, err := n.view.Fingerprint()
	if err != nil {
		log.Error("Failed to get view fingerprint", "err", err)
		return 0
	}
	return fp
}

func (n *Node) ViewFingerprintBytes() []byte {
	fp, err := n.view.Fingerprint()
	if err != nil {
		log.Error("Failed to get view fingerprint", "err", err)
		return nil
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(fp))
	return buf[:]
}

// IsDivergent checks if peer p's reported fingerprints differ from local node's current fingerprints.
func (n *Node) IsDivergent(p *discovery.Peer) bool {
	dataDiff, accDiff, viewDiff := n.DivergentSets(p)
	return dataDiff || accDiff || viewDiff
}

// DivergentSets returns boolean indicators for which specific sets differ between peer p and the local node.
func (n *Node) DivergentSets(peer *discovery.Peer) (dataDiff, accDiff, viewDiff bool) {
	if peer == nil {
		return false, false, false
	}
	dataDiff = !bytes.Equal(peer.FingerprintData(), n.FingerprintData())
	accDiff = !bytes.Equal(peer.FingerprintAccusations(), n.AccusationFingerprintBytes())
	viewDiff = !bytes.Equal(peer.FingerprintView(), n.ViewFingerprintBytes())
	return
}

// AccusationDigests returns the digest symbols of all local accusations.
func (n *Node) AccusationDigests() []digestmaps.DigestSymbol {
	return n.view.AccusationStore().DigestsCopy()
}

// AccusationDigestsUint64 returns the 64-bit uint64 digests of all local accusations for wire serialization.
func (n *Node) AccusationDigestsUint64() []uint64 {
	return digestmaps.AsUint64Slice(n.AccusationDigests())
}

// NoteDigests returns the digest symbols of all local notes in the version vector.
func (n *Node) NoteDigests() []digestmaps.DigestSymbol {
	digests, err := n.view.NoteDigests()
	if err != nil {
		log.Error("Failed to get note digests", "err", err)
		return nil
	}
	return digests
}

// NoteDigestsUint64 returns the 64-bit uint64 digests of all local notes in the version vector for wire serialization.
func (n *Node) NoteDigestsUint64() []uint64 {
	return digestmaps.AsUint64Slice(n.NoteDigests())
}

// CertStore returns the underlying ReverseIndexStore backing peer certificates.
func (n *Node) CertStore() digestmaps.ReverseIndexStore[*pki.Certificate, digestmaps.DigestSymbol] {
	return n.view.CertStore()
}

// CertFingerprint returns the commutative XOR fingerprint of all certificates in the view.
func (n *Node) CertFingerprint() digestmaps.DigestSymbol {
	fp, err := n.view.CertFingerprint()
	if err != nil {
		log.Error("Failed to get cert fingerprint", "err", err)
		return 0
	}
	return fp
}

// CertFingerprintBytes returns the 8-byte big-endian representation of the certificate fingerprint.
func (n *Node) CertFingerprintBytes() []byte {
	fp, err := n.view.CertFingerprint()
	if err != nil {
		log.Error("Failed to get cert fingerprint", "err", err)
		return nil
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(fp))
	return buf[:]
}

// CertDigests returns the digest symbols of all local certificates.
func (n *Node) CertDigests() []digestmaps.DigestSymbol {
	digests, err := n.view.CertDigests()
	if err != nil {
		log.Error("Failed to get cert digests", "err", err)
		return nil
	}
	return digests
}

// CertDigestsUint64 returns the 64-bit uint64 digests of all local certificates for wire serialization.
func (n *Node) CertDigestsUint64() []uint64 {
	return digestmaps.AsUint64Slice(n.CertDigests())
}

// SessionManager returns the peer reconciliation session manager.
func (n *Node) SessionManager() *PeerSessionManager {
	return n.sessionManager
}

// RegisterDataStore registers an application's typed reconcilable data store on the node
// using the default reconcile.ItemCodec for type T.
func RegisterDataStore[T any](n *Node, store reconcile.Store[T]) {
	RegisterDataStoreWithCodec(n, store, nil)
}

// RegisterDataStoreWithCodec registers an application's typed reconcilable data store on the node
// with a custom reconcile.ItemCodec.
func RegisterDataStoreWithCodec[T any](n *Node, store reconcile.Store[T], codec reconcile.ItemCodec[T]) {
	RegisterReconcilableDataStore(n, store, codec)
}
