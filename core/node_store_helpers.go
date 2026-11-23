package core

import (
	"bytes"
	"encoding/binary"

	"github.com/eika123/ifrit/comm"
	"github.com/eika123/ifrit/core/discovery"
	"github.com/eika123/ifrit/crypto/pki"
	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
)

// FingerprintData returns the canonical 8-byte big-endian fingerprint of the
// registered data store, or an 8-byte zero slice when no data store is registered.
func (n *Node) FingerprintData() []byte {
	n.dataReconcilerMutex.RLock()
	fingerprintpFn := n.dataStoreFP
	n.dataReconcilerMutex.RUnlock()
	if fingerprintpFn != nil {
		return fingerprintpFn()
	}
	return make([]byte, 8)
}

// Fingerprints returns the current 8-byte store fingerprints for UDP Pong replies.
func (n *Node) Fingerprints() comm.Fingerprints {
	return comm.Fingerprints{
		Data:        n.FingerprintData(),
		Accusations: n.AccusationFingerprintBytes(),
		View:        n.ViewFingerprintBytes(),
		Services:    n.ServiceFingerprintBytes(),
	}
}

func (n *Node) ServiceFingerprint() digestmaps.DigestSymbol {
	return n.view.ServiceFingerprint()
}

func (n *Node) ServiceFingerprintBytes() []byte {
	fp := n.view.ServiceFingerprint()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(fp))
	return buf[:]
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
	return n.view.Fingerprint()
}

func (n *Node) ViewFingerprintBytes() []byte {
	fp := n.view.Fingerprint()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(fp))
	return buf[:]
}

// IsDivergent checks if peer p's reported fingerprints differ from local node's current fingerprints.
func (n *Node) IsDivergent(p *discovery.Peer) bool {
	dataDiff, accDiff, viewDiff, serviceDiff := n.DivergentSets(p)
	return dataDiff || accDiff || viewDiff || serviceDiff
}

// DivergentSets returns boolean indicators for which specific sets differ between peer p and the local node.
func (n *Node) DivergentSets(peer *discovery.Peer) (dataDiff, accDiff, viewDiff, serviceDiff bool) {
	if peer == nil {
		return false, false, false, false
	}
	dataDiff = !bytes.Equal(peer.FingerprintData(), n.FingerprintData())
	accDiff = !bytes.Equal(peer.FingerprintAccusations(), n.AccusationFingerprintBytes())
	viewDiff = !bytes.Equal(peer.FingerprintView(), n.ViewFingerprintBytes())
	serviceDiff = !bytes.Equal(peer.FingerprintServices(), n.ServiceFingerprintBytes())
	return
}

// NoteDigests returns the digest symbols of all local notes in the version vector.
func (n *Node) NoteDigests() []digestmaps.DigestSymbol {
	return n.view.NoteDigests()
}

// CertStore returns the underlying ReverseIndexStore backing peer certificates.
func (n *Node) CertStore() digestmaps.ReverseIndexStore[*pki.Certificate, digestmaps.DigestSymbol] {
	return n.view.CertStore()
}

// CertFingerprint returns the commutative XOR fingerprint of all certificates in the view.
func (n *Node) CertFingerprint() digestmaps.DigestSymbol {
	return n.view.CertFingerprint()
}

// CertFingerprintBytes returns the 8-byte big-endian representation of the certificate fingerprint.
func (n *Node) CertFingerprintBytes() []byte {
	fp := n.view.CertFingerprint()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(fp))
	return buf[:]
}

// CertDigests returns the digest symbols of all local certificates.
func (n *Node) CertDigests() []digestmaps.DigestSymbol {
	return n.view.CertDigests()
}

// PeerGate returns the per-peer reconciliation concurrency gate.
func (n *Node) PeerGate() *PeerGate {
	return n.peerGate
}

// RegisterDataStore registers an application's typed data store on the node
// using the default reconcile.ItemCodec for type T.
func RegisterDataStore[T any](n *Node, store digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol]) {
	RegisterDataStoreWithCodec(n, store, nil)
}

// RegisterDataStoreWithCodec registers an application's typed data store on the node
// with a custom reconcile.ItemCodec.
func RegisterDataStoreWithCodec[T any](n *Node, store digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol], codec reconcile.ItemCodec[T]) {
	RegisterReconcilableDataStore(n, store, codec)
}
