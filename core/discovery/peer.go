package discovery

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
)

var (
	errPeerId                  = errors.New("certificate contains no subjectKeyIdentifier")
	errPeerAddr                = errors.New("certificate contains no address")
	errNoteId                  = errors.New("note id is invalid")
	errNoteSign                = errors.New("note signature is invalid")
	errAccusedId               = errors.New("accused id is invalid")
	errAccuserId               = errors.New("accuser id is invalid")
	errAccuserSign             = errors.New("accusation signature is invalid")
	errPubKey                  = errors.New("Public key type is invalid")
	errOldEpoch                = errors.New("accusation contains old epoch")
	errFoundNoNote             = errors.New("no note found for the accused peer")
	errNoCert                  = errors.New("Passed certificate was nil")
	errInvalidRing             = errors.New("Tried to set an accusation on a non-existing ring")
	errTooManyDeactivatedRings = errors.New("Mask contains too many deactivated rings")
	errInvalidMaskLength       = errors.New("mask contains set bits beyond numRings or invalid ring count")
	errNonExistingRing         = errors.New("Accusation specifies non exisiting ring")
	errDeactivatedRing         = errors.New("Accusation on deactivated ring")
	ErrAccAlreadyExists        = errors.New("Accusation already exists")
)

// Peer represents a discovered node in the Fireflies overlay, holding its
// certificate-bound identity, network endpoints, liveness state, and cached
// reconciliation fingerprints.
type Peer struct {
	// Addr is the peer's TCP/gRPC gossip and sync endpoint (host:port),
	// populated from cert.Subject.Locality[0].
	Addr string

	// PingAddr is the peer's UDP heartbeat/ping endpoint (host:port),
	// populated from cert.Subject.Locality[1].
	PingAddr string

	// Debuging and experiments only.
	HttpAddr string

	// Id is the peer's opaque 32-byte random identifier as a raw byte-string,
	// populated from cert.SubjectKeyId. Used for ring placement, view indexing,
	// and mTLS caller lookup on inbound RPCs (where source ports are ephemeral).
	Id        string
	cert      *x509.Certificate
	publicKey *ecdsa.PublicKey

	// Number of unswered pings sent to this peer.
	// A high value can move this peer from live to dead status.
	nPing uint32

	nPingMutex sync.RWMutex

	// scratch pad between udp ping-pongs and gossip loop
	// used to detect divergence, triggering calls on spread
	fingerprintData  []byte
	fingerprintAcc   []byte
	fingerprintView  []byte
	fingerprintMutex sync.RWMutex
}

// Ecdsa signature values
type signature struct {
	r []byte
	s []byte
}

type timeout struct {
	observer  *Peer
	timeStamp time.Time
	accused   *Peer
	lastNote  *Note
}

// newPeer constructs a Peer from an X.509 certificate, expecting SubjectKeyId
// for Peer.Id and Subject.Locality entries [TCP/gRPC, UDP ping, optional HTTP].
func newPeer(cert *x509.Certificate, numRings uint32) (*Peer, error) {
	var ok bool
	var http string
	var pb *ecdsa.PublicKey

	if numRings == 0 {
		return nil, errNoRings
	}

	if cert == nil {
		return nil, errNoCert
	}

	if fields := len(cert.Subject.Locality); fields < 2 {
		return nil, errPeerAddr
	} else if fields == 3 {
		http = cert.Subject.Locality[2]
	}

	if len(cert.SubjectKeyId) == 0 {
		return nil, errPeerId
	}

	if pb, ok = cert.PublicKey.(*ecdsa.PublicKey); !ok {
		return nil, errPubKey
	}

	return &Peer{
		Addr:      cert.Subject.Locality[0],
		PingAddr:  cert.Subject.Locality[1],
		HttpAddr:  http,
		cert:      cert,
		Id:        string(cert.SubjectKeyId),
		publicKey: pb,
	}, nil
}

func (p *Peer) Certificate() []byte {
	if p.cert == nil {
		log.Error("Peer had no certificate")
		return nil
	}

	return p.cert.Raw
}

func (p *Peer) PublicKey() *ecdsa.PublicKey {
	return p.publicKey
}

func (p *Peer) IncrementPingCount() {
	p.nPingMutex.Lock()
	defer p.nPingMutex.Unlock()

	p.nPing++
}

// Resets the count of unsuccessful pings to 0
func (p *Peer) ResetPingCount() {
	p.nPingMutex.Lock()
	defer p.nPingMutex.Unlock()

	p.nPing = 0
}

func (p *Peer) NumPing() uint32 {
	p.nPingMutex.RLock()
	defer p.nPingMutex.RUnlock()

	return p.nPing
}

func (p *Peer) FingerprintData() []byte {
	p.fingerprintMutex.RLock()
	defer p.fingerprintMutex.RUnlock()

	return p.fingerprintData
}

func (p *Peer) SetFingerprintData(fp []byte) {
	p.fingerprintMutex.Lock()
	defer p.fingerprintMutex.Unlock()

	p.fingerprintData = fp
}

func (p *Peer) FingerprintAccusations() []byte {
	p.fingerprintMutex.RLock()
	defer p.fingerprintMutex.RUnlock()

	return p.fingerprintAcc
}

func (p *Peer) SetFingerprintAccusations(fp []byte) {
	p.fingerprintMutex.Lock()
	defer p.fingerprintMutex.Unlock()

	p.fingerprintAcc = fp
}

func (p *Peer) FingerprintView() []byte {
	p.fingerprintMutex.RLock()
	defer p.fingerprintMutex.RUnlock()

	return p.fingerprintView
}

func (p *Peer) SetFingerprintView(fp []byte) {
	p.fingerprintMutex.Lock()
	defer p.fingerprintMutex.Unlock()

	p.fingerprintView = fp
}

// SetFingerprints updates cached peer fingerprints from remote responses.
func (p *Peer) SetFingerprints(data, acc, view []byte) {
	// go: method calls on nil structs are allowed
	if p == nil {
		return
	}
	if len(data) > 0 {
		p.SetFingerprintData(data)
	}
	if len(acc) > 0 {
		p.SetFingerprintAccusations(acc)
	}
	if len(view) > 0 {
		p.SetFingerprintView(view)
	}
}
