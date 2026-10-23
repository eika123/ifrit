package discovery

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"math"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	pb "github.com/joonnna/ifrit/protobuf"
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
	errNonExistingRing         = errors.New("Accusation specifies non exisiting ring")
	errDeactivatedRing         = errors.New("Accusation on deactivated ring")
	ErrAccAlreadyExists        = errors.New("Accusation already exists")
)

type Peer struct {
	Addr     string
	PingAddr string

	// Debuging and experiments only.
	HttpAddr string

	noteMutex sync.RWMutex
	note      *Note

	Id        string
	cert      *x509.Certificate
	publicKey *ecdsa.PublicKey

	// Number of unswered pings sent to this peer.
	// A high value can move this peer from live to dead status.
	nPing uint32

	nPingMutex sync.RWMutex

	fingerprint      []byte
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

func (p *Peer) AddNote(mask uint32, epoch uint64, r, s []byte) {
	p.noteMutex.Lock()
	defer p.noteMutex.Unlock()

	if p.note == nil || p.note.IsMoreRecent(epoch) {
		p.note = &Note{
			id:    p.Id,
			mask:  mask,
			epoch: epoch,
			signature: &signature{
				r: r,
				s: s,
			},
		}
	}
}

func (p *Peer) Note() *Note {
	p.noteMutex.RLock()
	defer p.noteMutex.RUnlock()

	return p.note
}

func (p *Peer) Info() (*pb.Certificate, *pb.Note) {
	var c *pb.Certificate
	var n *pb.Note

	if p.cert != nil {
		c = &pb.Certificate{
			Raw: p.cert.Raw,
		}
	} else {
		log.Error("Had no certificate for peer", "addr", p.Addr)
	}

	if note := p.Note(); note != nil {
		n = note.ToPbMsg()
	} else {
		log.Debug("No note existed for peer", "addr", p.Addr)
	}

	return c, n
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

func (p *Peer) Fingerprint() []byte {
	p.fingerprintMutex.RLock()
	defer p.fingerprintMutex.RUnlock()

	return p.fingerprint
}

func (p *Peer) SetFingerprint(fp []byte) {
	p.fingerprintMutex.Lock()
	defer p.fingerprintMutex.Unlock()

	p.fingerprint = fp
}

/*

########## METHODS ONLY USED FOR TESTING BELOW THIS LINE ##########

*/

// ONLY for testing
func (p *Peer) NewNote(priv *ecdsa.PrivateKey, epoch uint64) {
	p.note = &Note{
		id:    p.Id,
		mask:  math.MaxUint32,
		epoch: epoch,
	}
	signNote(p.note, priv)
}

// ONLY for testing
func (p *Peer) ClearNote() {
	p.note = nil
}
