package core

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"

	"github.com/golang/protobuf/proto"
	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
	grpcPeer "google.golang.org/grpc/peer"
)

var (
	errNoPeerInCtx            = errors.New("No peer information found in provided context.")
	errNoTLSInfo              = errors.New("No TLS info provided in peer context.")
	errNeighbourPeerNotFound  = errors.New("Neighbour peer was not found.")
	errNotMyNeighbour         = errors.New("Invalid gossip partner, not my neighbour.")
	errInvalidPeerInformation = errors.New("Could not create local peer representation.")
	errInvalidMaskLength      = errors.New("Mask is of invalid length.")

	errAccAlreadyExists      = errors.New("Accusation already existed, discarding.")
	errDisabledRing          = errors.New("Ring associated with accusation was disabled.")
	errInvalidAccuser        = errors.New("Accuser is not predecessor of accused on given ring, invalid accusation.")
	errInvalidSignature      = errors.New("Signature was invalid.")
	errInvalidSelfAccusation = errors.New("Received accusation about myself, but it was invalid.")
	errInvalidEpoch          = errors.New("Accusation epoch did not match note epoch.")

	errInvalidMask = errors.New("Note contained invalid mask")
	errOldNote     = errors.New("Already had the same or a more recent note")
	errNoPeer      = errors.New("Peer associated with note not found in full view.")

	errNilCert   = errors.New("Certificate was nil.")
	errSelfCert  = errors.New("Certificate was my own.")
	errNoCert    = errors.New("No certificate present in tls context.")
	errInvalidId = errors.New("Id in certificate is of invalid size.")
)

func (n *Node) Spread(ctx context.Context, args *pb.State) (*pb.StateResponse, error) {
	var observed bool
	cert, err := n.validateCtx(ctx)
	if err != nil {
		return nil, err
	}

	reply := &pb.StateResponse{}

	remoteId := string(cert.SubjectKeyId[:])
	peer := n.view.Peer(remoteId)
	if peer != nil {
		observed = true
	}

	if n.view.ShouldBeNeighbour(remoteId) {
		if err := n.evalCertificate(cert); err != nil {
			log.Error(err.Error())
			return nil, err
		}

		err := n.evalNote(args.GetOwnNote())
		if err != nil && err != errOldNote {
			log.Debug(err.Error())
		}

		extGossip := args.GetExternalGossip()
		hosts := args.GetExistingHosts()

		// If hosts is nil gossip message was only a rebuttal,
		// no need to merge views.
		if hosts != nil {
			n.mergeViews(hosts, reply)
		}

		if handler := n.getGossipHandler(); handler != nil && extGossip != nil {
			// received some gossip, handle it
			reply.ExternalGossip, err = handler(extGossip)
			if err != nil {
				log.Error(err.Error())
			}
		}
	} else if observed {
		if !peer.IsAccused() {
			err := n.evalNote(args.GetOwnNote())
			if err != nil {
				log.Debug(err.Error())
			}
			return nil, errNotMyNeighbour
		}

		err := n.evalNote(args.GetOwnNote())
		if err != nil {
			log.Debug(err.Error())
		}

		for _, a := range peer.AllAccusations() {
			reply.Accusations = append(reply.Accusations, a.ToPbMsg())
		}
	} else {
		if err := n.evalCertificate(cert); err != nil {
			log.Error(err.Error())
			return nil, err
		}

		err := n.evalNote(args.GetOwnNote())
		if err != nil {
			log.Debug(err.Error())
		}

		// Help new peer integrate into the network
		reply.Certificates = append(reply.Certificates,
			&pb.Certificate{Raw: n.cm.Certificate().Raw})
		reply.Notes = append(reply.Notes, n.self.Note().ToPbMsg())

		for _, p := range n.view.FindNeighbours(remoteId) {
			reply.Certificates = append(reply.Certificates,
				&pb.Certificate{Raw: p.Certificate()})
			if note := p.Note(); note != nil {
				reply.Notes = append(reply.Notes, note.ToPbMsg())
			}
		}
	}

	return reply, nil
}

func (n *Node) Messenger(ctx context.Context, args *pb.Msg) (*pb.MsgResponse, error) {
	var errMsg string
	var replyContent []byte

	_, err := n.validateCtx(ctx)
	if err != nil {
		return nil, err
	}

	if handler := n.getMsgHandler(); handler != nil {
		replyContent, err = handler(args.GetContent())
		if err != nil {
			errMsg = err.Error()
		}
	}
	return &pb.MsgResponse{Content: replyContent, Error: errMsg}, nil
}

func (n *Node) Stream(srv pb.Gossip_StreamServer) error {
	// Channels used for bi-directional communication
	input := make(chan []byte)
	reply := make(chan []byte)
	defer close(input)

	if handler := n.getStreamHandler(); handler != nil {
		go n.runStreamHandler(handler, input, reply)
		go n.replyStream(reply, srv)
		ctx := srv.Context()

		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			req, err := srv.Recv()
			if err == io.EOF {
				return nil
			}

			if err != nil {
				log.Error(err.Error())
				continue
			}

			input <- req.GetContent()
		}
	}

	return nil
}

func (n *Node) replyStream(reply chan []byte, srv pb.Gossip_StreamServer) {
	for resp := range reply {
		responseMsg := &pb.MsgResponse{
			Content: resp,
		}

		if err := srv.Send(responseMsg); err != nil {
			log.Error(err.Error())
		}
	}
}

func (n *Node) runStreamHandler(handler streamMsg, input, reply chan []byte) {
	handler(input, reply)
}

func (n *Node) mergeViews(given map[string]uint64, reply *pb.StateResponse) {
	lookupEpoch := func(rawId string) (uint64, bool) {
		if epoch, ok := given[hex.EncodeToString([]byte(rawId))]; ok {
			return epoch, true
		}
		if epoch, ok := given[rawId]; ok {
			return epoch, true
		}
		return 0, false
	}

	for _, p := range n.view.Full() {
		epoch, ok := lookupEpoch(p.Id)
		if !ok {
			reply.Certificates = append(reply.Certificates,
				&pb.Certificate{Raw: p.Certificate()})

			if note := p.Note(); note != nil {
				reply.Notes = append(reply.Notes, note.ToPbMsg())
			}
		} else if note := p.Note(); note != nil && note.IsMoreRecent(epoch) {
			reply.Notes = append(reply.Notes, note.ToPbMsg())
		}

		// No solution yet to avoid transferring all accusations.
		// Transferring all notes are avoided by checking epoch numbers.
		accs := p.AllAccusations()
		for _, a := range accs {
			reply.Accusations = append(reply.Accusations, a.ToPbMsg())
		}
	}

	localNote := n.self.Note()

	if epoch, exists := lookupEpoch(n.self.Id); !exists || localNote.IsMoreRecent(epoch) {
		reply.Notes = append(reply.Notes, localNote.ToPbMsg())
	}
}

func (n *Node) mergeNotes(notes []*pb.Note) {
	if notes == nil {
		return
	}

	for _, newNote := range notes {
		if n.self.Id == string(newNote.GetId()) {
			continue
		}

		err := n.evalNote(newNote)
		if err != nil {
			log.Debug(err.Error())
		}
	}
}

func (n *Node) mergeAccusations(accusations []*pb.Accusation) {
	if accusations == nil {
		return
	}

	for _, acc := range accusations {
		accId := string(acc.GetAccused())
		accuserId := string(acc.GetAccuser())

		accuser := n.view.Peer(accuserId)
		if accuserId == n.self.Id {
			accuser = n.self
		} else if accuser == nil {
			continue
		}

		accused := n.view.Peer(accId)
		if accId == n.self.Id {
			accused = n.self
		} else if accused == nil || accused.Note() == nil {
			continue
		}

		err := n.evalAccusation(acc, accuser, accused)
		if err != nil {
			log.Debug(err.Error(), "ringNum", acc.GetRingNum(), "epoch", acc.GetEpoch(), "accused", accused.Addr, "accuser", accuser.Addr)
		}
	}
}

func (n *Node) mergeCertificates(certs []*pb.Certificate) {
	if certs == nil {
		return
	}
	for _, b := range certs {
		cert, err := x509.ParseCertificate(b.GetRaw())
		if err != nil {
			log.Error(err.Error())
			continue
		}

		if n.self.Id == string(cert.SubjectKeyId) {
			continue
		}

		// Adds a valid certificate to the full view if valid and not already present.
		err = n.evalCertificate(cert)
		if err != nil {
			log.Debug(err.Error())
		}
	}
}

// marshalAccusationContent strips the signature, marshals the accusation payload,
// and restores the signature on the protobuf struct.
func (n *Node) marshalAccusationContent(a *pb.Accusation) ([]byte, error) {
	sign := a.GetSignature()
	if sign == nil {
		return nil, errInvalidSignature
	}

	a.Signature = nil
	bytes, err := proto.Marshal(a)
	a.Signature = sign
	return bytes, err
}

// handleSelfAccusation validates and responds to an incoming accusation against the local node.
// If the accuser is a legitimate ring predecessor with a valid signature, an immediate
// rebuttal broadcast is triggered.
func (n *Node) handleSelfAccusation(a *pb.Accusation, accuserPeer *discovery.Peer, marshaledAcc []byte) error {
	ringNum := a.GetRingNum()
	epoch := a.GetEpoch()

	if !n.view.ValidAccuser(n.self, accuserPeer, ringNum) {
		return errInvalidAccuser
	}

	sign := a.GetSignature()
	if !n.cs.Verify(marshaledAcc, sign.GetR(), sign.GetS(), accuserPeer.PublicKey()) {
		return errInvalidSignature
	}

	if n.view.ShouldRebuttal(epoch, ringNum) {
		n.protocol().Rebuttal(n)
		return nil
	}
	return errInvalidSelfAccusation
}

// validateRemoteAccusation verifies that an accusation against a remote peer matches the peer's
// current note epoch, is on an enabled ring, that the accuserPeer is the legitimate predecessor of accusedPeer,
// and carries a valid cryptographic signature.
func (n *Node) validateRemoteAccusation(a *pb.Accusation, accuserPeer, accusedPeer *discovery.Peer, marshaledAcc []byte) error {
	ringNum := a.GetRingNum()
	epoch := a.GetEpoch()

	note := accusedPeer.Note()
	if note == nil || !note.Equal(epoch) {
		return errInvalidEpoch
	}

	if note.IsRingDisabled(ringNum, n.view.NumRings()) {
		return errDisabledRing
	}

	if !n.view.ValidAccuser(accusedPeer, accuserPeer, ringNum) {
		return errInvalidAccuser
	}

	sign := a.GetSignature()
	if !n.cs.Verify(marshaledAcc, sign.GetR(), sign.GetS(), accuserPeer.PublicKey()) {
		return errInvalidSignature
	}

	return nil
}

// applyValidAccusation records a validated accusation on the accused peer and starts a suspicion
// removal timer if the peer is live.
func (n *Node) applyValidAccusation(a *pb.Accusation, accuserPeer, p *discovery.Peer) error {
	sign := a.GetSignature()
	err := p.AddAccusation(p.Id, accuserPeer.Id, a.GetEpoch(), a.GetRingNum(), sign.GetR(), sign.GetS())
	if err != nil {
		return err
	}

	// start timer if there isn't already one and the peer is considered alive
	if n.view.IsAlive(p.Id) && !n.view.HasTimer(p.Id) {
		n.view.StartTimer(p, p.Note(), accuserPeer)
	}
	return nil
}

// ensureAccusationTimer ensures a suspicion timer is active for an already recorded accusation if the peer is live.
func (n *Node) ensureAccusationTimer(accusedPeer, accuserPeer *discovery.Peer) {
	if n.view.IsAlive(accusedPeer.Id) && !n.view.HasTimer(accusedPeer.Id) {
		n.view.StartTimer(accusedPeer, accusedPeer.Note(), accuserPeer)
		log.Debug("Had accusation with no timer, starting timer.")
	}
}

// evalAccusation validates and processes an incoming gossip accusation against peer p.
//
// Behavior:
//  1. Verifies the accusation's ECDSA signature using the accuser's public key.
//  2. If the accusation targets the local node (self):
//     - Validates that the accuser is our legitimate ring predecessor.
//     - Checks if a rebuttal is needed (current epoch match) and triggers an immediate rebuttal broadcast.
//  3. If the accusation targets a remote peer:
//     - If already recorded, ensures the suspicion timer is active.
//     - If new, verifies that the target note epoch matches, the ring is not disabled, and the accuser is the valid predecessor.
//     - Stores the accusation on the peer and starts a suspicion removal timer if the peer is live.
func (n *Node) evalAccusation(a *pb.Accusation, accuserPeer, accusedPeer *discovery.Peer) error {
	marshaledAcc, err := n.marshalAccusationContent(a)
	if err != nil {
		return err
	}

	if n.self.Id == accusedPeer.Id {
		return n.handleSelfAccusation(a, accuserPeer, marshaledAcc)
	}

	ringNum := a.GetRingNum()
	epoch := a.GetEpoch()

	if acc := accusedPeer.RingAccusation(ringNum); acc != nil && acc.Equal(accusedPeer.Id, accuserPeer.Id, ringNum, epoch) {
		n.ensureAccusationTimer(accusedPeer, accuserPeer)
		return errAccAlreadyExists
	}

	if err := n.validateRemoteAccusation(a, accuserPeer, accusedPeer, marshaledAcc); err != nil {
		return err
	}

	return n.applyValidAccusation(a, accuserPeer, accusedPeer)
}

func (node *Node) evalNote(newNote *pb.Note) error {
	epoch := newNote.GetEpoch()
	mask := newNote.GetMask()

	sign := newNote.GetSignature()
	if sign == nil {
		return errInvalidSignature
	}

	r := sign.GetR()
	s := sign.GetS()

	// Get the peer this note is about.
	peer := node.view.Peer(string(newNote.GetId()))
	if peer == nil {
		return errNoPeer
	}

	note := peer.Note()

	if note != nil && !note.IsMoreRecent(epoch) {
		return errOldNote
	}

	if valid := node.view.ValidMask(mask); !valid {
		return errInvalidMask
	}

	newNote.Signature = nil
	bytes, err := proto.Marshal(newNote)
	newNote.Signature = sign
	if err != nil {
		return err
	}

	accusations := peer.AllAccusations()
	// Not accused, only need to check if newnote is more recent
	if len(accusations) == 0 {
		// Want to store the most recent note
		if note == nil || note.IsMoreRecent(epoch) {
			if valid := node.cs.Verify(bytes, r, s, peer.PublicKey()); !valid {
				return errInvalidSignature
			}

			peer.AddNote(mask, epoch, r, s)

			if alive := node.view.IsAlive(peer.Id); !alive {
				node.view.AddLive(peer)
			}
		}
	} else {
		if valid := node.cs.Verify(bytes, r, s, peer.PublicKey()); !valid {
			return errInvalidSignature
		}

		// Peer is accused, need to check if this note invalidates any accusations.
		for _, acc := range accusations {
			if acc.IsMoreRecent(epoch) {
				peer.RemoveAccusation(acc)
			}
		}

		if note == nil || note.IsMoreRecent(epoch) {
			peer.AddNote(mask, epoch, r, s)
		}

		// All accusations has to be invalidated before we add peer back to full view.
		if !peer.IsAccused() {
			peer.ResetPingCount()

			if exists := node.view.HasTimer(peer.Id); exists {
				node.view.DeleteTimeout(peer.Id)
			}

			if alive := node.view.IsAlive(peer.Id); !alive {
				node.view.AddLive(peer)
			}

			log.Debug("Rebuttal received", "epoch", epoch, "addr", peer.Addr)
		}
	}
	return nil
}

// validateCertificate checks if a certificate is non-nil, does not belong to self,
// has a valid SubjectKeyId length, and is signed by the CA (or self-signed if CA is absent).
func (n *Node) validateCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return errNilCert
	}

	id := string(cert.SubjectKeyId)

	if n.self.Id == id {
		return errSelfCert
	}

	if len(id) != sha256.Size {
		return errInvalidId
	}

	if caCert := n.cm.CaCertificate(); caCert != nil {
		// our chain of trust is currently just CA -> nodes, no intermediaries
		return cert.CheckSignatureFrom(caCert)
	}
	return cert.CheckSignatureFrom(cert)
}

// addValidCertificate registers an authenticated certificate in the full view if not already present.
func (n *Node) addValidCertificate(cert *x509.Certificate) {
	id := string(cert.SubjectKeyId)
	_ = n.view.AddFull(id, cert)
}

// evalCertificate validates a certificate and adds it to the full view if valid.
func (n *Node) evalCertificate(cert *x509.Certificate) error {
	if err := n.validateCertificate(cert); err != nil {
		return err
	}
	n.addValidCertificate(cert)
	return nil
}

func (n *Node) validateCtx(ctx context.Context) (*x509.Certificate, error) {
	var tlsInfo credentials.TLSInfo
	var ok bool

	p, ok := grpcPeer.FromContext(ctx)
	if !ok {
		return nil, errNoPeerInCtx
	}

	if tlsInfo, ok = p.AuthInfo.(credentials.TLSInfo); !ok {
		return nil, errNoTLSInfo
	}

	if len(tlsInfo.State.PeerCertificates) < 1 {
		return nil, errNoCert
	}

	return tlsInfo.State.PeerCertificates[0], nil
}

func hashContent(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
