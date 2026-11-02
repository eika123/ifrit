package core

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	cert, err := n.validateCtx(ctx)
	if err != nil {
		return nil, err
	}

	remoteId := string(cert.SubjectKeyId[:])
	peer, wasObserved, wasAccused, err := n.admitCaller(cert, remoteId, args.GetOwnNote())
	if err != nil {
		return nil, err
	}

	reply := n.newStateResponse()

	if !n.view.ShouldBeNeighbour(remoteId) {
		return n.handleNonNeighbourSpread(remoteId, peer, wasObserved, wasAccused, reply)
	}

	if err := n.computeControlAndDataDeltas(remoteId, args, reply); err != nil {
		return nil, err
	}
	n.populateReplyFingerprints(reply)

	return reply, nil
}

func (n *Node) newStateResponse() *pb.StateResponse {
	return &pb.StateResponse{
		FingerprintData:         n.FingerprintData(),
		FingerprintAccusations:  n.AccusationFingerprintBytes(),
		FingerprintView:         n.ViewFingerprintBytes(),
		FingerprintCertificates: n.CertFingerprintBytes(),
	}
}

func (n *Node) populateReplyFingerprints(reply *pb.StateResponse) {
	reply.FingerprintData = n.FingerprintData()
	reply.FingerprintAccusations = n.AccusationFingerprintBytes()
	reply.FingerprintView = n.ViewFingerprintBytes()
	reply.FingerprintCertificates = n.CertFingerprintBytes()
}

func (n *Node) admitCaller(cert *x509.Certificate, remoteId string, ownNote *pb.Note) (*discovery.Peer, bool, bool, error) {
	var wasObserved, wasAccused bool

	// TIER 1: Unconditional raw ingestion of own note
	if ownNote != nil {
		if rawNote := discovery.NoteFromPb(ownNote); rawNote != nil && n.view.NoteStore() != nil {
			n.view.NoteStore().Insert(rawNote)
		}
	}

	peer := n.view.Peer(remoteId)
	if peer != nil {
		wasObserved = true
		wasAccused = n.view.IsAccused(peer)
	}

	if n.view.ShouldBeNeighbour(remoteId) || !wasObserved {
		if err := n.evalCertificate(cert); err != nil {
			log.Error(err.Error())
			return nil, wasObserved, wasAccused, err
		}
		if peer == nil {
			peer = n.view.Peer(remoteId)
		}
	}

	if ownNote != nil {
		if err := n.evalNote(ownNote); err != nil && err != errOldNote {
			log.Debug(err.Error())
		}
	}

	return peer, wasObserved, wasAccused, nil
}

func (n *Node) handleNonNeighbourSpread(remoteId string, peer *discovery.Peer, wasObserved bool, wasAccused bool, reply *pb.StateResponse) (*pb.StateResponse, error) {
	if wasObserved {
		if !wasAccused {
			return nil, errNotMyNeighbour
		}
		for _, a := range n.view.ActiveAccusationsForPeer(peer) {
			reply.Accusations = append(reply.Accusations, a.ToPbMsg())
		}
		return reply, nil
	}

	// Help new peer integrate into the network
	reply.Certificates = append(reply.Certificates,
		&pb.Certificate{Raw: n.cm.Certificate().Raw})
	if selfNote := n.view.SelfNote(); selfNote != nil {
		reply.Notes = append(reply.Notes, selfNote.ToPbMsg())
	}

	for _, p := range n.view.FindNeighbours(remoteId) {
		reply.Certificates = append(reply.Certificates,
			&pb.Certificate{Raw: p.Certificate()})
		if note, ok := n.view.ActiveNote(p.Id); ok {
			reply.Notes = append(reply.Notes, note.ToPbMsg())
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
	handler := n.getStreamHandler()
	if handler == nil {
		return nil
	}

	// Channels used for bi-directional communication
	input := make(chan []byte)
	reply := make(chan []byte)

	// Concurrency guard: Ensure replyStream finishes transmitting all generated responses
	// before Stream() returns. Returning early on io.EOF cancels the gRPC stream context
	// on the server, prematurely severing the connection and dropping in-flight responses.
	replyDone := make(chan struct{})
	go func() {
		defer close(replyDone)
		n.replyStream(reply, srv)
	}()

	go n.runStreamHandler(handler, input, reply)

	ctx := srv.Context()
	var recvErr error

	for {
		select {
		case <-ctx.Done():
			recvErr = ctx.Err()
			goto done
		default:
		}

		req, err := srv.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			recvErr = err
			break
		}

		select {
		case <-ctx.Done():
			recvErr = ctx.Err()
			goto done
		case input <- req.GetContent():
		}
	}

done:
	// Signal to stream handler that client has closed its send side (no more inputs).
	close(input)

	// Wait for handler to finish processing remaining messages and replyStream to flush
	// all replies across the gRPC transport before completing the RPC.
	<-replyDone

	if recvErr != nil && recvErr != io.EOF {
		return recvErr
	}
	return nil
}

// Sync handles inbound bulk data and anti-entropy synchronization streams from peers.
func (n *Node) Sync(srv pb.Gossip_SyncServer) error {
	if srv == nil {
		return errors.New("sync: server stream is nil")
	}
	ctx := srv.Context()
	cert, err := n.validateCtx(ctx)
	if err != nil {
		log.Error("Sync validateCtx failed", "err", err)
		return status.Errorf(codes.Unauthenticated, "invalid caller cert: %v", err)
	}
	remoteID := string(cert.SubjectKeyId)

	peer := n.view.Peer(remoteID)
	if peer == nil {
		log.Error("Sync peer not in view", "remoteID", fmt.Sprintf("%x", remoteID))
		return status.Errorf(codes.PermissionDenied, "caller not recognized in view: %x", remoteID)
	}

	sess := n.sessionManager.GetOrCreate(remoteID)
	seq, err := sess.StartInboundTransfer()
	if err != nil {
		log.Error("Sync StartInboundTransfer failed", "err", err, "state", sess.State())
		return status.Errorf(codes.FailedPrecondition, "session not awaiting stream: %v", err)
	}

	return n.executeBidirectionalSync(ctx, srv, peer, sess, seq, false)
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

func hashContent(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
