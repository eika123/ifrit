package core

import (
	"bytes"
	"crypto/rand"
	"errors"
	"time"

	"github.com/eika123/ifrit/comm"
	"github.com/eika123/ifrit/core/discovery"
	pb "github.com/eika123/ifrit/protobuf"
	log "github.com/inconshreveable/log15"
)

var (
	errDead                 = errors.New("Peer is dead")
	errInvalidPongSignature = errors.New("Invalid signature on pong message")
)

// /////////////// Fireflies ring maintenance //////////////////////////////
func (n *Node) rebuttal() {
	neighbours := n.view.GossipPartners()

	selfNote := n.view.SelfNote()
	if selfNote == nil {
		return
	}
	noteMsg := selfNote.ToPbMsg()

	baseMsg := &pb.AnnounceRequest{
		OwnNote:    noteMsg,
		IsRebuttal: true,
	}

	adv := n.AdversarialPolicy()

	for _, peer := range neighbours {
		msg, suppress := adv.shouldSuppressRebuttal(peer, baseMsg)
		if suppress || msg == nil {
			log.Debug("Adversary: suppressed rebuttal to peer", "addr", peer.Addr)
			continue
		}

		_, err := n.announce(n.syncCtx, peer.Addr, msg)
		if err != nil {
			log.Error(err.Error(), "addr", peer.Addr)
			continue
		}
	}
}

func (n *Node) gossip() {
	n.gossipWithStoreReconcilers()
	n.reconcileServiceStores()
}

func (n *Node) monitor() {
	adv := n.AdversarialPolicy()

	// Fireflies protocol: ping one successor per ring,
	// up to ringsPingedPerInterval in total.
	for i := 1; i <= n.ringsPingedPerInterval; i++ {
		peer, ringNum := n.view.MonitorTarget()
		if peer == nil {
			continue
		}

		err := n.fd.probe(peer)
		if err == errDead {
			log.Debug("Monitor --> Successor dead, accusing", "succ", peer.Addr, "ringNum", ringNum)
			peerNote, found := n.view.ActiveNote(peer.Id)

			// Will always have note for a peer in our liveView, except when the peer stems
			// from the initial contact list of the CA, if it's dead
			// we should remove it to ensure it doesn't stay in our liveView.
			// Not possible to accuse a peer without a note.
			if !found || peerNote == nil {
				n.view.RemoveLive(peer)
				log.Debug("Monitor -- Removing live peer due to not having note and being accused",
					"addr", peer.Addr)
				continue
			}

			if adv.shouldSuppressAccusation(peer, ringNum) {
				log.Debug("Adversary: suppressed accusation against peer", "addr", peer.Addr, "ringNum", ringNum)
				continue
			}

			err := n.view.CreateAccusation(peer, peerNote, ringNum, n.cs)
			if err == discovery.ErrAccAlreadyExists || err == nil {
				live := n.view.IsAlive(peer)
				if exists := n.view.HasTimer(peer); !exists && live {
					n.view.StartTimer(peer, peerNote, n.self)
				}
			} else {
				log.Error(err.Error())
			}
		}

		if err == errInvalidPongSignature {
			log.Debug("Monitor -- Invalid pong signature, successor is malicious (or this implementation is just buggy!)", "succ", peer.Addr)
		}

		if err != nil && err != errInvalidPongSignature {
			log.Error(err.Error(), "Monitor -- successor peer addr:", peer.Addr)
		}
	}
}

func (n *Node) gossipLoop() {
	defer n.wg.Done()

	for {
		select {
		case <-n.exitChan:
			log.Info("Exiting gossiping")
			return
		case <-time.After(n.getGossipTimeout()):
			n.gossip()
		}
	}
}

func (n *Node) monitorLoop() {
	defer n.wg.Done()

	for {
		select {
		case <-n.exitChan:
			log.Info("Stopping monitoring")
			return
		case <-time.After(n.monitorTimeout):
			n.monitor()
		}
	}
}

// fireflies describes a way to estimate round-trip-times, packet loss etc.
// This can be used for that
func (n *Node) setGossipTimeout(timeout int) {
	n.gossipTimeoutMutex.Lock()
	defer n.gossipTimeoutMutex.Unlock()

	n.gossipTimeout = (time.Duration(timeout) * time.Second)
}

func (n *Node) getGossipTimeout() time.Duration {
	n.gossipTimeoutMutex.RLock()
	defer n.gossipTimeoutMutex.RUnlock()

	return n.gossipTimeout
}

///////////////////////////////////////////////////////////////////////////

// /////////////////// Failure detector module /////////////////////////////
type failureDetector struct {
	ps             pingService
	cs             cryptoService
	maxFailedPings uint32
}

type pingService interface {
	Pause(time.Duration)
	Ping(string, *pb.Ping) (*pb.Pong, error)
	Start()
	Stop()
	PongContent(nonce []byte, fpData []byte, fpAcc []byte, fpView []byte, fpServices []byte) []byte
	SetFingerprintsProvider(func() comm.Fingerprints)
}

func newFd(ps pingService, cs cryptoService, maxPing uint32) *failureDetector {
	return &failureDetector{
		ps:             ps,
		cs:             cs,
		maxFailedPings: maxPing,
	}
}

func (fd *failureDetector) stopServing(d time.Duration) {
	fd.ps.Pause(d)
}

func (fd *failureDetector) validPong(pong *pb.Pong, pingMsg *pb.Ping, dest *discovery.Peer) bool {
	sign := pong.GetSignature()
	if sign == nil || !bytes.Equal(pong.GetNonce(), pingMsg.GetNonce()) {
		return false
	}

	content := fd.ps.PongContent(pong.GetNonce(), pong.GetFingerprintData(), pong.GetFingerprintAccusations(), pong.GetFingerprintView(), pong.GetFingerprintServices())
	return fd.cs.Verify(content, sign.GetR(), sign.GetS(), dest.PublicKey())
}

func (fd *failureDetector) probe(dest *discovery.Peer) error {
	msg := &pb.Ping{
		Nonce: genNonce(),
	}

	pong, err := fd.ps.Ping(dest.PingAddr, msg)
	if err != nil {
		dest.IncrementPingCount()
		if dest.NumPing() >= fd.maxFailedPings {
			return errDead
		}

		return err
	}

	if !fd.validPong(pong, msg, dest) {
		dest.IncrementPingCount()
		if dest.NumPing() >= fd.maxFailedPings {
			return errDead
		}
		return errInvalidPongSignature
	}

	dest.ResetPingCount()
	dest.SetFingerprints(
		pong.GetFingerprintData(),
		pong.GetFingerprintAccusations(),
		pong.GetFingerprintView(),
		pong.GetFingerprintServices(),
	)

	return nil
}

func (fd *failureDetector) start() {
	fd.ps.Start()
}

func (fd *failureDetector) stop() {
	fd.ps.Stop()
}

func genNonce() []byte {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	return nonce
}

///////////////////////////////////////////////////////////////////////
