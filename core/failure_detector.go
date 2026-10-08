package core

import (
	"bytes"
	"crypto/rand"
	"errors"
	"time"

	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
)

var (
	errDead                 = errors.New("Peer is dead")
	errInvalidPongSignature = errors.New("Invalid signature on pong message")
)

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

	return fd.cs.Verify(pong.GetNonce(), sign.GetR(), sign.GetS(), dest.PublicKey())
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
