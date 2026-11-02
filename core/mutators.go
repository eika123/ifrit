package core

import (
	"errors"
	"time"

	"github.com/joonnna/ifrit/core/discovery"
	"github.com/joonnna/ifrit/protobuf"
)

var (
	errNotFound     = errors.New("No node info found")
	errPeerNotFound = errors.New("No peer info found")
)

func (n *Node) collectGossipContentForPeer(p *discovery.Peer) *proto.State {
	msg := &proto.State{
		FingerprintData:         n.FingerprintData(),
		FingerprintAccusations:  n.AccusationFingerprintBytes(),
		FingerprintView:         n.ViewFingerprintBytes(),
		FingerprintCertificates: n.CertFingerprintBytes(),
	}

	if selfNote := n.view.SelfNote(); selfNote != nil {
		msg.OwnNote = selfNote.ToPbMsg()
	}

	dataDiff, accDiff, viewDiff := n.DivergentSets(p)

	if accDiff {
		msg.AccusationDigests = n.AccusationDigestsUint64()
	}

	if viewDiff {
		msg.CertificateDigests = n.CertDigestsUint64()
		msg.NoteDigests = n.NoteDigestsUint64()
	}

	if dataDiff {
		msg.DataDigests = n.DataDigestsUint64()
	}

	return msg
}

func (n *Node) setProtocol(pr protocol) {
	n.protocolMutex.Lock()
	defer n.protocolMutex.Unlock()

	n.p = pr
}

func (n *Node) protocol() protocol {
	n.protocolMutex.RLock()
	defer n.protocolMutex.RUnlock()

	return n.p
}

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

// Expose so that client can set new handler directly
func (n *Node) SetMsgHandler(newHandler processMsg) {
	n.msgHandlerMutex.Lock()
	defer n.msgHandlerMutex.Unlock()

	n.msgHandler = newHandler
}

func (n *Node) getMsgHandler() processMsg {
	n.msgHandlerMutex.RLock()
	defer n.msgHandlerMutex.RUnlock()

	return n.msgHandler
}

// Expose so that client can set new handler directly
func (n *Node) SetStreamHandler(newHandler streamMsg) {
	n.streamHandlerMutex.Lock()
	defer n.streamHandlerMutex.Unlock()

	n.streamHandler = newHandler
}

func (n *Node) getStreamHandler() streamMsg {
	n.streamHandlerMutex.RLock()
	defer n.streamHandlerMutex.RUnlock()

	return n.streamHandler
}
