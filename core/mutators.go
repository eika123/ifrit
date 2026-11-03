package core

import (
	"errors"
	"time"
)

var (
	errNotFound     = errors.New("No node info found")
	errPeerNotFound = errors.New("No peer info found")
)

func (n *Node) SetAdversarialPolicy(p *AdversarialPolicy) {
	n.adversaryMutex.Lock()
	defer n.adversaryMutex.Unlock()

	n.adversary = p
}

func (n *Node) AdversarialPolicy() *AdversarialPolicy {
	n.adversaryMutex.RLock()
	defer n.adversaryMutex.RUnlock()

	return n.adversary
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
