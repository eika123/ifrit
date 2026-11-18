package comm

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"

	pb "github.com/eika123/ifrit/protobuf"
	log "github.com/inconshreveable/log15"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcPeer "google.golang.org/grpc/peer"
)

var (
	errNilCert     = errors.New("Given certificate was nil")
	errNilPriv     = errors.New("Given private key was nil")
	ErrNoPeerInCtx = errors.New("no peer information found in context")
	ErrNoTLSInfo   = errors.New("no TLS info provided in peer context")
	ErrNoCert      = errors.New("no peer certificate present in TLS context")
)

type Comm struct {
	s *gRPCServer
	*gRPCClient
	telemetryLogger TelemetryLogger
}

func NewComm(cert, caCert *x509.Certificate, priv *ecdsa.PrivateKey, l net.Listener, advertisedAddr ...string) (*Comm, error) {
	if cert == nil {
		return nil, errNilCert
	}

	if priv == nil {
		return nil, errNilPriv
	}

	var telemetryLogger TelemetryLogger
	if dbPath := getTelemetryDBPath(); dbPath != "" {
		var err error
		telemetryLogger, err = NewRPCInterfaceLogger(dbPath)
		if err != nil {
			log.Error("Failed to initialize telemetry logger: " + err.Error())
		}
	}

	serverConf := serverConfig(cert, caCert, priv)

	server, err := newServer(serverConf, l, telemetryLogger, advertisedAddr...)
	if err != nil {
		return nil, err
	}

	clientConf := clientConfig(cert, caCert, priv)

	client, err := newClient(clientConf, telemetryLogger)
	if err != nil {
		return nil, err
	}

	return &Comm{
		s:               server,
		gRPCClient:      client,
		telemetryLogger: telemetryLogger,
	}, nil
}

func (c *Comm) Register(p pb.GossipServer) {
	pb.RegisterGossipServer(c.s.rpcServer, p)
}

// RegisterService registers an arbitrary gRPC service implementation on the node's mTLS server.
func (c *Comm) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	c.s.rpcServer.RegisterService(desc, impl)
}

// RegisterGRPC invokes register against the underlying mTLS gRPC server, allowing
// generated Register*Server helpers to attach additional services without exposing *grpc.Server directly.
func (c *Comm) RegisterGRPC(register func(*grpc.Server)) {
	if register != nil {
		register(c.s.rpcServer)
	}
}

// PeerCertFromContext extracts the leaf client certificate from an incoming gRPC mTLS context.
func PeerCertFromContext(ctx context.Context) (*x509.Certificate, error) {
	p, ok := grpcPeer.FromContext(ctx)
	if !ok {
		return nil, ErrNoPeerInCtx
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, ErrNoTLSInfo
	}
	if len(tlsInfo.State.PeerCertificates) < 1 {
		return nil, ErrNoCert
	}
	return tlsInfo.State.PeerCertificates[0], nil
}

func (c *Comm) Start() {
	c.s.start()
}

func (c *Comm) Stop() {

	c.s.stop()

	if c.telemetryLogger != nil {
		_ = c.telemetryLogger.Close()
	}
}

func (c *Comm) Addr() string {
	return c.s.addr()
}

func serverConfig(c, caCert *x509.Certificate, key *ecdsa.PrivateKey) *tls.Config {
	tlsCert := tls.Certificate{
		Certificate: [][]byte{c.Raw},
		PrivateKey:  key,
	}

	conf := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	if caCert == nil {
		conf.ClientAuth = tls.RequestClientCert
	} else {
		pool := x509.NewCertPool()
		pool.AddCert(caCert)
		conf.ClientCAs = pool
		conf.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return conf
}

func clientConfig(c, caCert *x509.Certificate, key *ecdsa.PrivateKey) *tls.Config {
	tlsCert := tls.Certificate{
		Certificate: [][]byte{c.Raw},
		PrivateKey:  key,
	}

	conf := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	if caCert != nil {
		pool := x509.NewCertPool()
		pool.AddCert(caCert)
		conf.RootCAs = pool
	} else {
		conf.InsecureSkipVerify = true
	}

	return conf
}
