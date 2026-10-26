package comm

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"

	log "github.com/inconshreveable/log15"
	pb "github.com/joonnna/ifrit/protobuf"
)

var (
	errNilCert = errors.New("Given certificate was nil")
	errNilPriv = errors.New("Given private key was nil")
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
