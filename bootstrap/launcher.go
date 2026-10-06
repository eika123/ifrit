package bootstrap

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"sync"

	_ "net/http/pprof"

	"github.com/joonnna/ifrit/cauth"
	"github.com/joonnna/ifrit/worm"

	log "github.com/inconshreveable/log15"
)

const (
	port = 5632
)

type Config struct {
	CaAddr string

	CertPath     string `default:"./certs"`
	Host         string `default:"localhost"`
	Port         string `default:"8321"`
	NumRings     uint32 `default:"3"`
	NumBootNodes uint32 `default:"5"`
}

type ClientFactory func() (Application, error)

type Launcher struct {
	cfg                  *Config
	applicationList      []Application
	applicationListMutex sync.RWMutex

	ca *cauth.Ca

	listener   net.Listener
	httpServer *http.Server

	// TODO naming things...
	worm *worm.Worm

	clientFactory ClientFactory
}

type Application interface {
	Start()
	Stop()
	Addr() string
}

func NewLauncher(factory ClientFactory, w *worm.Worm, cfg *Config) (*Launcher, error) {
	if cfg == nil {
		cfg = &Config{
			CertPath:     "./certs",
			Host:         "localhost",
			Port:         "8321",
			NumRings:     3,
			NumBootNodes: 5,
		}
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return nil, err
	}

	var ca *cauth.Ca
	// Only spin up an embedded CA if no external CA address is provided
	if cfg.CaAddr == "" {
		var err error
		ca, err = cauth.NewCa(cfg.CertPath)
		if err != nil {
			listener.Close()
			return nil, err
		}
		if err := ca.NewGroup(cfg.NumRings, cfg.NumBootNodes); err != nil {
			listener.Close()
			return nil, err
		}
	}

	return &Launcher{
		cfg:           cfg,
		ca:            ca,
		listener:      listener,
		worm:          w,
		clientFactory: factory,
	}, nil
}

func (l *Launcher) Start() {
	if l.ca != nil {
		host := l.cfg.Host
		if host == "" {
			host = "localhost"
		}
		port := l.cfg.Port
		if port == "" {
			port = "8321"
		}
		go l.ca.Start(host, port)
	}

	if l.worm != nil {
		log.Info("Starting worm")
		l.worm.Start()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/addApplication", l.addApplicationHandler)

	s := &http.Server{
		Handler: mux,
	}

	l.httpServer = s

	l.httpServer.Serve(l.listener)
}

func (l *Launcher) ShutDown() {
	l.shutDownApplications()
	if l.worm != nil {
		l.worm.Stop()
	}
	l.httpServer.Close()

	if l.ca != nil {
		l.ca.Shutdown()
	}
}

func (l *Launcher) Addr() string {
	return l.listener.Addr().String()
}

func (l *Launcher) shutDownApplications() {
	l.applicationListMutex.RLock()
	defer l.applicationListMutex.RUnlock()

	for _, n := range l.applicationList {
		n.Stop()
	}
}

func (l *Launcher) startApplication() {
	l.applicationListMutex.Lock()
	defer l.applicationListMutex.Unlock()

	if l.clientFactory == nil {
		log.Error("No client factory configured on Launcher")
		return
	}

	client, err := l.clientFactory()
	if err != nil {
		log.Error("Failed to create client application", "err", err)
		return
	}

	go client.Start()

	l.applicationList = append(l.applicationList, client)
}

func (l *Launcher) addApplicationHandler(w http.ResponseWriter, r *http.Request) {
	io.Copy(ioutil.Discard, r.Body)
	defer r.Body.Close()

	l.startApplication()
}
