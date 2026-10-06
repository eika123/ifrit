package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/joonnna/ifrit"

	log "github.com/inconshreveable/log15"
)

var (
	errNoAddr = errors.New("No certificate authority address provided, can't continue")
	logger    = log.New("module", "ifritclient/main")
)

func main() {
	var logfile string
	var logHandler log.Handler

	runtime.GOMAXPROCS(runtime.NumCPU())

	args := flag.NewFlagSet("args", flag.ExitOnError)
	args.StringVar(&logfile, "logfile", "", "Log to file.")
	args.Parse(os.Args[1:])

	rootLogger := log.Root()

	if logfile != "" {
		logHandler = log.CallerFileHandler(log.Must.FileHandler(logfile, log.LogfmtFormat()))
	} else {
		logHandler = log.StreamHandler(os.Stdout, log.LogfmtFormat())
	}

	rootLogger.SetHandler(logHandler)

	clientIfrit, err := ifrit.NewClient(&ifrit.Config{
		New:            true,
		Hostname:       "127.0.1.1",
		TCPPort:        2000,
		UDPPort:        3000,
		CryptoUnitPath: "crypto",
	})
	if err != nil {
		panic(err)
	}

	clientIfrit.RegisterMsgHandler(msgHandler)
	go clientIfrit.Start()

	for {
		if len(clientIfrit.Members()) == 0 {
			continue
		}

		addr := clientIfrit.Members()[0]
		ch := clientIfrit.SendTo(addr, []byte("HellO!"))

		time.Sleep(3 * time.Second)
		select {
		case msg := <-ch:
			if msg != nil {
				fmt.Println("Got response from client:", msg)
			} else {
				break
			}
		}
	}

	channel := make(chan os.Signal, 2)
	signal.Notify(channel, os.Interrupt, syscall.SIGTERM)
	<-channel

	if err := clientIfrit.SavePrivateKey(); err != nil {
		panic(err)
	}

	if err := clientIfrit.SaveCertificate(); err != nil {
		panic(err)
	}

	clientIfrit.Stop()
}

func msgHandler(data []byte) ([]byte, error) {
	fmt.Println("Handler!:", string(data))

	return []byte("Return value from handler"), nil
}
