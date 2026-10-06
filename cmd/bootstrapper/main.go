package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"

	_ "net/http/pprof"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit"
	"github.com/joonnna/ifrit/bootstrap"
)

type EnvConfig struct {
	Hostname       string
	CaAddr         string
	CryptoUnitPath string
	TCPPort        int
	UDPPort        int
}

func mustGetEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Crit("FATAL: Required environment variable missing", "key", key)
		panic(fmt.Sprintf("💥 FATAL: Missing required environment variable [%s]", key))
	}
	return val
}

func mustGetEnvInt(key string) int {
	valStr := mustGetEnv(key)
	val, err := strconv.Atoi(valStr)
	if err != nil {
		log.Crit("FATAL: Environment variable is not a valid integer", "key", key, "val", valStr, "err", err)
		panic(fmt.Sprintf("💥 FATAL: Environment variable [%s='%s'] must be a valid integer: %v", key, valStr, err))
	}
	return val
}

func getEnvOr(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getEnvIntOr(key string, fallback int) int {
	if valStr := os.Getenv(key); valStr != "" {
		if val, err := strconv.Atoi(valStr); err == nil {
			return val
		}
		log.Crit("FATAL: Environment variable is not a valid integer", "key", key, "val", valStr)
		panic(fmt.Sprintf("💥 FATAL: Environment variable [%s='%s'] must be a valid integer", key, valStr))
	}
	return fallback
}

func LoadEnvConfig() *EnvConfig {
	return &EnvConfig{
		Hostname:       getEnvOr("IFRIT_HOSTNAME", "localhost"),
		CaAddr:         getEnvOr("IFRIT_CA_ADDR", ""),
		CryptoUnitPath: getEnvOr("IFRIT_CRYPTO_PATH", "/tmp/ifrit_crypto"),
		TCPPort:        getEnvIntOr("IFRIT_TCP_PORT", 0),
		UDPPort:        getEnvIntOr("IFRIT_UDP_PORT", 0),
	}
}

func NewEnvClientFactory(env *EnvConfig) bootstrap.ClientFactory {
	var count uint64

	return func() (bootstrap.Application, error) {
		id := atomic.AddUint64(&count, 1)

		cfg := &ifrit.Config{
			New:            true,
			Hostname:       env.Hostname,
			CryptoUnitPath: fmt.Sprintf("%s_%d", env.CryptoUnitPath, id),
			TCPPort:        env.TCPPort,
			UDPPort:        env.UDPPort,
		}

		client, err := ifrit.NewClient(cfg)
		if err != nil {
			log.Error("Failed to instantiate Ifrit client", "id", id, "err", err)
			return nil, err
		}

		return client, nil
	}
}

func gossipHandler(data []byte) ([]byte, error) {
	fmt.Println(string(data))
	resp := []byte("This is a gossip response!!!")
	return resp, nil
}

func gossipResponseHandler(data []byte) {
	fmt.Println(string(data))
}

func msgHandler(data []byte) ([]byte, error) {
	fmt.Println(string(data))
	resp := []byte("Got message, here is response!!!")
	return resp, nil
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	r := log.Root()
	h := log.StreamHandler(os.Stdout, log.TerminalFormat())
	r.SetHandler(h)

	envCfg := LoadEnvConfig()
	factory := NewEnvClientFactory(envCfg)

	launcherCfg := &bootstrap.Config{
		CaAddr: envCfg.CaAddr,
	}

	launcher, err := bootstrap.NewLauncher(factory, nil, launcherCfg)
	if err != nil {
		panic(err)
	}

	go launcher.Start()

	channel := make(chan os.Signal, 2)
	signal.Notify(channel, os.Interrupt, syscall.SIGTERM)

	// blocks until a message comes back across the channel
	<-channel

	launcher.ShutDown()
}
