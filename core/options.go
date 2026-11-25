package core

import (
	"strings"
	"time"
)

// Options configures a Fireflies Node at construction time.
// Zero-valued fields fall back to DefaultOptions() when passed to NewNode.
type Options struct {
	GossipInterval         time.Duration
	MonitorInterval        time.Duration
	ViewUpdateInterval     time.Duration
	RemovalTimeout         time.Duration
	PingLimit              uint32
	PingsPerInterval       int
	ReconciliationStrategy string
	EntryAddrs             []string
	SyncConfig             SyncConfig
	UseViz                 bool
	VizAddr                string
	VizUpdateInterval      time.Duration
}

// DefaultOptions returns standard Node configuration defaults.
func DefaultOptions() Options {
	return Options{
		GossipInterval:         10 * time.Second,
		MonitorInterval:        10 * time.Second,
		ViewUpdateInterval:     10 * time.Second,
		RemovalTimeout:         60 * time.Second,
		PingLimit:              3,
		PingsPerInterval:       3,
		ReconciliationStrategy: "riblt",
		SyncConfig:             DefaultSyncConfig(),
		VizUpdateInterval:      10 * time.Second,
	}
}

func (o Options) withDefaults() Options {
	def := DefaultOptions()
	if o.GossipInterval <= 0 {
		o.GossipInterval = def.GossipInterval
	}
	if o.MonitorInterval <= 0 {
		o.MonitorInterval = def.MonitorInterval
	}
	if o.ViewUpdateInterval <= 0 {
		o.ViewUpdateInterval = def.ViewUpdateInterval
	}
	if o.RemovalTimeout <= 0 {
		o.RemovalTimeout = def.RemovalTimeout
	}
	if o.PingLimit == 0 {
		o.PingLimit = def.PingLimit
	}
	if o.PingsPerInterval <= 0 {
		o.PingsPerInterval = def.PingsPerInterval
	}
	o.ReconciliationStrategy = strings.ToLower(strings.TrimSpace(o.ReconciliationStrategy))
	if o.ReconciliationStrategy == "" {
		o.ReconciliationStrategy = def.ReconciliationStrategy
	}
	if o.SyncConfig.Timeout <= 0 && o.SyncConfig.MaxItemBytes == 0 {
		o.SyncConfig = def.SyncConfig
	} else if o.SyncConfig.Timeout <= 0 {
		o.SyncConfig.Timeout = def.SyncConfig.Timeout
	}
	if o.VizUpdateInterval <= 0 {
		o.VizUpdateInterval = def.VizUpdateInterval
	}
	return o
}
