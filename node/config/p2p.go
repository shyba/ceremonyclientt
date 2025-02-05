package config

import (
	"time"
)

type P2PConfig struct {
	D                         int           `yaml:"d"`
	DLo                       int           `yaml:"dLo"`
	DHi                       int           `yaml:"dHi"`
	DScore                    int           `yaml:"dScore"`
	DOut                      int           `yaml:"dOut"`
	HistoryLength             int           `yaml:"historyLength"`
	HistoryGossip             int           `yaml:"historyGossip"`
	DLazy                     int           `yaml:"dLazy"`
	GossipRetransmission      int           `yaml:"gossipRetransmission"`
	HeartbeatInitialDelay     time.Duration `yaml:"heartbeatInitialDelay"`
	HeartbeatInterval         time.Duration `yaml:"heartbeatInterval"`
	FanoutTTL                 time.Duration `yaml:"fanoutTTL"`
	PrunePeers                int           `yaml:"prunePeers"`
	PruneBackoff              time.Duration `yaml:"pruneBackoff"`
	UnsubscribeBackoff        time.Duration `yaml:"unsubscribeBackoff"`
	Connectors                int           `yaml:"connectors"`
	MaxPendingConnections     int           `yaml:"maxPendingConnections"`
	ConnectionTimeout         time.Duration `yaml:"connectionTimeout"`
	DirectConnectTicks        uint64        `yaml:"directConnectTicks"`
	DirectConnectInitialDelay time.Duration `yaml:"directConnectInitialDelay"`
	OpportunisticGraftTicks   uint64        `yaml:"opportunisticGraftTicks"`
	OpportunisticGraftPeers   int           `yaml:"opportunisticGraftPeers"`
	GraftFloodThreshold       time.Duration `yaml:"graftFloodThreshold"`
	MaxIHaveLength            int           `yaml:"maxIHaveLength"`
	MaxIHaveMessages          int           `yaml:"maxIHaveMessages"`
	IWantFollowupTime         time.Duration `yaml:"iWantFollowupTime"`
	BootstrapPeers            []string      `yaml:"bootstrapPeers"`
	ListenMultiaddr           string        `yaml:"listenMultiaddr"`
	PeerPrivKey               string        `yaml:"peerPrivKey"`
	TraceLogFile              string        `yaml:"traceLogFile"`
	Network                   uint8         `yaml:"network"`
	LowWatermarkConnections   int           `yaml:"lowWatermarkConnections"`
	HighWatermarkConnections  int           `yaml:"highWatermarkConnections"`
	DirectPeers               []string      `yaml:"directPeers"`
	GrpcServerRateLimit       int           `yaml:"grpcServerRateLimit"`
	MinBootstrapPeers         int           `yaml:"minBootstrapPeers"`
	BootstrapParallelism      int           `yaml:"bootstrapParallelism"`
	DiscoveryParallelism      int           `yaml:"discoveryParallelism"`
	DiscoveryPeerLookupLimit  int           `yaml:"discoveryPeerLookupLimit"`
	PingTimeout               time.Duration `yaml:"pingTimeout"`
	PingPeriod                time.Duration `yaml:"pingPeriod"`
	PingAttempts              int           `yaml:"pingAttempts"`
	ValidateQueueSize         int           `yaml:"validateQueueSize"`
	ValidateWorkers           int           `yaml:"validateWorkers"`
}
