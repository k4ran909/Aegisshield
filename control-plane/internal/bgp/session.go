// Package bgp provides GoBGP integration for BGP Anycast and Flowspec.
//
// Features:
// - Establish BGP sessions with upstream routers
// - Advertise/withdraw Anycast prefixes based on node health
// - Inject BGP Flowspec rules to divert attack traffic
// - RTBH (Remotely Triggered Black Hole) for emergency upstream filtering
//
// This is an OPTIONAL component — standalone mode works without BGP.
// Requires an ASN and at least a /24 IPv4 prefix from your provider.
package bgp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SessionState represents the BGP session state.
type SessionState int

const (
	StateIdle        SessionState = iota // Not connected
	StateConnect                         // TCP connection in progress
	StateOpenSent                        // OPEN message sent
	StateOpenConfirm                     // OPEN received, waiting for KEEPALIVE
	StateEstablished                     // Session fully established
)

func (s SessionState) String() string {
	switch s {
	case StateIdle:
		return "IDLE"
	case StateConnect:
		return "CONNECT"
	case StateOpenSent:
		return "OPEN_SENT"
	case StateOpenConfirm:
		return "OPEN_CONFIRM"
	case StateEstablished:
		return "ESTABLISHED"
	default:
		return "UNKNOWN"
	}
}

// Config defines BGP session configuration.
type Config struct {
	Enabled       bool   `yaml:"enabled"`
	LocalASN      uint32 `yaml:"local_asn"`
	RouterID      string `yaml:"router_id"`
	ListenPort    int    `yaml:"listen_port"`
	AnycastPrefix string `yaml:"anycast_prefix"` // e.g., "203.0.113.0/24"

	Neighbors []NeighborConfig `yaml:"neighbors"`
}

// NeighborConfig defines a BGP peer.
type NeighborConfig struct {
	Address  string `yaml:"address"`
	PeerASN  uint32 `yaml:"peer_asn"`
	Password string `yaml:"password,omitempty"` // MD5 auth
}

// Manager manages BGP sessions and route announcements.
type Manager struct {
	mu      sync.RWMutex
	config  Config
	logger  *zap.SugaredLogger
	state   SessionState
	healthy bool // Whether this node should advertise routes
}

// NewManager creates a new BGP manager.
func NewManager(cfg Config, logger *zap.SugaredLogger) *Manager {
	return &Manager{
		config:  cfg,
		logger:  logger,
		state:   StateIdle,
		healthy: true,
	}
}

// Start initializes BGP sessions with configured neighbors.
func (m *Manager) Start(ctx context.Context) error {
	if !m.config.Enabled {
		m.logger.Info("BGP is disabled — running in standalone mode")
		return nil
	}

	m.logger.Infow("Starting BGP manager",
		"local_asn", m.config.LocalASN,
		"router_id", m.config.RouterID,
		"anycast_prefix", m.config.AnycastPrefix,
		"neighbors", len(m.config.Neighbors),
	)

	// TODO: Initialize GoBGP server using the gobgpapi package.
	// This requires:
	// 1. Creating a GoBGP server instance
	// 2. Configuring the global ASN and router ID
	// 3. Adding each neighbor with their peer ASN
	// 4. Starting the BGP listener

	// For now, simulate session establishment.
	m.mu.Lock()
	m.state = StateEstablished
	m.mu.Unlock()

	// Announce our Anycast prefix.
	if m.config.AnycastPrefix != "" {
		m.AnnouncePrefix(m.config.AnycastPrefix)
	}

	// Start health check loop.
	go m.healthCheckLoop(ctx)

	return nil
}

// AnnouncePrefix advertises an IP prefix via BGP.
func (m *Manager) AnnouncePrefix(prefix string) {
	m.logger.Infow("📡 Announcing BGP prefix",
		"prefix", prefix,
		"asn", m.config.LocalASN,
	)
	// TODO: Use GoBGP API to add a path with the prefix.
}

// WithdrawPrefix withdraws an IP prefix from BGP.
func (m *Manager) WithdrawPrefix(prefix string) {
	m.logger.Warnw("📡 Withdrawing BGP prefix",
		"prefix", prefix,
		"reason", "node unhealthy or overloaded",
	)
	// TODO: Use GoBGP API to delete the path.
}

// InjectFlowspec pushes a BGP Flowspec rule to upstream routers.
// Flowspec rules allow fine-grained traffic filtering at the ISP level.
//
// Example: Block all UDP traffic from 10.0.0.0/8 to port 25565
func (m *Manager) InjectFlowspec(rule FlowspecRule) error {
	m.logger.Infow("📡 Injecting BGP Flowspec rule",
		"protocol", rule.Protocol,
		"src_prefix", rule.SrcPrefix,
		"dst_prefix", rule.DstPrefix,
		"dst_port", rule.DstPort,
		"action", rule.Action,
	)
	// TODO: Use GoBGP API to inject Flowspec NLRI.
	return nil
}

// TriggerRTBH sends a Remotely Triggered Black Hole for an IP.
// This asks upstream routers to drop ALL traffic to the attacked IP.
// LAST RESORT — drops both good and bad traffic.
func (m *Manager) TriggerRTBH(targetIP string) {
	m.logger.Errorw("☠️ Triggering RTBH (Remotely Triggered Black Hole)",
		"target_ip", targetIP,
		"warning", "ALL traffic to this IP will be dropped upstream",
	)
	// TODO: Announce a /32 host route with BLACKHOLE community.
}

// FlowspecRule defines a BGP Flowspec filtering rule.
type FlowspecRule struct {
	SrcPrefix string // Source IP prefix
	DstPrefix string // Destination IP prefix
	Protocol  string // tcp, udp, icmp
	SrcPort   uint16
	DstPort   uint16
	Action    string // discard, rate-limit, redirect
}

// GetState returns the current BGP session state.
func (m *Manager) GetState() SessionState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// healthCheckLoop monitors node health and withdraws BGP routes on overload.
func (m *Manager) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.WithdrawPrefix(m.config.AnycastPrefix)
			return
		case <-ticker.C:
			// TODO: Check system health metrics (CPU, memory, packet drop rate).
			// If node is overloaded, withdraw routes to shift traffic
			// to other Anycast nodes.
		}
	}
}
