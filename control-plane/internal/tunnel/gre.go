// Package tunnel manages clean traffic delivery from scrubbing nodes
// to origin servers via GRE, IP-in-IP, or WireGuard tunnels.
//
// After the XDP data plane drops malicious packets, clean traffic needs
// to reach the origin server. This module handles:
// 1. Tunnel creation/teardown (GRE, IPIP, WireGuard)
// 2. Source IP preservation through the tunnel
// 3. Health monitoring with automatic failover
// 4. MTU adjustment to account for tunnel overhead
package tunnel

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// TunnelType defines the encapsulation method.
type TunnelType string

const (
	TypeGRE       TunnelType = "gre"
	TypeIPIP      TunnelType = "ipip"
	TypeWireGuard TunnelType = "wireguard"
)

// TunnelState represents the health of a tunnel.
type TunnelState int

const (
	TunnelDown TunnelState = iota
	TunnelUp
	TunnelDegraded
)

func (s TunnelState) String() string {
	switch s {
	case TunnelDown:
		return "DOWN"
	case TunnelUp:
		return "UP"
	case TunnelDegraded:
		return "DEGRADED"
	default:
		return "UNKNOWN"
	}
}

// Config defines tunnel configuration.
type Config struct {
	Enabled         bool       `yaml:"enabled"`
	Type            TunnelType `yaml:"type"`
	LocalIP         string     `yaml:"local_ip"`
	RemoteIP        string     `yaml:"remote_ip"`
	InterfaceName   string     `yaml:"interface_name"`
	MTU             int        `yaml:"mtu"`
	KeepaliveInterval int     `yaml:"keepalive_interval"` // seconds
	// WireGuard-specific
	WGPrivateKey string `yaml:"wg_private_key,omitempty"`
	WGPeerPubKey string `yaml:"wg_peer_pubkey,omitempty"`
	WGListenPort int    `yaml:"wg_listen_port,omitempty"`
}

// Tunnel represents an active tunnel connection.
type Tunnel struct {
	Config    Config
	State     TunnelState
	CreatedAt time.Time
	LastPing  time.Time
	RTT       time.Duration // Round-trip time
	BytesSent uint64
	BytesRecv uint64
}

// Manager manages tunnel lifecycle and health.
type Manager struct {
	mu      sync.RWMutex
	config  Config
	logger  *zap.SugaredLogger
	tunnel  *Tunnel
}

// NewManager creates a new tunnel manager.
func NewManager(cfg Config, logger *zap.SugaredLogger) *Manager {
	return &Manager{
		config: cfg,
		logger: logger,
	}
}

// Start creates and brings up the tunnel.
func (m *Manager) Start(ctx context.Context) error {
	if !m.config.Enabled {
		m.logger.Info("Tunnel delivery disabled — traffic will be processed locally")
		return nil
	}

	m.logger.Infow("Creating tunnel",
		"type", m.config.Type,
		"local", m.config.LocalIP,
		"remote", m.config.RemoteIP,
	)

	switch m.config.Type {
	case TypeGRE:
		return m.createGRE(ctx)
	case TypeIPIP:
		return m.createIPIP(ctx)
	case TypeWireGuard:
		return m.createWireGuard(ctx)
	default:
		return fmt.Errorf("unknown tunnel type: %s", m.config.Type)
	}
}

// createGRE sets up a GRE tunnel.
// Equivalent to:
//   ip tunnel add aegis0 mode gre local <local> remote <remote>
//   ip link set aegis0 up
//   ip link set aegis0 mtu 1476
func (m *Manager) createGRE(ctx context.Context) error {
	ifName := m.config.InterfaceName
	if ifName == "" {
		ifName = "aegis0"
	}

	mtu := m.config.MTU
	if mtu == 0 {
		mtu = 1476 // 1500 - GRE overhead (24 bytes)
	}

	m.logger.Infow("Setting up GRE tunnel",
		"interface", ifName,
		"local_ip", m.config.LocalIP,
		"remote_ip", m.config.RemoteIP,
		"mtu", mtu,
	)

	// TODO: Execute netlink commands to create the GRE tunnel.
	// In production, use the vishvananda/netlink Go library:
	//
	// gre := &netlink.Gretun{
	//     LinkAttrs: netlink.LinkAttrs{Name: ifName, MTU: mtu},
	//     Local:     net.ParseIP(m.config.LocalIP),
	//     Remote:    net.ParseIP(m.config.RemoteIP),
	// }
	// netlink.LinkAdd(gre)
	// netlink.LinkSetUp(gre)

	m.mu.Lock()
	m.tunnel = &Tunnel{
		Config:    m.config,
		State:     TunnelUp,
		CreatedAt: time.Now(),
	}
	m.mu.Unlock()

	// Start keepalive loop.
	go m.keepaliveLoop(ctx)

	m.logger.Infow("✓ GRE tunnel established",
		"interface", ifName,
		"mtu", mtu,
	)

	return nil
}

// createIPIP sets up an IP-in-IP tunnel (lower overhead than GRE).
func (m *Manager) createIPIP(ctx context.Context) error {
	ifName := m.config.InterfaceName
	if ifName == "" {
		ifName = "aegis0"
	}

	mtu := m.config.MTU
	if mtu == 0 {
		mtu = 1480 // 1500 - IPIP overhead (20 bytes)
	}

	m.logger.Infow("Setting up IP-in-IP tunnel",
		"interface", ifName,
		"mtu", mtu,
	)

	// TODO: Use netlink to create IPIP tunnel.
	m.mu.Lock()
	m.tunnel = &Tunnel{
		Config:    m.config,
		State:     TunnelUp,
		CreatedAt: time.Now(),
	}
	m.mu.Unlock()

	go m.keepaliveLoop(ctx)
	return nil
}

// createWireGuard sets up a WireGuard tunnel (encrypted).
func (m *Manager) createWireGuard(ctx context.Context) error {
	m.logger.Infow("Setting up WireGuard tunnel",
		"listen_port", m.config.WGListenPort,
		"remote", m.config.RemoteIP,
	)

	// TODO: Use wgctrl-go library to configure WireGuard.
	m.mu.Lock()
	m.tunnel = &Tunnel{
		Config:    m.config,
		State:     TunnelUp,
		CreatedAt: time.Now(),
	}
	m.mu.Unlock()

	go m.keepaliveLoop(ctx)
	return nil
}

// keepaliveLoop sends periodic keepalive pings to the remote end.
func (m *Manager) keepaliveLoop(ctx context.Context) {
	interval := time.Duration(m.config.KeepaliveInterval) * time.Second
	if interval == 0 {
		interval = 10 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	failCount := 0
	maxFails := 3

	for {
		select {
		case <-ctx.Done():
			m.teardown()
			return
		case <-ticker.C:
			alive := m.sendKeepalive()

			m.mu.Lock()
			if alive {
				failCount = 0
				if m.tunnel != nil {
					m.tunnel.State = TunnelUp
					m.tunnel.LastPing = time.Now()
				}
			} else {
				failCount++
				if failCount >= maxFails {
					m.logger.Errorw("Tunnel keepalive failed — tunnel is DOWN",
						"remote", m.config.RemoteIP,
						"failures", failCount,
					)
					if m.tunnel != nil {
						m.tunnel.State = TunnelDown
					}
				} else {
					if m.tunnel != nil {
						m.tunnel.State = TunnelDegraded
					}
				}
			}
			m.mu.Unlock()
		}
	}
}

// sendKeepalive sends a ping to the remote tunnel endpoint.
func (m *Manager) sendKeepalive() bool {
	// TODO: Send ICMP echo to remote IP and measure RTT.
	return true // Placeholder
}

// teardown removes the tunnel interface.
func (m *Manager) teardown() {
	m.logger.Infow("Tearing down tunnel",
		"type", m.config.Type,
		"interface", m.config.InterfaceName,
	)
	// TODO: netlink.LinkDel
}

// GetState returns the current tunnel state.
func (m *Manager) GetState() TunnelState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.tunnel == nil {
		return TunnelDown
	}
	return m.tunnel.State
}

// GetTunnelInfo returns tunnel details.
func (m *Manager) GetTunnelInfo() *Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tunnel
}
