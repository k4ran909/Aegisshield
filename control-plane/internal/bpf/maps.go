// Package bpf provides an enhanced BPF map manager with helper types.
//
// This is an expanded version of the original maps.go, adding:
// - Stats struct for Go-side representation of XDP counters
// - Per-second rate calculation
// - Blocked IP listing
// - Threshold update helpers
package bpf

import (
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Stats holds a snapshot of all XDP statistics, aggregated across CPUs.
type Stats struct {
	RxPackets        uint64 `json:"rx_packets"`
	TotalDrops       uint64 `json:"total_drops"`
	TotalPassed      uint64 `json:"total_passed"`
	TxPackets        uint64 `json:"tx_packets"`
	BlocklistDrops   uint64 `json:"blocklist_drops"`
	ACLDrops         uint64 `json:"acl_drops"`
	UDPDropsPerSec   uint64 `json:"udp_drops_per_sec"`
	SYNDropsPerSec   uint64 `json:"syn_drops_per_sec"`
	ICMPDropsPerSec  uint64 `json:"icmp_drops_per_sec"`
	DNSAmpDrops      uint64 `json:"dns_amp_drops"`
	GREDrops         uint64 `json:"gre_drops"`
	FragDrops        uint64 `json:"frag_drops"`
	ConntrackBypass  uint64 `json:"conntrack_bypass"`
	SYNCookiesSent   uint64 `json:"syn_cookies_sent"`
	TotalDropsPerSec uint64 `json:"total_drops_per_sec"`
	// Per-second rates (calculated by Manager)
	RxPPS     uint64 `json:"rx_pps"`
	DropPPS   uint64 `json:"drop_pps"`
	Timestamp int64  `json:"timestamp"`
}

// Manager controls interaction with pinned BPF maps.
type Manager struct {
	mu            sync.RWMutex
	logger        *zap.SugaredLogger
	pinPath       string
	prevStats     *Stats
	prevTimestamp time.Time
	blockedIPs    map[string]time.Time // IP → block time
}

// NewManager creates a new BPF map manager.
func NewManager(pinPath string, logger *zap.SugaredLogger) *Manager {
	return &Manager{
		pinPath:    pinPath,
		logger:     logger,
		blockedIPs: make(map[string]time.Time),
	}
}

// ReadStats reads and aggregates per-CPU stats from BPF maps.
func (m *Manager) ReadStats() (*Stats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// TODO: Open pinned PerCpuArray at m.pinPath + "/STATS"
	// and sum values across all CPUs for each stat index.
	//
	// For now, return a zeroed struct.
	stats := &Stats{
		Timestamp: time.Now().Unix(),
	}

	// Calculate PPS from delta.
	if m.prevStats != nil {
		elapsed := time.Since(m.prevTimestamp).Seconds()
		if elapsed > 0 {
			stats.RxPPS = uint64(float64(stats.RxPackets-m.prevStats.RxPackets) / elapsed)
			stats.DropPPS = uint64(float64(stats.TotalDrops-m.prevStats.TotalDrops) / elapsed)
		}
	}

	m.prevStats = stats
	m.prevTimestamp = time.Now()

	return stats, nil
}

// BlockIP adds an IP to the XDP blocklist.
func (m *Manager) BlockIP(ip net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ipStr := ip.String()

	// TODO: Open pinned HashMap at m.pinPath + "/BLOCKLIST"
	// and insert the IP.

	m.blockedIPs[ipStr] = time.Now()
	m.logger.Infow("🔒 Blocked IP in XDP", "ip", ipStr)

	return nil
}

// UnblockIP removes an IP from the XDP blocklist.
func (m *Manager) UnblockIP(ip net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ipStr := ip.String()

	// TODO: Open pinned HashMap and remove the IP.
	delete(m.blockedIPs, ipStr)
	m.logger.Infow("🔓 Unblocked IP in XDP", "ip", ipStr)

	return nil
}

// ListBlockedIPs returns all currently blocked IPs.
func (m *Manager) ListBlockedIPs() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ips := make([]string, 0, len(m.blockedIPs))
	for ip := range m.blockedIPs {
		ips = append(ips, ip)
	}
	return ips, nil
}

// UpdateThresholds pushes new rate limit thresholds to the XDP program.
func (m *Manager) UpdateThresholds(
	udpPPS uint64,
	synFlood uint64,
	icmpPPS uint64,
	dnsMaxSize uint16,
) error {
	m.logger.Infow("Updating XDP thresholds",
		"udp_pps", udpPPS,
		"syn_flood", synFlood,
		"icmp_pps", icmpPPS,
		"dns_max", dnsMaxSize,
	)

	// TODO: Open pinned Array at m.pinPath + "/CONFIG"
	// and write GlobalConfig struct.

	return nil
}

// Close releases any open map file descriptors.
func (m *Manager) Close() error {
	return nil
}

func init() {
	// Ensure Stats implements json serialization.
	_ = fmt.Sprintf("%v", Stats{})
}
