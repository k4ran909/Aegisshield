// Package bpf manages pinned eBPF maps shared with the XDP data plane.
package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

const (
	// Shared stat indices (must match data-plane/aegis-common/src/lib.rs).
	statRX              = 0
	statDrop            = 1
	statPass            = 2
	statTX              = 3
	statBlocklistDrop   = 4
	statACLDrop         = 5
	statUDPDrop         = 6
	statSYNDrop         = 7
	statICMPDrop        = 8
	statDNSDrop         = 9
	statGREDrop         = 10
	statFragDrop        = 11
	statConntrackBypass = 12
	statSYNCookiesSent  = 13
)

// Stats holds a snapshot of XDP counters and computed rates.
type Stats struct {
	RxPackets            uint64 `json:"rx_packets"`
	TotalDrops           uint64 `json:"total_drops"`
	TotalPassed          uint64 `json:"total_passed"`
	TxPackets            uint64 `json:"tx_packets"`
	BlocklistDrops       uint64 `json:"blocklist_drops"`
	ACLDrops             uint64 `json:"acl_drops"`
	UDPDrops             uint64 `json:"udp_drops"`
	SYNDrops             uint64 `json:"syn_drops"`
	ICMPDrops            uint64 `json:"icmp_drops"`
	DNSAmpDrops          uint64 `json:"dns_amp_drops"`
	GREDrops             uint64 `json:"gre_drops"`
	FragDrops            uint64 `json:"frag_drops"`
	ConntrackBypass      uint64 `json:"conntrack_bypass"`
	SYNCookiesSent       uint64 `json:"syn_cookies_sent"`
	TotalDropsPerSec     uint64 `json:"total_drops_per_sec"`
	BlocklistDropsPerSec uint64 `json:"blocklist_drops_per_sec"`
	UDPDropsPerSec       uint64 `json:"udp_drops_per_sec"`
	SYNDropsPerSec       uint64 `json:"syn_drops_per_sec"`
	ICMPDropsPerSec      uint64 `json:"icmp_drops_per_sec"`
	DNSDropsPerSec       uint64 `json:"dns_drops_per_sec"`
	GREDropsPerSec       uint64 `json:"gre_drops_per_sec"`
	FragDropsPerSec      uint64 `json:"frag_drops_per_sec"`
	RxPPS                uint64 `json:"rx_pps"`
	DropPPS              uint64 `json:"drop_pps"`
	Timestamp            int64  `json:"timestamp"`
}

// globalConfigValue must match Rust GlobalConfig layout.
type globalConfigValue struct {
	UDPRateThreshold   uint64
	SYNFloodThreshold  uint64
	ICMPRateThreshold  uint64
	DNSMaxResponseSize uint16
	FragmentPolicy     uint8
	ConntrackEnabled   uint8
	SYNCookieSecret    uint32
	Pad                [8]byte
}

// Manager controls interaction with pinned BPF maps.
type Manager struct {
	mu            sync.RWMutex
	logger        *zap.SugaredLogger
	pinPath       string
	prevStats     *Stats
	prevTimestamp time.Time

	statsMap     *ebpf.Map
	blocklistMap *ebpf.Map
	configMap    *ebpf.Map
}

// NewManager creates a new BPF map manager.
func NewManager(pinPath string, logger *zap.SugaredLogger) *Manager {
	if runtime.NumCPU() <= 0 {
		logger.Warn("failed to determine CPU count, proceeding with map lookup sizing from kernel")
	}

	return &Manager{
		pinPath: pinPath,
		logger:  logger,
	}
}

// ReadStats reads and aggregates per-CPU stats from the pinned STATS map.
func (m *Manager) ReadStats() (*Stats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureStatsMap(); err != nil {
		return nil, err
	}

	now := time.Now()
	stats := &Stats{
		Timestamp: now.Unix(),
	}

	raw, err := m.readAllStatTotals()
	if err != nil {
		return nil, err
	}

	stats.RxPackets = raw[statRX]
	stats.TotalDrops = raw[statDrop]
	stats.TotalPassed = raw[statPass]
	stats.TxPackets = raw[statTX]
	stats.BlocklistDrops = raw[statBlocklistDrop]
	stats.ACLDrops = raw[statACLDrop]
	stats.UDPDrops = raw[statUDPDrop]
	stats.SYNDrops = raw[statSYNDrop]
	stats.ICMPDrops = raw[statICMPDrop]
	stats.DNSAmpDrops = raw[statDNSDrop]
	stats.GREDrops = raw[statGREDrop]
	stats.FragDrops = raw[statFragDrop]
	stats.ConntrackBypass = raw[statConntrackBypass]
	stats.SYNCookiesSent = raw[statSYNCookiesSent]

	if m.prevStats != nil && !m.prevTimestamp.IsZero() {
		elapsed := now.Sub(m.prevTimestamp).Seconds()
		if elapsed > 0 {
			stats.RxPPS = rate(stats.RxPackets, m.prevStats.RxPackets, elapsed)
			stats.DropPPS = rate(stats.TotalDrops, m.prevStats.TotalDrops, elapsed)
			stats.TotalDropsPerSec = stats.DropPPS
			stats.BlocklistDropsPerSec = rate(stats.BlocklistDrops, m.prevStats.BlocklistDrops, elapsed)
			stats.UDPDropsPerSec = rate(stats.UDPDrops, m.prevStats.UDPDrops, elapsed)
			stats.SYNDropsPerSec = rate(stats.SYNDrops, m.prevStats.SYNDrops, elapsed)
			stats.ICMPDropsPerSec = rate(stats.ICMPDrops, m.prevStats.ICMPDrops, elapsed)
			stats.DNSDropsPerSec = rate(stats.DNSAmpDrops, m.prevStats.DNSAmpDrops, elapsed)
			stats.GREDropsPerSec = rate(stats.GREDrops, m.prevStats.GREDrops, elapsed)
			stats.FragDropsPerSec = rate(stats.FragDrops, m.prevStats.FragDrops, elapsed)
		}
	}

	m.prevStats = cloneStats(stats)
	m.prevTimestamp = now
	return stats, nil
}

// BlockIP adds an IP to the XDP blocklist with expiry.
// duration <= 0 means permanent.
func (m *Manager) BlockIP(ip net.IP, duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureBlocklistMap(); err != nil {
		return err
	}

	key, err := ipToU32(ip)
	if err != nil {
		return err
	}

	var expiryNs uint64
	if duration > 0 {
		nowNs, err := monotonicNowNS()
		if err != nil {
			return fmt.Errorf("read CLOCK_MONOTONIC: %w", err)
		}
		expiryNs = nowNs + uint64(duration.Nanoseconds())
	}

	if err := m.blocklistMap.Update(key, expiryNs, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update blocklist: %w", err)
	}

	m.logger.Infow("Blocked IP in XDP", "ip", ip.String(), "duration", duration)
	return nil
}

// UnblockIP removes an IP from the XDP blocklist.
func (m *Manager) UnblockIP(ip net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureBlocklistMap(); err != nil {
		return err
	}

	key, err := ipToU32(ip)
	if err != nil {
		return err
	}

	if err := m.blocklistMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete blocklist key: %w", err)
	}

	m.logger.Infow("Unblocked IP in XDP", "ip", ip.String())
	return nil
}

// ListBlockedIPs returns all currently blocked (non-expired) IPv4 addresses.
func (m *Manager) ListBlockedIPs() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureBlocklistMap(); err != nil {
		return nil, err
	}

	nowNs, err := monotonicNowNS()
	if err != nil {
		return nil, fmt.Errorf("read CLOCK_MONOTONIC: %w", err)
	}
	var stale []uint32
	var ips []string

	it := m.blocklistMap.Iterate()
	var key uint32
	var expiry uint64
	for it.Next(&key, &expiry) {
		if expiry != 0 && expiry < nowNs {
			stale = append(stale, key)
			continue
		}
		ips = append(ips, u32ToIP(key).String())
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate blocklist: %w", err)
	}

	for _, k := range stale {
		_ = m.blocklistMap.Delete(k)
	}

	sort.Strings(ips)
	return ips, nil
}

// UpdateThresholds pushes new thresholds to the XDP CONFIG map.
func (m *Manager) UpdateThresholds(
	udpPPS uint64,
	synFlood uint64,
	icmpPPS uint64,
	dnsMaxSize uint16,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureConfigMap(); err != nil {
		return err
	}

	cfg := globalConfigValue{
		UDPRateThreshold:   udpPPS,
		SYNFloodThreshold:  synFlood,
		ICMPRateThreshold:  icmpPPS,
		DNSMaxResponseSize: dnsMaxSize,
		FragmentPolicy:     1,
		ConntrackEnabled:   1,
	}

	var existing globalConfigValue
	if err := m.configMap.Lookup(uint32(0), &existing); err == nil {
		cfg.FragmentPolicy = existing.FragmentPolicy
		cfg.ConntrackEnabled = existing.ConntrackEnabled
		cfg.SYNCookieSecret = existing.SYNCookieSecret
	}

	if err := m.configMap.Update(uint32(0), cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update config map: %w", err)
	}

	m.logger.Infow("Updated XDP thresholds",
		"udp_pps", udpPPS,
		"syn_flood", synFlood,
		"icmp_pps", icmpPPS,
		"dns_max", dnsMaxSize,
	)
	return nil
}

// Close releases map file descriptors.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	if m.statsMap != nil {
		if err := m.statsMap.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.statsMap = nil
	}
	if m.blocklistMap != nil {
		if err := m.blocklistMap.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.blocklistMap = nil
	}
	if m.configMap != nil {
		if err := m.configMap.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.configMap = nil
	}

	return firstErr
}

func (m *Manager) ensureStatsMap() error {
	if m.statsMap != nil {
		return nil
	}

	mp, err := ebpf.LoadPinnedMap(filepath.Join(m.pinPath, "STATS"), nil)
	if err != nil {
		return fmt.Errorf("load pinned STATS map: %w", err)
	}
	m.statsMap = mp
	return nil
}

func (m *Manager) ensureBlocklistMap() error {
	if m.blocklistMap != nil {
		return nil
	}

	mp, err := ebpf.LoadPinnedMap(filepath.Join(m.pinPath, "BLOCKLIST"), nil)
	if err != nil {
		return fmt.Errorf("load pinned BLOCKLIST map: %w", err)
	}
	m.blocklistMap = mp
	return nil
}

func (m *Manager) ensureConfigMap() error {
	if m.configMap != nil {
		return nil
	}

	mp, err := ebpf.LoadPinnedMap(filepath.Join(m.pinPath, "CONFIG"), nil)
	if err != nil {
		return fmt.Errorf("load pinned CONFIG map: %w", err)
	}
	m.configMap = mp
	return nil
}

func (m *Manager) readAllStatTotals() (map[int]uint64, error) {
	out := make(map[int]uint64, 16)
	for idx := 0; idx < 16; idx++ {
		value, err := m.readPerCPUCounter(uint32(idx))
		if err != nil {
			return nil, fmt.Errorf("read stat index %d: %w", idx, err)
		}
		out[idx] = value
	}
	return out, nil
}

func (m *Manager) readPerCPUCounter(index uint32) (uint64, error) {
	raw, err := m.statsMap.LookupBytes(index)
	if err != nil {
		return 0, err
	}
	if len(raw)%8 != 0 {
		return 0, fmt.Errorf("unexpected per-cpu value size: %d", len(raw))
	}

	var sum uint64
	for i := 0; i < len(raw); i += 8 {
		sum += binary.LittleEndian.Uint64(raw[i : i+8])
	}
	return sum, nil
}

func ipToU32(ip net.IP) (uint32, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("only IPv4 is supported: %q", ip.String())
	}
	return binary.BigEndian.Uint32(ip4), nil
}

func u32ToIP(v uint32) net.IP {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IPv4(b[0], b[1], b[2], b[3])
}

func rate(curr, prev uint64, elapsedSeconds float64) uint64 {
	if elapsedSeconds <= 0 || curr < prev {
		return 0
	}
	return uint64(float64(curr-prev) / elapsedSeconds)
}

func cloneStats(in *Stats) *Stats {
	if in == nil {
		return nil
	}
	cp := *in
	return &cp
}
