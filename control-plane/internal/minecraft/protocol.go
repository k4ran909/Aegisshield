// Package minecraft implements Minecraft Java Edition protocol-aware
// DDoS filtering. This provides deep packet inspection for MC-specific
// attack vectors: bot join floods, ping floods, null pings, and
// invalid handshake detection.
//
// Minecraft Protocol Reference (Java Edition):
// - Handshake packet (ID 0x00): VarInt length, VarInt packet ID, VarInt protocol version,
//   String server address, UInt16 port, VarInt next state (1=status, 2=login)
// - Status Request (ID 0x00 in status state): Empty
// - Login Start (ID 0x00 in login state): String player name, UUID
package minecraft

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ProtocolState represents the Minecraft connection state.
type ProtocolState int

const (
	StateHandshake ProtocolState = iota
	StateStatus                  // Server list ping
	StateLogin                   // Player login
	StatePlay                    // Active gameplay
)

// ConnectionTracker tracks per-IP Minecraft connection state for bot detection.
type ConnectionTracker struct {
	mu     sync.RWMutex
	logger *zap.SugaredLogger

	// Per-IP connection rate tracking
	connRates map[uint32]*RateCounter
	// Per-IP ping rate tracking
	pingRates map[uint32]*RateCounter
	// Per-IP login rate tracking
	loginRates map[uint32]*RateCounter

	// Thresholds
	maxConnRate  uint64
	maxPingRate  uint64
	maxLoginRate uint64
}

// RateCounter tracks events per second for a single IP.
type RateCounter struct {
	Count     uint64
	WindowStart time.Time
}

// HandshakeResult represents the result of parsing a MC handshake.
type HandshakeResult struct {
	Valid           bool
	ProtocolVersion int32
	ServerAddress   string
	ServerPort      uint16
	NextState       ProtocolState
	Reason          string // If invalid, why
}

// NewConnectionTracker creates a new Minecraft protocol tracker.
func NewConnectionTracker(maxConn, maxPing uint64, logger *zap.SugaredLogger) *ConnectionTracker {
	ct := &ConnectionTracker{
		logger:       logger,
		connRates:    make(map[uint32]*RateCounter),
		pingRates:    make(map[uint32]*RateCounter),
		loginRates:   make(map[uint32]*RateCounter),
		maxConnRate:  maxConn,
		maxPingRate:  maxPing,
		maxLoginRate: maxConn, // Same as conn rate for now
	}

	// Start cleanup goroutine to evict stale entries
	go ct.cleanup()

	return ct
}

// ValidateHandshake parses and validates a raw Minecraft handshake packet.
func ValidateHandshake(data []byte) *HandshakeResult {
	if len(data) < 5 {
		return &HandshakeResult{Valid: false, Reason: "packet too short"}
	}

	offset := 0

	// Read packet length (VarInt)
	packetLen, n := readVarInt(data[offset:])
	if n <= 0 || packetLen <= 0 || packetLen > 1024 {
		return &HandshakeResult{Valid: false, Reason: "invalid packet length"}
	}
	offset += n

	// Read packet ID (VarInt) — must be 0x00 for handshake
	packetID, n := readVarInt(data[offset:])
	if n <= 0 || packetID != 0 {
		return &HandshakeResult{Valid: false, Reason: fmt.Sprintf("invalid packet ID: %d", packetID)}
	}
	offset += n

	// Read protocol version (VarInt)
	protoVersion, n := readVarInt(data[offset:])
	if n <= 0 {
		return &HandshakeResult{Valid: false, Reason: "cannot read protocol version"}
	}
	offset += n

	// Validate known protocol versions (MC 1.7 through 1.21+)
	if protoVersion < 4 || protoVersion > 770 {
		return &HandshakeResult{
			Valid:  false,
			Reason: fmt.Sprintf("unknown protocol version: %d", protoVersion),
		}
	}

	// Read server address (String: VarInt length + UTF-8 bytes)
	addrLen, n := readVarInt(data[offset:])
	if n <= 0 || addrLen <= 0 || addrLen > 255 {
		return &HandshakeResult{Valid: false, Reason: "invalid server address length"}
	}
	offset += n
	if offset+int(addrLen) > len(data) {
		return &HandshakeResult{Valid: false, Reason: "server address exceeds packet"}
	}
	serverAddr := string(data[offset : offset+int(addrLen)])
	offset += int(addrLen)

	// Read server port (UInt16 big-endian)
	if offset+2 > len(data) {
		return &HandshakeResult{Valid: false, Reason: "cannot read server port"}
	}
	serverPort := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Read next state (VarInt) — must be 1 (status) or 2 (login)
	nextState, n := readVarInt(data[offset:])
	if n <= 0 || (nextState != 1 && nextState != 2) {
		return &HandshakeResult{
			Valid:  false,
			Reason: fmt.Sprintf("invalid next state: %d (must be 1 or 2)", nextState),
		}
	}

	return &HandshakeResult{
		Valid:           true,
		ProtocolVersion: protoVersion,
		ServerAddress:   serverAddr,
		ServerPort:      serverPort,
		NextState:       ProtocolState(nextState),
	}
}

// CheckConnectionRate returns true if the IP should be blocked (rate exceeded).
func (ct *ConnectionTracker) CheckConnectionRate(ipU32 uint32) bool {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	rate, exists := ct.connRates[ipU32]
	now := time.Now()

	if !exists || now.Sub(rate.WindowStart) > time.Second {
		ct.connRates[ipU32] = &RateCounter{Count: 1, WindowStart: now}
		return false
	}

	rate.Count++
	return rate.Count > ct.maxConnRate
}

// CheckPingRate returns true if the IP should be blocked for excessive pings.
func (ct *ConnectionTracker) CheckPingRate(ipU32 uint32) bool {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	rate, exists := ct.pingRates[ipU32]
	now := time.Now()

	if !exists || now.Sub(rate.WindowStart) > time.Second {
		ct.pingRates[ipU32] = &RateCounter{Count: 1, WindowStart: now}
		return false
	}

	rate.Count++
	return rate.Count > ct.maxPingRate
}

// cleanup evicts stale entries from rate tracking maps every 30 seconds.
func (ct *ConnectionTracker) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ct.mu.Lock()
		now := time.Now()
		threshold := 30 * time.Second

		for ip, rate := range ct.connRates {
			if now.Sub(rate.WindowStart) > threshold {
				delete(ct.connRates, ip)
			}
		}
		for ip, rate := range ct.pingRates {
			if now.Sub(rate.WindowStart) > threshold {
				delete(ct.pingRates, ip)
			}
		}
		for ip, rate := range ct.loginRates {
			if now.Sub(rate.WindowStart) > threshold {
				delete(ct.loginRates, ip)
			}
		}
		ct.mu.Unlock()
	}
}

// readVarInt decodes a Minecraft VarInt from raw bytes.
// Returns the value and number of bytes consumed (0 on error).
func readVarInt(data []byte) (int32, int) {
	var result int32
	var numRead int

	for {
		if numRead >= 5 || numRead >= len(data) {
			return 0, 0 // VarInt too long or not enough data
		}

		b := data[numRead]
		result |= int32(b&0x7F) << (7 * numRead)
		numRead++

		if b&0x80 == 0 {
			break
		}
	}

	return result, numRead
}
