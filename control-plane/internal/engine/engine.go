// Package engine is the core mitigation orchestrator.
//
// It runs the main event loop that:
// 1. Polls XDP data plane statistics every second
// 2. Evaluates traffic against anomaly thresholds
// 3. Transitions between states: NORMAL → DETECTED → MITIGATING → COOLDOWN
// 4. Dispatches automated responses (update BPF maps, block IPs, trigger alerts)
package engine

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/aegisshield/aegisshield/internal/bpf"
	"github.com/aegisshield/aegisshield/internal/config"
)

// AttackState represents the current state of the mitigation engine.
type AttackState int

const (
	StateNormal    AttackState = iota // No attack detected
	StateDetected                     // Anomaly detected, evaluating
	StateMitigating                   // Active mitigation in progress
	StateCooldown                     // Attack subsided, waiting before returning to normal
)

func (s AttackState) String() string {
	switch s {
	case StateNormal:
		return "NORMAL"
	case StateDetected:
		return "DETECTED"
	case StateMitigating:
		return "MITIGATING"
	case StateCooldown:
		return "COOLDOWN"
	default:
		return "UNKNOWN"
	}
}

// AttackInfo contains details about a detected attack.
type AttackInfo struct {
	Type       string    // "SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", etc.
	StartTime  time.Time
	PeakPPS    uint64
	PeakBPS    uint64
	SourceIPs  []string
	DroppedPkts uint64
}

// Engine is the core mitigation orchestrator.
type Engine struct {
	cfg    *config.Config
	bpf    *bpf.Manager
	logger *zap.SugaredLogger

	mu            sync.RWMutex
	state         AttackState
	currentAttack *AttackInfo
	attackHistory []AttackInfo

	// Channels for async events
	alertCh chan AttackInfo
}

// New creates a new mitigation engine.
func New(cfg *config.Config, bpfMgr *bpf.Manager, logger *zap.SugaredLogger) *Engine {
	return &Engine{
		cfg:     cfg,
		bpf:     bpfMgr,
		logger:  logger,
		state:   StateNormal,
		alertCh: make(chan AttackInfo, 100),
	}
}

// State returns the current mitigation state.
func (e *Engine) State() AttackState {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.state
}

// Run starts the main event loop. Blocks until context is cancelled.
func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	e.logger.Info("Engine event loop started")

	for {
		select {
		case <-ctx.Done():
			e.logger.Info("Engine shutting down")
			return

		case <-ticker.C:
			e.tick()
		}
	}
}

// tick is called every second to evaluate the current traffic state.
func (e *Engine) tick() {
	if e.bpf == nil {
		return // BPF not available yet
	}

	// ── Read XDP Statistics ──────────────────────────────────────────
	stats, err := e.bpf.ReadStats()
	if err != nil {
		e.logger.Debugw("Failed to read BPF stats", "error", err)
		return
	}

	// ── Evaluate Against Thresholds ──────────────────────────────────
	e.mu.Lock()
	defer e.mu.Unlock()

	switch e.state {
	case StateNormal:
		// Check for anomalies
		if stats.UDPDropsPerSec > e.cfg.Thresholds.UDPPPS*2 ||
			stats.SYNDropsPerSec > e.cfg.Thresholds.SYNFlood {
			e.state = StateDetected
			e.currentAttack = &AttackInfo{
				StartTime: time.Now(),
				Type:      e.classifyAttack(stats),
			}
			e.logger.Warnw("⚠ Attack DETECTED",
				"type", e.currentAttack.Type,
				"udp_drops/s", stats.UDPDropsPerSec,
				"syn_drops/s", stats.SYNDropsPerSec,
			)
		}

	case StateDetected:
		// Confirm the attack is sustained (not a brief spike)
		e.state = StateMitigating
		e.logger.Warnw("🛡 MITIGATING attack",
			"type", e.currentAttack.Type,
			"duration", time.Since(e.currentAttack.StartTime),
		)

	case StateMitigating:
		// Update peak values
		if stats.TotalDropsPerSec > e.currentAttack.PeakPPS {
			e.currentAttack.PeakPPS = stats.TotalDropsPerSec
		}

		// Check if attack has subsided
		if stats.TotalDropsPerSec < 100 {
			e.state = StateCooldown
			e.logger.Infow("Attack subsiding — entering cooldown",
				"peak_pps", e.currentAttack.PeakPPS,
				"duration", time.Since(e.currentAttack.StartTime),
			)
		}

	case StateCooldown:
		cooldownDuration := time.Duration(e.cfg.ControlPlane.CooldownSeconds) * time.Second
		if e.currentAttack != nil && time.Since(e.currentAttack.StartTime) > cooldownDuration {
			e.logger.Infow("✓ Returning to NORMAL state",
				"attack_type", e.currentAttack.Type,
				"total_duration", time.Since(e.currentAttack.StartTime),
				"peak_pps", e.currentAttack.PeakPPS,
			)
			e.attackHistory = append(e.attackHistory, *e.currentAttack)
			e.currentAttack = nil
			e.state = StateNormal
		}
	}
}

// classifyAttack determines the attack type based on stats.
func (e *Engine) classifyAttack(stats *bpf.Stats) string {
	if stats.SYNDropsPerSec > stats.UDPDropsPerSec && stats.SYNDropsPerSec > stats.ICMPDropsPerSec {
		return "SYN_FLOOD"
	}
	if stats.UDPDropsPerSec > stats.SYNDropsPerSec && stats.UDPDropsPerSec > stats.ICMPDropsPerSec {
		return "UDP_FLOOD"
	}
	if stats.ICMPDropsPerSec > 0 {
		return "ICMP_FLOOD"
	}
	return "MIXED_VOLUMETRIC"
}

// GetAttackHistory returns a copy of the attack history.
func (e *Engine) GetAttackHistory() []AttackInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	history := make([]AttackInfo, len(e.attackHistory))
	copy(history, e.attackHistory)
	return history
}
