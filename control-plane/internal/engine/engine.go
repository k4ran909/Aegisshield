// Package engine is the core mitigation orchestrator.
package engine

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/aegisshield/aegisshield/internal/bpf"
	"github.com/aegisshield/aegisshield/internal/config"
)

// AttackState represents the current mitigation state.
type AttackState int

const (
	StateNormal AttackState = iota
	StateDetected
	StateMitigating
	StateCooldown
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
	Type        string
	StartTime   time.Time
	PeakPPS     uint64
	PeakBPS     uint64
	SourceIPs   []string
	DroppedPkts uint64
}

// Engine coordinates state transitions based on live traffic.
type Engine struct {
	cfg    *config.Config
	bpf    *bpf.Manager
	logger *zap.SugaredLogger

	mu            sync.RWMutex
	state         AttackState
	currentAttack *AttackInfo
	attackHistory []AttackInfo
	alertCh       chan AttackInfo
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

// Run polls stats from BPF and updates the state machine.
func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
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

func (e *Engine) tick() {
	if e.bpf == nil {
		return
	}

	stats, err := e.bpf.ReadStats()
	if err != nil {
		e.logger.Debugw("Failed to read BPF stats", "error", err)
		return
	}

	e.Ingest(stats)
}

// Ingest updates state transitions using an externally supplied stats snapshot.
func (e *Engine) Ingest(stats *bpf.Stats) {
	if stats == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	switch e.state {
	case StateNormal:
		if stats.UDPDropsPerSec > e.cfg.Thresholds.UDPPPS*2 ||
			stats.SYNDropsPerSec > e.cfg.Thresholds.SYNFlood {
			e.state = StateDetected
			e.currentAttack = &AttackInfo{
				StartTime: time.Now(),
				Type:      e.classifyAttack(stats),
			}
			e.logger.Warnw("Attack detected",
				"type", e.currentAttack.Type,
				"udp_drops_per_sec", stats.UDPDropsPerSec,
				"syn_drops_per_sec", stats.SYNDropsPerSec,
			)
		}

	case StateDetected:
		e.state = StateMitigating
		if e.currentAttack != nil {
			e.logger.Warnw("Entering mitigation",
				"type", e.currentAttack.Type,
				"duration", time.Since(e.currentAttack.StartTime),
			)
		}

	case StateMitigating:
		if e.currentAttack != nil && stats.TotalDropsPerSec > e.currentAttack.PeakPPS {
			e.currentAttack.PeakPPS = stats.TotalDropsPerSec
		}

		if stats.TotalDropsPerSec < 100 {
			e.state = StateCooldown
			if e.currentAttack != nil {
				e.logger.Infow("Attack subsiding, entering cooldown",
					"peak_pps", e.currentAttack.PeakPPS,
					"duration", time.Since(e.currentAttack.StartTime),
				)
			}
		}

	case StateCooldown:
		cooldownDuration := time.Duration(e.cfg.ControlPlane.CooldownSeconds) * time.Second
		if e.currentAttack != nil && time.Since(e.currentAttack.StartTime) > cooldownDuration {
			e.logger.Infow("Returning to normal",
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

// GetAttackHistory returns a copy of recorded attacks.
func (e *Engine) GetAttackHistory() []AttackInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	history := make([]AttackInfo, len(e.attackHistory))
	copy(history, e.attackHistory)
	return history
}
