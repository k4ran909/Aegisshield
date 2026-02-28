// Package engine — Auto-Responder
//
// Dispatches automated mitigation actions based on detected anomalies.
// The responder follows a graduated response model:
//
// Level 1 (LOW)    → Log + Alert (Discord/Telegram notification)
// Level 2 (MEDIUM) → Tighten rate limits + Block top offenders
// Level 3 (HIGH)   → Emergency mode: strict thresholds + mass block
//
// All actions are reversible and time-limited to prevent permanent
// damage from false positives.
package engine

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/aegisshield/aegisshield/internal/bpf"
	"github.com/aegisshield/aegisshield/internal/config"
	"github.com/aegisshield/aegisshield/internal/metrics"
)

// ResponseAction represents an automated mitigation action.
type ResponseAction struct {
	Type      ActionType
	Target    string // IP address or rule ID
	Duration  time.Duration
	StartedAt time.Time
	ExpiresAt time.Time
	Reason    string
}

// ActionType defines the kind of response action.
type ActionType int

const (
	ActionBlockIP          ActionType = iota // Add IP to XDP blocklist
	ActionTightenLimits                      // Reduce rate limit thresholds
	ActionEnableStrictMode                   // Switch to strict filtering mode
	ActionNotify                             // Send alert notification
	ActionUnblockIP                          // Remove IP from blocklist (auto-expire)
	ActionRestoreLimits                      // Restore normal rate limits
)

func (a ActionType) String() string {
	switch a {
	case ActionBlockIP:
		return "BLOCK_IP"
	case ActionTightenLimits:
		return "TIGHTEN_LIMITS"
	case ActionEnableStrictMode:
		return "STRICT_MODE"
	case ActionNotify:
		return "NOTIFY"
	case ActionUnblockIP:
		return "UNBLOCK_IP"
	case ActionRestoreLimits:
		return "RESTORE_LIMITS"
	default:
		return "UNKNOWN"
	}
}

// Responder dispatches and manages automated response actions.
type Responder struct {
	mu            sync.RWMutex
	cfg           *config.Config
	bpfMgr        *bpf.Manager
	logger        *zap.SugaredLogger
	activeActions []ResponseAction
	actionHistory []ResponseAction
	alertCh       chan string // Channel for outbound alert messages
}

// NewResponder creates a new auto-responder.
func NewResponder(
	cfg *config.Config,
	bpfMgr *bpf.Manager,
	logger *zap.SugaredLogger,
) *Responder {
	return &Responder{
		cfg:     cfg,
		bpfMgr:  bpfMgr,
		logger:  logger,
		alertCh: make(chan string, 100),
	}
}

// Respond takes a list of anomaly alerts and dispatches appropriate actions.
func (r *Responder) Respond(alerts []AnomalyAlert) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, alert := range alerts {
		switch alert.Severity {
		case SeverityLow:
			r.handleLow(alert)
		case SeverityMedium:
			r.handleMedium(alert)
		case SeverityHigh:
			r.handleHigh(alert)
		}
	}
}

// handleLow — Level 1: Log + Alert.
func (r *Responder) handleLow(alert AnomalyAlert) {
	msg := fmt.Sprintf(
		"⚠️ [LOW] Anomaly on %s: value=%.0f baseline=%.0f z=%.1f",
		alert.Metric, alert.Value, alert.Baseline, alert.ZScore,
	)
	r.logger.Warn(msg)
	r.sendAlert(msg)

	r.recordAction(ResponseAction{
		Type:      ActionNotify,
		Reason:    msg,
		StartedAt: time.Now(),
		Duration:  0,
	})
}

// handleMedium — Level 2: Tighten limits + Block top offenders.
func (r *Responder) handleMedium(alert AnomalyAlert) {
	msg := fmt.Sprintf(
		"🛡️ [MEDIUM] Attack detected on %s: value=%.0f (%.1fσ above baseline %.0f). Tightening limits.",
		alert.Metric, alert.Value, alert.ZScore, alert.Baseline,
	)
	r.logger.Warn(msg)
	r.sendAlert(msg)

	// Tighten rate limits by 50%
	if r.bpfMgr != nil {
		r.logger.Info("Tightening XDP rate limits by 50%")
		if err := r.bpfMgr.UpdateThresholds(
			uint64(float64(r.cfg.Thresholds.UDPPPS)*0.5),
			uint64(float64(r.cfg.Thresholds.SYNFlood)*0.5),
			uint64(float64(r.cfg.Thresholds.ICMPPPS)*0.5),
			r.cfg.Thresholds.DNSResponseSize,
		); err != nil {
			r.logger.Errorw("Failed to tighten limits", "error", err)
		}
	}

	blockDuration := time.Duration(r.cfg.ControlPlane.AutoBlockDuration) * time.Second

	r.recordAction(ResponseAction{
		Type:      ActionTightenLimits,
		Reason:    msg,
		StartedAt: time.Now(),
		Duration:  blockDuration,
		ExpiresAt: time.Now().Add(blockDuration),
	})

	metrics.AttackState.Set(2) // MITIGATING
}

// handleHigh — Level 3: Emergency mode.
func (r *Responder) handleHigh(alert AnomalyAlert) {
	msg := fmt.Sprintf(
		"🚨 [HIGH] Severe attack on %s: value=%.0f (%.1fσ above baseline %.0f). EMERGENCY MODE.",
		alert.Metric, alert.Value, alert.ZScore, alert.Baseline,
	)
	r.logger.Error(msg)
	r.sendAlert(msg)

	// Drop rate limits to minimum viable levels
	if r.bpfMgr != nil {
		r.logger.Info("EMERGENCY: Setting minimum rate limits")
		if err := r.bpfMgr.UpdateThresholds(100, 500, 10, 256); err != nil {
			r.logger.Errorw("Failed to set emergency limits", "error", err)
		}
	}

	r.recordAction(ResponseAction{
		Type:      ActionEnableStrictMode,
		Reason:    msg,
		StartedAt: time.Now(),
		Duration:  5 * time.Minute,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	metrics.AttackState.Set(2) // MITIGATING
}

// BlockIP blocks a single IP address via the XDP data plane.
func (r *Responder) BlockIP(ip string, duration time.Duration, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	if r.bpfMgr != nil {
		if err := r.bpfMgr.BlockIP(parsedIP, duration); err != nil {
			return fmt.Errorf("BPF block failed: %w", err)
		}
	}

	action := ResponseAction{
		Type:      ActionBlockIP,
		Target:    ip,
		Duration:  duration,
		StartedAt: time.Now(),
		ExpiresAt: time.Now().Add(duration),
		Reason:    reason,
	}
	r.activeActions = append(r.activeActions, action)

	r.logger.Infow("🔒 IP Blocked",
		"ip", ip,
		"duration", duration,
		"reason", reason,
	)

	msg := fmt.Sprintf("🔒 Blocked %s for %v: %s", ip, duration, reason)
	r.sendAlert(msg)
	metrics.BlockedIPs.Inc()

	return nil
}

// RunExpiryLoop runs in a goroutine to auto-expire timed actions.
func (r *Responder) RunExpiryLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.expireActions()
		}
	}
}

// expireActions checks for and cleans up expired actions.
func (r *Responder) expireActions() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	var remaining []ResponseAction

	for _, action := range r.activeActions {
		if action.Duration > 0 && now.After(action.ExpiresAt) {
			// Action expired — reverse it
			switch action.Type {
			case ActionBlockIP:
				if r.bpfMgr != nil {
					ip := net.ParseIP(action.Target)
					if ip != nil {
						r.bpfMgr.UnblockIP(ip)
						r.logger.Infow("🔓 IP auto-unblocked (expired)",
							"ip", action.Target,
							"was_blocked_for", action.Duration,
						)
						metrics.BlockedIPs.Dec()
					}
				}
			case ActionTightenLimits, ActionEnableStrictMode:
				// Restore normal limits
				if r.bpfMgr != nil {
					r.bpfMgr.UpdateThresholds(
						r.cfg.Thresholds.UDPPPS,
						r.cfg.Thresholds.SYNFlood,
						r.cfg.Thresholds.ICMPPPS,
						r.cfg.Thresholds.DNSResponseSize,
					)
					r.logger.Info("Rate limits restored to normal")
				}
				metrics.AttackState.Set(0) // NORMAL
			}

			r.actionHistory = append(r.actionHistory, action)
		} else {
			remaining = append(remaining, action)
		}
	}

	r.activeActions = remaining
}

// sendAlert pushes an alert message to the notification channel.
func (r *Responder) sendAlert(msg string) {
	select {
	case r.alertCh <- msg:
	default:
		r.logger.Warn("Alert channel full, dropping alert")
	}
}

// recordAction stores an action in the active actions list.
func (r *Responder) recordAction(action ResponseAction) {
	r.activeActions = append(r.activeActions, action)
	r.actionHistory = append(r.actionHistory, action)
}

// GetActiveActions returns currently active response actions.
func (r *Responder) GetActiveActions() []ResponseAction {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]ResponseAction, len(r.activeActions))
	copy(result, r.activeActions)
	return result
}

// GetAlertChannel returns the channel for consuming alert messages.
func (r *Responder) GetAlertChannel() <-chan string {
	return r.alertCh
}
