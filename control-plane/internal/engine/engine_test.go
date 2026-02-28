package engine

import (
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/aegisshield/aegisshield/internal/bpf"
	"github.com/aegisshield/aegisshield/internal/config"
)

func TestEngineStateTransitions(t *testing.T) {
	cfg := &config.Config{
		Thresholds: config.ThresholdConfig{
			UDPPPS:   100,
			SYNFlood: 100,
		},
		ControlPlane: config.ControlPlaneConfig{
			CooldownSeconds: 1,
		},
	}

	e := New(cfg, nil, zap.NewNop().Sugar())

	e.Ingest(&bpf.Stats{UDPDropsPerSec: 250, TotalDropsPerSec: 250})
	if got := e.State(); got != StateDetected {
		t.Fatalf("expected DETECTED, got %s", got.String())
	}

	e.Ingest(&bpf.Stats{UDPDropsPerSec: 300, TotalDropsPerSec: 300})
	if got := e.State(); got != StateMitigating {
		t.Fatalf("expected MITIGATING, got %s", got.String())
	}

	e.Ingest(&bpf.Stats{UDPDropsPerSec: 20, TotalDropsPerSec: 20})
	if got := e.State(); got != StateCooldown {
		t.Fatalf("expected COOLDOWN, got %s", got.String())
	}

	e.mu.Lock()
	if e.currentAttack == nil {
		t.Fatal("expected current attack to be present in cooldown")
	}
	e.currentAttack.StartTime = time.Now().Add(-2 * time.Second)
	e.mu.Unlock()

	e.Ingest(&bpf.Stats{UDPDropsPerSec: 0, TotalDropsPerSec: 0})
	if got := e.State(); got != StateNormal {
		t.Fatalf("expected NORMAL, got %s", got.String())
	}

	if history := e.GetAttackHistory(); len(history) != 1 {
		t.Fatalf("expected one attack history entry, got %d", len(history))
	}
}
