//go:build linux

package bpf

import (
	"os"
	"testing"

	"go.uber.org/zap"
)

func TestReadStatsIntegration(t *testing.T) {
	if os.Getenv("AEGIS_INTEGRATION") != "1" {
		t.Skip("set AEGIS_INTEGRATION=1 to run integration tests against pinned maps")
	}

	mgr := NewManager("/sys/fs/bpf/aegis", zap.NewNop().Sugar())
	defer mgr.Close()

	if _, err := mgr.ReadStats(); err != nil {
		t.Fatalf("read stats from pinned map failed: %v", err)
	}
}
