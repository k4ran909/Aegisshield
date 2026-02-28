package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsRemoteWithoutToken(t *testing.T) {
	cfgPath := writeTempConfig(t, `
thresholds:
  udp_pps: 1000
control_plane:
  api_listen: "0.0.0.0:9090"
  metrics_listen: "0.0.0.0:9100"
  expose_remote: true
  allowed_cidrs: ["10.0.0.0/8"]
`)

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected validation error when expose_remote=true without auth_token")
	}
}

func TestLoadRejectsNonLoopbackWhenRemoteDisabled(t *testing.T) {
	cfgPath := writeTempConfig(t, `
thresholds:
  udp_pps: 1000
control_plane:
  api_listen: "0.0.0.0:9090"
  metrics_listen: "127.0.0.1:9100"
  expose_remote: false
`)

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected validation error for non-loopback api_listen when expose_remote=false")
	}
}

func TestLoadAcceptsRemoteWithTokenAndCIDR(t *testing.T) {
	cfgPath := writeTempConfig(t, `
thresholds:
  udp_pps: 1000
control_plane:
  api_listen: "0.0.0.0:9090"
  metrics_listen: "0.0.0.0:9100"
  expose_remote: true
  auth_token: "secret-token"
  allowed_cidrs: ["10.0.0.0/8", "127.0.0.1/32"]
`)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("expected config to load, got error: %v", err)
	}
	if cfg.ControlPlane.AuthToken != "secret-token" {
		t.Fatalf("unexpected auth token value: %q", cfg.ControlPlane.AuthToken)
	}
}

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "aegis.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}
