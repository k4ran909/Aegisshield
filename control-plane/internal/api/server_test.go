package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/aegisshield/aegisshield/internal/config"
	"github.com/aegisshield/aegisshield/internal/engine"
)

func TestMutatingEndpointRequiresAuth(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/block", bytes.NewBufferString(`{"ip":"1.2.3.4"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/block", bytes.NewBufferString(`{"ip":"1.2.3.4"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid auth, got %d", rec.Code)
	}
}

func TestThresholdUpdateRequiresAuth(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/thresholds", bytes.NewBufferString(`{"udp_pps":1000,"syn_flood":5000,"icmp_pps":50,"dns_response_size":512}`))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/thresholds", bytes.NewBufferString(`{"udp_pps":1000,"syn_flood":5000,"icmp_pps":50,"dns_response_size":512}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("expected auth check to pass with token")
	}
}

func TestRootRedirectsToUI(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/ui/" {
		t.Fatalf("expected redirect to /ui/, got %q", got)
	}
}

func TestUIServed(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body, _ := io.ReadAll(rec.Body)
	if !bytes.Contains(body, []byte("AegisShield Control Panel")) {
		t.Fatalf("expected UI HTML content")
	}
}

func TestDisallowedCORSOriginIsRejected(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Origin", "https://not-allowed.example")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed origin, got %d", rec.Code)
	}
}

func TestDisallowedCIDRIsRejected(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "10.10.10.10:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed source, got %d", rec.Code)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()

	cfg := &config.Config{
		Thresholds: config.ThresholdConfig{
			UDPPPS:   100,
			SYNFlood: 100,
		},
		ControlPlane: config.ControlPlaneConfig{
			AuthToken:      "test-token",
			AllowedOrigins: []string{"https://allowed.example"},
			AllowedCIDRs:   []string{"127.0.0.1/32"},
		},
	}

	logger := zap.NewNop().Sugar()
	eng := engine.New(cfg, nil, logger)
	resp := engine.NewResponder(cfg, nil, logger)
	det := engine.NewDetector(engine.DefaultDetectorConfig(), logger)

	return NewServer("127.0.0.1:0", eng, resp, det, nil, cfg, logger)
}
