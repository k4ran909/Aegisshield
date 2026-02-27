// Package api provides the gRPC and REST API for the AegisShield daemon.
//
// Endpoints:
//
//	GET  /api/v1/status       — Current protection state + stats
//	GET  /api/v1/attacks      — Attack history
//	GET  /api/v1/baselines    — Anomaly detector baselines
//	POST /api/v1/block        — Block an IP address
//	POST /api/v1/unblock      — Unblock an IP address
//	GET  /api/v1/rules        — List ACL rules
//	POST /api/v1/config/reload — Hot-reload configuration
//	GET  /api/v1/blocklist    — List all blocked IPs
package api

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/aegisshield/aegisshield/internal/bpf"
	"github.com/aegisshield/aegisshield/internal/config"
	"github.com/aegisshield/aegisshield/internal/engine"
)

// Server is the HTTP/gRPC API server.
type Server struct {
	listenAddr string
	engine     *engine.Engine
	responder  *engine.Responder
	detector   *engine.Detector
	bpfMgr     *bpf.Manager
	cfg        *config.Config
	logger     *zap.SugaredLogger
}

// NewServer creates a new API server.
func NewServer(
	addr string,
	eng *engine.Engine,
	resp *engine.Responder,
	det *engine.Detector,
	bpfMgr *bpf.Manager,
	cfg *config.Config,
	logger *zap.SugaredLogger,
) *Server {
	return &Server{
		listenAddr: addr,
		engine:     eng,
		responder:  resp,
		detector:   det,
		bpfMgr:     bpfMgr,
		cfg:        cfg,
		logger:     logger,
	}
}

// Start begins serving the API.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// ── API Routes ───────────────────────────────────────────────
	mux.HandleFunc("/api/v1/status", s.corsMiddleware(s.handleStatus))
	mux.HandleFunc("/api/v1/attacks", s.corsMiddleware(s.handleAttacks))
	mux.HandleFunc("/api/v1/baselines", s.corsMiddleware(s.handleBaselines))
	mux.HandleFunc("/api/v1/block", s.corsMiddleware(s.handleBlock))
	mux.HandleFunc("/api/v1/unblock", s.corsMiddleware(s.handleUnblock))
	mux.HandleFunc("/api/v1/blocklist", s.corsMiddleware(s.handleBlocklist))
	mux.HandleFunc("/api/v1/rules", s.corsMiddleware(s.handleRules))
	mux.HandleFunc("/api/v1/config/reload", s.corsMiddleware(s.handleConfigReload))
	mux.HandleFunc("/api/v1/actions", s.corsMiddleware(s.handleActions))

	s.logger.Infow("API server starting", "listen", s.listenAddr)
	return http.ListenAndServe(s.listenAddr, mux)
}

// ── Status ───────────────────────────────────────────────────────

type StatusResponse struct {
	State         string     `json:"state"`
	Uptime        string     `json:"uptime"`
	Learning      bool       `json:"learning"`
	ActiveActions int        `json:"active_actions"`
	BlockedIPs    int        `json:"blocked_ips"`
	Stats         *bpf.Stats `json:"stats,omitempty"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var stats *bpf.Stats
	if s.bpfMgr != nil {
		st, err := s.bpfMgr.ReadStats()
		if err == nil {
			stats = st
		}
	}

	blockedIPs, _ := s.bpfMgr.ListBlockedIPs()

	resp := StatusResponse{
		State:         s.engine.State().String(),
		Learning:      s.detector.IsLearning(),
		ActiveActions: len(s.responder.GetActiveActions()),
		BlockedIPs:    len(blockedIPs),
		Stats:         stats,
	}

	s.writeJSON(w, resp)
}

// ── Attacks ──────────────────────────────────────────────────────

func (s *Server) handleAttacks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.writeJSON(w, s.engine.GetAttackHistory())
}

// ── Baselines ────────────────────────────────────────────────────

func (s *Server) handleBaselines(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.writeJSON(w, s.detector.GetBaselines())
}

// ── Block IP ─────────────────────────────────────────────────────

type BlockRequest struct {
	IP       string `json:"ip"`
	Duration string `json:"duration"` // e.g., "1h", "30m", "permanent"
	Reason   string `json:"reason"`
}

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if net.ParseIP(req.IP) == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	duration := 5 * time.Minute // Default
	if req.Duration != "" && req.Duration != "permanent" {
		d, err := time.ParseDuration(req.Duration)
		if err != nil {
			http.Error(w, "Invalid duration format", http.StatusBadRequest)
			return
		}
		duration = d
	} else if req.Duration == "permanent" {
		duration = 365 * 24 * time.Hour // ~1 year
	}

	reason := req.Reason
	if reason == "" {
		reason = "Manual block via API"
	}

	if err := s.responder.BlockIP(req.IP, duration, reason); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.writeJSON(w, map[string]string{
		"status":   "blocked",
		"ip":       req.IP,
		"duration": duration.String(),
	})
}

// ── Unblock IP ───────────────────────────────────────────────────

func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ip := net.ParseIP(req.IP)
	if ip == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	if s.bpfMgr != nil {
		s.bpfMgr.UnblockIP(ip)
	}

	s.writeJSON(w, map[string]string{
		"status": "unblocked",
		"ip":     req.IP,
	})
}

// ── Blocklist ────────────────────────────────────────────────────

func (s *Server) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ips, _ := s.bpfMgr.ListBlockedIPs()
	s.writeJSON(w, map[string]interface{}{
		"count": len(ips),
		"ips":   ips,
	})
}

// ── ACL Rules ────────────────────────────────────────────────────

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.writeJSON(w, s.cfg.ACLRules)
}

// ── Config Reload ────────────────────────────────────────────────

func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.logger.Info("Configuration reload requested via API")
	// TODO: Re-read YAML config, update BPF maps

	s.writeJSON(w, map[string]string{
		"status": "reloaded",
	})
}

// ── Active Actions ───────────────────────────────────────────────

func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.writeJSON(w, s.responder.GetActiveActions())
}

// ── Helpers ──────────────────────────────────────────────────────

func (s *Server) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Errorw("Failed to encode JSON response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (s *Server) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}
