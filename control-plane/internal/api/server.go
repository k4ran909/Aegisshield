package api

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/aegisshield/aegisshield/internal/bpf"
	"github.com/aegisshield/aegisshield/internal/config"
	"github.com/aegisshield/aegisshield/internal/engine"
)

//go:embed web/*
var webAssets embed.FS

// Server is the HTTP API server.
type Server struct {
	listenAddr string
	engine     *engine.Engine
	responder  *engine.Responder
	detector   *engine.Detector
	bpfMgr     *bpf.Manager
	cfg        *config.Config
	logger     *zap.SugaredLogger
	startedAt  time.Time

	authToken      string
	allowedOrigins map[string]struct{}
	allowAnyOrigin bool
	allowedCIDRs   []*net.IPNet
}

// StatusResponse is returned by /api/v1/status.
type StatusResponse struct {
	State         string     `json:"state"`
	Uptime        string     `json:"uptime"`
	Learning      bool       `json:"learning"`
	ActiveActions int        `json:"active_actions"`
	BlockedIPs    int        `json:"blocked_ips"`
	Stats         *bpf.Stats `json:"stats,omitempty"`
}

type errorResponse struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// BlockRequest is used by /api/v1/block.
type BlockRequest struct {
	IP       string `json:"ip"`
	Duration string `json:"duration"` // e.g. "1h", "30m", "permanent"
	Reason   string `json:"reason"`
}

// ThresholdUpdateRequest is used by /api/v1/thresholds.
type ThresholdUpdateRequest struct {
	UDPPPS          uint64 `json:"udp_pps"`
	SYNFlood        uint64 `json:"syn_flood"`
	ICMPPPS         uint64 `json:"icmp_pps"`
	DNSResponseSize uint16 `json:"dns_response_size"`
}

var mutatingPaths = map[string]struct{}{
	"/api/v1/block":         {},
	"/api/v1/unblock":       {},
	"/api/v1/config/reload": {},
	"/api/v1/thresholds":    {},
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
	s := &Server{
		listenAddr:     addr,
		engine:         eng,
		responder:      resp,
		detector:       det,
		bpfMgr:         bpfMgr,
		cfg:            cfg,
		logger:         logger,
		startedAt:      time.Now(),
		allowedOrigins: make(map[string]struct{}),
		allowedCIDRs:   make([]*net.IPNet, 0),
	}

	if cfg != nil {
		s.authToken = cfg.ControlPlane.AuthToken
		s.allowedCIDRs = make([]*net.IPNet, 0, len(cfg.ControlPlane.AllowedCIDRs))

		for _, origin := range cfg.ControlPlane.AllowedOrigins {
			if origin == "*" {
				s.allowAnyOrigin = true
				continue
			}
			s.allowedOrigins[origin] = struct{}{}
		}

		for _, cidr := range cfg.ControlPlane.AllowedCIDRs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				logger.Warnw("Ignoring invalid CIDR in config", "cidr", cidr, "error", err)
				continue
			}
			s.allowedCIDRs = append(s.allowedCIDRs, ipNet)
		}
	}

	return s
}

// Start begins serving the API.
func (s *Server) Start() error {
	s.logger.Infow("API server starting", "listen", s.listenAddr)
	return http.ListenAndServe(s.listenAddr, s.Handler())
}

// Handler returns the full HTTP handler stack (useful for tests).
func (s *Server) Handler() http.Handler {
	return s.middleware(s.routes())
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	webRoot, err := fs.Sub(webAssets, "web")
	if err != nil {
		panic("failed to initialize embedded web assets: " + err.Error())
	}

	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusTemporaryRedirect)
	})
	mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(webRoot))))

	mux.HandleFunc("/api/v1/status", s.handleStatus)
	mux.HandleFunc("/api/v1/attacks", s.handleAttacks)
	mux.HandleFunc("/api/v1/baselines", s.handleBaselines)
	mux.HandleFunc("/api/v1/block", s.handleBlock)
	mux.HandleFunc("/api/v1/unblock", s.handleUnblock)
	mux.HandleFunc("/api/v1/blocklist", s.handleBlocklist)
	mux.HandleFunc("/api/v1/rules", s.handleRules)
	mux.HandleFunc("/api/v1/config", s.handleConfig)
	mux.HandleFunc("/api/v1/config/reload", s.handleConfigReload)
	mux.HandleFunc("/api/v1/thresholds", s.handleThresholds)
	mux.HandleFunc("/api/v1/actions", s.handleActions)
	return mux
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.isAllowedSource(r) {
			s.writeError(w, http.StatusForbidden, "source_forbidden", "request source is not in allowed CIDRs")
			return
		}

		if !s.handleCORS(w, r) {
			return
		}

		if s.requiresAuth(r) && !s.isAuthorized(r) {
			s.writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid bearer token")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/ui/", http.StatusTemporaryRedirect)
}

func (s *Server) handleCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin != "" {
		sameOrigin := s.isSameOrigin(r, origin)

		if !sameOrigin && !s.allowAnyOrigin {
			if len(s.allowedOrigins) == 0 {
				s.writeError(w, http.StatusForbidden, "origin_forbidden", "origin is not allowed")
				return false
			}
			if _, ok := s.allowedOrigins[origin]; !ok {
				s.writeError(w, http.StatusForbidden, "origin_forbidden", "origin is not allowed")
				return false
			}
		}

		if !sameOrigin && s.allowAnyOrigin {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	}

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	return true
}

func (s *Server) isSameOrigin(r *http.Request, origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func (s *Server) requiresAuth(r *http.Request) bool {
	if s.authToken == "" {
		return false
	}
	_, ok := mutatingPaths[r.URL.Path]
	return ok
}

func (s *Server) isAuthorized(r *http.Request) bool {
	raw := r.Header.Get("Authorization")
	if !strings.HasPrefix(raw, "Bearer ") {
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
	return token != "" && token == s.authToken
}

func (s *Server) isAllowedSource(r *http.Request) bool {
	if len(s.allowedCIDRs) == 0 {
		return true
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, cidr := range s.allowedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	var stats *bpf.Stats
	if s.bpfMgr != nil {
		st, err := s.bpfMgr.ReadStats()
		if err != nil {
			s.logger.Warnw("Failed to read BPF stats", "error", err)
		} else {
			stats = st
		}
	}

	blockedCount := 0
	if s.bpfMgr != nil {
		ips, err := s.bpfMgr.ListBlockedIPs()
		if err != nil {
			s.logger.Warnw("Failed to list blocked IPs", "error", err)
		} else {
			blockedCount = len(ips)
		}
	}

	state := "UNKNOWN"
	if s.engine != nil {
		state = s.engine.State().String()
	}

	learning := false
	if s.detector != nil {
		learning = s.detector.IsLearning()
	}

	activeActions := 0
	if s.responder != nil {
		activeActions = len(s.responder.GetActiveActions())
	}

	resp := StatusResponse{
		State:         state,
		Uptime:        time.Since(s.startedAt).Round(time.Second).String(),
		Learning:      learning,
		ActiveActions: activeActions,
		BlockedIPs:    blockedCount,
		Stats:         stats,
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAttacks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.engine == nil {
		s.writeJSON(w, http.StatusOK, []engine.AttackInfo{})
		return
	}
	s.writeJSON(w, http.StatusOK, s.engine.GetAttackHistory())
}

func (s *Server) handleBaselines(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.detector == nil {
		s.writeJSON(w, http.StatusOK, map[string]engine.MetricBaseline{})
		return
	}
	s.writeJSON(w, http.StatusOK, s.detector.GetBaselines())
}

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.responder == nil {
		s.writeError(w, http.StatusServiceUnavailable, "responder_unavailable", "responder is not available")
		return
	}

	var req BlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}

	if net.ParseIP(req.IP) == nil {
		s.writeError(w, http.StatusBadRequest, "invalid_ip", "invalid IP address")
		return
	}

	duration := 5 * time.Minute
	if req.Duration != "" && req.Duration != "permanent" {
		d, err := time.ParseDuration(req.Duration)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_duration", "invalid duration format")
			return
		}
		duration = d
	} else if req.Duration == "permanent" {
		duration = 0
	}

	reason := req.Reason
	if reason == "" {
		reason = "Manual block via API"
	}

	if err := s.responder.BlockIP(req.IP, duration, reason); err != nil {
		s.writeError(w, http.StatusInternalServerError, "block_failed", err.Error())
		return
	}

	durStr := "permanent"
	if duration > 0 {
		durStr = duration.String()
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"status":   "blocked",
		"ip":       req.IP,
		"duration": durStr,
	})
}

func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.bpfMgr == nil {
		s.writeError(w, http.StatusServiceUnavailable, "bpf_unavailable", "bpf manager is not available")
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}

	ip := net.ParseIP(req.IP)
	if ip == nil {
		s.writeError(w, http.StatusBadRequest, "invalid_ip", "invalid IP address")
		return
	}

	if err := s.bpfMgr.UnblockIP(ip); err != nil {
		s.writeError(w, http.StatusInternalServerError, "unblock_failed", err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"status": "unblocked",
		"ip":     req.IP,
	})
}

func (s *Server) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.bpfMgr == nil {
		s.writeJSON(w, http.StatusOK, map[string]any{"count": 0, "ips": []string{}})
		return
	}

	ips, err := s.bpfMgr.ListBlockedIPs()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "blocklist_failed", err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"count": len(ips),
		"ips":   ips,
	})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.cfg == nil {
		s.writeJSON(w, http.StatusOK, []config.ACLRuleConfig{})
		return
	}
	s.writeJSON(w, http.StatusOK, s.cfg.ACLRules)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.cfg == nil {
		s.writeJSON(w, http.StatusOK, map[string]any{})
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"thresholds": map[string]any{
			"udp_pps":           s.cfg.Thresholds.UDPPPS,
			"syn_flood":         s.cfg.Thresholds.SYNFlood,
			"icmp_pps":          s.cfg.Thresholds.ICMPPPS,
			"dns_response_size": s.cfg.Thresholds.DNSResponseSize,
		},
		"control_plane": map[string]any{
			"api_listen":          s.cfg.ControlPlane.APIListen,
			"metrics_listen":      s.cfg.ControlPlane.MetricsListen,
			"cooldown_seconds":    s.cfg.ControlPlane.CooldownSeconds,
			"auto_block_duration": s.cfg.ControlPlane.AutoBlockDuration,
			"expose_remote":       s.cfg.ControlPlane.ExposeRemote,
			"allowed_origins":     s.cfg.ControlPlane.AllowedOrigins,
			"allowed_cidrs":       s.cfg.ControlPlane.AllowedCIDRs,
		},
		"minecraft": s.cfg.Minecraft,
		"bgp": map[string]any{
			"enabled":      s.cfg.BGP.Enabled,
			"experimental": s.cfg.BGP.Experimental,
		},
		"tunnel": map[string]any{
			"enabled":      s.cfg.Tunnel.Enabled,
			"experimental": s.cfg.Tunnel.Experimental,
			"type":         s.cfg.Tunnel.Type,
		},
	})
}

func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	// Runtime reload is intentionally not implemented yet.
	s.writeError(w, http.StatusNotImplemented, "not_implemented", "runtime config reload is not implemented")
}

func (s *Server) handleThresholds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.bpfMgr == nil {
		s.writeError(w, http.StatusServiceUnavailable, "bpf_unavailable", "bpf manager is not available")
		return
	}
	if s.cfg == nil {
		s.writeError(w, http.StatusServiceUnavailable, "config_unavailable", "runtime config is not available")
		return
	}

	var req ThresholdUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}

	if req.UDPPPS == 0 || req.SYNFlood == 0 || req.ICMPPPS == 0 || req.DNSResponseSize == 0 {
		s.writeError(w, http.StatusBadRequest, "invalid_thresholds", "all threshold values must be non-zero")
		return
	}

	if err := s.bpfMgr.UpdateThresholds(req.UDPPPS, req.SYNFlood, req.ICMPPPS, req.DNSResponseSize); err != nil {
		s.writeError(w, http.StatusInternalServerError, "threshold_update_failed", err.Error())
		return
	}

	// Keep daemon-side view aligned for any component reading cfg after update.
	s.cfg.Thresholds.UDPPPS = req.UDPPPS
	s.cfg.Thresholds.SYNFlood = req.SYNFlood
	s.cfg.Thresholds.ICMPPPS = req.ICMPPPS
	s.cfg.Thresholds.DNSResponseSize = req.DNSResponseSize

	s.writeJSON(w, http.StatusOK, map[string]any{
		"status": "updated",
		"thresholds": map[string]any{
			"udp_pps":           s.cfg.Thresholds.UDPPPS,
			"syn_flood":         s.cfg.Thresholds.SYNFlood,
			"icmp_pps":          s.cfg.Thresholds.ICMPPPS,
			"dns_response_size": s.cfg.Thresholds.DNSResponseSize,
		},
	})
}

func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.responder == nil {
		s.writeJSON(w, http.StatusOK, []engine.ResponseAction{})
		return
	}
	s.writeJSON(w, http.StatusOK, s.responder.GetActiveActions())
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Errorw("Failed to encode JSON response", "error", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	s.writeJSON(w, status, errorResponse{
		Error: apiError{
			Code:    code,
			Message: message,
		},
	})
}
