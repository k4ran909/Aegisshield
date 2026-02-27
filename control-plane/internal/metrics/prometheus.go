// Package metrics provides an enhanced Prometheus metrics exporter.
package metrics

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// ── Global Metrics ───────────────────────────────────────────────

var (
	// Packet counters
	RxPackets = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aegis_rx_packets_total",
		Help: "Total packets received by XDP",
	})
	DroppedPackets = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aegis_dropped_packets_total",
		Help: "Total packets dropped by XDP",
	})
	PassedPackets = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aegis_passed_packets_total",
		Help: "Total packets passed through XDP",
	})

	// Per-filter drop counters
	BlocklistDrops = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aegis_blocklist_drops_total",
		Help: "Packets dropped by IP blocklist",
	})
	ACLDrops = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aegis_acl_drops_total",
		Help: "Packets dropped by ACL firewall",
	})
	UDPDrops = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aegis_udp_drops_total",
		Help: "UDP packets dropped by rate limiter",
	})
	SYNDrops = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aegis_syn_drops_total",
		Help: "SYN packets dropped by SYN proxy",
	})
	ICMPDrops = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aegis_icmp_drops_total",
		Help: "ICMP packets dropped by rate limiter",
	})
	DNSDrops = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aegis_dns_amp_drops_total",
		Help: "DNS amplification packets dropped",
	})
	GREDrops = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aegis_gre_drops_total",
		Help: "GRE packets dropped",
	})
	FragDrops = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aegis_frag_drops_total",
		Help: "IP fragment packets dropped",
	})

	// Gauges
	AttackState = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "aegis_attack_state",
		Help: "Current attack state (0=NORMAL, 1=DETECTED, 2=MITIGATING, 3=COOLDOWN)",
	})
	BlockedIPs = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "aegis_blocked_ips",
		Help: "Number of currently blocked IPs in XDP blocklist",
	})
	CurrentPPS = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "aegis_current_pps",
		Help: "Current packets-per-second received",
	})
	CurrentDropPPS = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "aegis_current_drop_pps",
		Help: "Current packets-per-second being dropped",
	})
	ConntrackEntries = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "aegis_conntrack_entries",
		Help: "Number of entries in connection tracking table",
	})

	// Histograms
	AttackDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "aegis_attack_duration_seconds",
		Help:    "Duration of detected attacks",
		Buckets: prometheus.ExponentialBuckets(1, 2, 15), // 1s → ~8h
	})

	// Counters for attack events
	AttacksDetected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aegis_attacks_detected_total",
		Help: "Total number of attacks detected",
	})

	// Minecraft-specific
	MCBotScore = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aegis_mc_bot_score",
		Help: "Bot detection score by IP",
	}, []string{"ip"})
	MCConnectionRate = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "aegis_mc_connections_per_sec",
		Help: "Minecraft connection rate per second",
	})
)

func init() {
	prometheus.MustRegister(
		RxPackets,
		DroppedPackets,
		PassedPackets,
		BlocklistDrops,
		ACLDrops,
		UDPDrops,
		SYNDrops,
		ICMPDrops,
		DNSDrops,
		GREDrops,
		FragDrops,
		AttackState,
		BlockedIPs,
		CurrentPPS,
		CurrentDropPPS,
		ConntrackEntries,
		AttackDuration,
		AttacksDetected,
		MCBotScore,
		MCConnectionRate,
	)
}

// StartServer starts the Prometheus metrics HTTP server.
func StartServer(addr string, logger *zap.SugaredLogger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	})

	logger.Infow("📊 Prometheus metrics server starting", "listen", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Fatalw("Metrics server failed", "error", err)
	}
}
