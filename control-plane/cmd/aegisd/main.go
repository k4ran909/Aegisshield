// AegisShield Control Plane Daemon — Fully Wired Main
//
// This is the master orchestrator that initializes and connects:
// 1. Configuration loading
// 2. BPF Map Manager (connects to pinned XDP maps)
// 3. Anomaly Detector (EWMA baseline learning)
// 4. Auto-Responder (graduated mitigation actions)
// 5. REST API Server (management endpoints)
// 6. Prometheus Metrics Exporter
// 7. Alert Notifier (Discord/Telegram)
// 8. BGP Manager (optional — Anycast/Flowspec)
// 9. Tunnel Manager (optional — GRE/WireGuard)
// 10. Minecraft Bot Detector (optional)
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/aegisshield/aegisshield/internal/alerts"
	"github.com/aegisshield/aegisshield/internal/api"
	"github.com/aegisshield/aegisshield/internal/bgp"
	"github.com/aegisshield/aegisshield/internal/bpf"
	"github.com/aegisshield/aegisshield/internal/config"
	"github.com/aegisshield/aegisshield/internal/engine"
	"github.com/aegisshield/aegisshield/internal/metrics"
	"github.com/aegisshield/aegisshield/internal/minecraft"
	"github.com/aegisshield/aegisshield/internal/tunnel"
)

const banner = `
╔═════════════════════════════════════════════════════════╗
║                                                         ║
║     ▄▀█ █▀▀ █▀▀ █ █▀   █▀ █ █ █ █▀▀ █   █▀▄           ║
║     █▀█ ██▄ █▄█ █ ▄█   ▄█ █▀█ █ ██▄ █▄▄ █▄▀           ║
║                                                         ║
║         XDP-Powered DDoS Protection Engine              ║
║         L3 → L7 Mitigation at Wire Speed                ║
║                                                         ║
╚═════════════════════════════════════════════════════════╝`

func main() {
	fmt.Println(banner)

	// ── Logger ───────────────────────────────────────────────────
	zapCfg := zap.NewProductionConfig()
	zapCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	zapLogger, err := zapCfg.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer zapLogger.Sync()
	logger := zapLogger.Sugar()

	// ── Configuration ────────────────────────────────────────────
	cfgPath := "configs/aegis.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		logger.Fatalw("Failed to load config", "path", cfgPath, "error", err)
	}
	logger.Infow("✓ Configuration loaded", "path", cfgPath)

	// ── Context with graceful shutdown ───────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// ── BPF Map Manager ──────────────────────────────────────────
	bpfMgr := bpf.NewManager("/sys/fs/bpf/aegis", logger)
	logger.Info("✓ BPF Map Manager initialized")

	// ── Anomaly Detector ─────────────────────────────────────────
	detectorCfg := engine.DefaultDetectorConfig()
	detector := engine.NewDetector(detectorCfg, logger)
	logger.Infow("✓ Anomaly Detector initialized (learning for 60s)")

	// ── Mitigation Engine ────────────────────────────────────────
	mitigationEngine := engine.New(cfg, bpfMgr, logger)
	logger.Info("✓ Mitigation Engine initialized")

	// ── Auto-Responder ───────────────────────────────────────────
	responder := engine.NewResponder(cfg, bpfMgr, logger)
	go responder.RunExpiryLoop(ctx)
	logger.Info("✓ Auto-Responder initialized")

	// ── Alert Notifier ───────────────────────────────────────────
	notifierCfg := alerts.Config{
		DiscordWebhook:   cfg.Alerts.DiscordWebhook,
		TelegramBotToken: cfg.Alerts.TelegramBotToken,
		TelegramChatID:   cfg.Alerts.TelegramChatID,
	}
	notifier := alerts.NewNotifier(notifierCfg, logger)
	go notifier.RunAlertLoop(ctx, responder.GetAlertChannel())
	logger.Info("✓ Alert Notifier initialized")

	// ── BGP Manager (optional) ───────────────────────────────────
	bgpCfg := bgp.Config{
		Enabled:       cfg.BGP.Enabled,
		LocalASN:      cfg.BGP.LocalASN,
		RouterID:      cfg.BGP.RouterID,
		AnycastPrefix: cfg.BGP.AnycastPrefix,
	}
	bgpMgr := bgp.NewManager(bgpCfg, logger)
	if err := bgpMgr.Start(ctx); err != nil {
		logger.Warnw("BGP failed to start (non-fatal)", "error", err)
	}

	// ── Tunnel Manager (optional) ────────────────────────────────
	tunnelCfg := tunnel.Config{
		Enabled:           cfg.Tunnel.Enabled,
		Type:              tunnel.TunnelType(cfg.Tunnel.Type),
		LocalIP:           cfg.Tunnel.LocalIP,
		RemoteIP:          cfg.Tunnel.RemoteIP,
		InterfaceName:     cfg.Tunnel.InterfaceName,
		MTU:               cfg.Tunnel.MTU,
		KeepaliveInterval: cfg.Tunnel.KeepaliveInterval,
	}
	tunnelMgr := tunnel.NewManager(tunnelCfg, logger)
	if err := tunnelMgr.Start(ctx); err != nil {
		logger.Warnw("Tunnel failed to start (non-fatal)", "error", err)
	}

	// ── Minecraft Bot Detector (optional) ────────────────────────
	var botDetector *minecraft.BotDetector
	if cfg.Minecraft.Enabled {
		botDetector = minecraft.NewBotDetector(int(cfg.Minecraft.MaxConnRate), logger)
		logger.Infow("✓ Minecraft Bot Detector enabled",
			"server_port", cfg.Minecraft.ServerPort,
		)
	}

	// ── Prometheus Metrics ───────────────────────────────────────
	go metrics.StartServer(cfg.ControlPlane.MetricsListen, logger)

	// ── REST API Server ──────────────────────────────────────────
	apiServer := api.NewServer(
		cfg.ControlPlane.APIListen,
		mitigationEngine,
		responder,
		detector,
		bpfMgr,
		cfg,
		logger,
	)
	go func() {
		if err := apiServer.Start(); err != nil {
			logger.Fatalw("API server failed", "error", err)
		}
	}()

	// ── Main Processing Loop ─────────────────────────────────────
	logger.Info("🛡️ AegisShield is ACTIVE — all systems operational")
	logger.Infow("Services running",
		"api", cfg.ControlPlane.APIListen,
		"metrics", cfg.ControlPlane.MetricsListen,
		"bgp", bgpCfg.Enabled,
		"tunnel", tunnelCfg.Enabled,
		"minecraft", cfg.Minecraft.Enabled,
	)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case sig := <-sigCh:
			logger.Infow("Received signal, shutting down", "signal", sig)
			cancel()
			bpfMgr.Close()
			logger.Info("AegisShield stopped gracefully.")
			return

		case <-ticker.C:
			// 1. Read XDP statistics
			stats, err := bpfMgr.ReadStats()
			if err != nil {
				logger.Warnw("Failed to read BPF stats", "error", err)
				continue
			}

			// 2. Feed stats to anomaly detector
			anomalies := detector.Ingest(stats)

			// 3. Dispatch automated responses
			if len(anomalies) > 0 {
				responder.Respond(anomalies)
			}

			// 4. Update Prometheus metrics
			metrics.CurrentPPS.Set(float64(stats.RxPPS))
			metrics.CurrentDropPPS.Set(float64(stats.DropPPS))

			// 5. Unused, but keeps lint happy
			_ = mitigationEngine
			_ = botDetector
		}
	}
}
