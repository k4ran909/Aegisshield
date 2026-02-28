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

func main() {
	zapCfg := zap.NewProductionConfig()
	zapCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	zapLogger, err := zapCfg.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer zapLogger.Sync()
	logger := zapLogger.Sugar()

	cfgPath := "configs/aegis.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		logger.Fatalw("Failed to load config", "path", cfgPath, "error", err)
	}
	logger.Infow("Configuration loaded", "path", cfgPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	bpfMgr := bpf.NewManager("/sys/fs/bpf/aegis", logger)
	detector := engine.NewDetector(engine.DefaultDetectorConfig(), logger)
	mitigationEngine := engine.New(cfg, bpfMgr, logger)
	responder := engine.NewResponder(cfg, bpfMgr, logger)
	go responder.RunExpiryLoop(ctx)

	notifierCfg := alerts.Config{
		DiscordWebhook:   cfg.Alerts.DiscordWebhook,
		TelegramBotToken: cfg.Alerts.TelegramBotToken,
		TelegramChatID:   cfg.Alerts.TelegramChatID,
	}
	notifier := alerts.NewNotifier(notifierCfg, logger)
	go notifier.RunAlertLoop(ctx, responder.GetAlertChannel())

	if cfg.BGP.Enabled {
		if !cfg.BGP.Experimental {
			logger.Warn("BGP is enabled but not marked experimental; skipping startup")
		} else {
			bgpCfg := bgp.Config{
				Enabled:       true,
				LocalASN:      cfg.BGP.LocalASN,
				RouterID:      cfg.BGP.RouterID,
				AnycastPrefix: cfg.BGP.AnycastPrefix,
			}
			bgpMgr := bgp.NewManager(bgpCfg, logger)
			if err := bgpMgr.Start(ctx); err != nil {
				logger.Warnw("BGP failed to start (non-fatal)", "error", err)
			}
		}
	}

	if cfg.Tunnel.Enabled {
		if !cfg.Tunnel.Experimental {
			logger.Warn("Tunnel is enabled but not marked experimental; skipping startup")
		} else {
			tunnelCfg := tunnel.Config{
				Enabled:           true,
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
		}
	}

	var botDetector *minecraft.BotDetector
	if cfg.Minecraft.Enabled {
		botDetector = minecraft.NewBotDetector(int(cfg.Minecraft.MaxConnRate), logger)
		logger.Infow("Minecraft bot detector enabled", "server_port", cfg.Minecraft.ServerPort)
	}

	go metrics.StartServer(cfg.ControlPlane.MetricsListen, logger)

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

	logger.Infow("AegisShield is active",
		"api", cfg.ControlPlane.APIListen,
		"metrics", cfg.ControlPlane.MetricsListen,
		"minecraft", cfg.Minecraft.Enabled,
		"bgp_experimental", cfg.BGP.Enabled && cfg.BGP.Experimental,
		"tunnel_experimental", cfg.Tunnel.Enabled && cfg.Tunnel.Experimental,
	)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case sig := <-sigCh:
			logger.Infow("Received signal, shutting down", "signal", sig)
			cancel()
			_ = bpfMgr.Close()
			logger.Info("AegisShield stopped gracefully")
			return

		case <-ticker.C:
			stats, err := bpfMgr.ReadStats()
			if err != nil {
				logger.Warnw("Failed to read BPF stats", "error", err)
				continue
			}

			mitigationEngine.Ingest(stats)
			anomalies := detector.Ingest(stats)
			if len(anomalies) > 0 {
				responder.Respond(anomalies)
			}

			metrics.CurrentPPS.Set(float64(stats.RxPPS))
			metrics.CurrentDropPPS.Set(float64(stats.DropPPS))

			_ = botDetector
		}
	}
}
