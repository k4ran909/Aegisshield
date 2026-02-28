package config

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level AegisShield configuration.
type Config struct {
	Thresholds   ThresholdConfig    `yaml:"thresholds"`
	Blocklist    []string           `yaml:"blocklist"`
	ACLRules     []ACLRuleConfig    `yaml:"acl_rules"`
	Minecraft    MinecraftConfig    `yaml:"minecraft"`
	ControlPlane ControlPlaneConfig `yaml:"control_plane"`
	Logging      LoggingConfig      `yaml:"logging"`
	Alerts       AlertConfig        `yaml:"alerts"`
	BGP          BGPConfig          `yaml:"bgp"`
	Tunnel       TunnelConfig       `yaml:"tunnel"`
}

type ThresholdConfig struct {
	UDPPPS          uint64 `yaml:"udp_pps"`
	SYNFlood        uint64 `yaml:"syn_flood"`
	ICMPPPS         uint64 `yaml:"icmp_pps"`
	DNSResponseSize uint16 `yaml:"dns_response_size"`
}

type ACLRuleConfig struct {
	Priority uint32 `yaml:"priority"`
	Protocol string `yaml:"protocol"`
	SrcPort  uint16 `yaml:"src_port,omitempty"`
	DstPort  uint16 `yaml:"dst_port,omitempty"`
	Action   string `yaml:"action"`
}

type MinecraftConfig struct {
	Enabled     bool   `yaml:"enabled"`
	ServerPort  uint16 `yaml:"server_port"`
	MaxConnRate uint64 `yaml:"max_conn_rate"`
	MaxPingRate uint64 `yaml:"max_ping_rate"`
}

type ControlPlaneConfig struct {
	APIListen         string   `yaml:"api_listen"`
	MetricsListen     string   `yaml:"metrics_listen"`
	CooldownSeconds   uint64   `yaml:"cooldown_seconds"`
	AutoBlockDuration uint64   `yaml:"auto_block_duration"`
	ExposeRemote      bool     `yaml:"expose_remote"`
	AuthToken         string   `yaml:"auth_token"`
	AllowedOrigins    []string `yaml:"allowed_origins"`
	AllowedCIDRs      []string `yaml:"allowed_cidrs"`
}

type LoggingConfig struct {
	Level    string `yaml:"level"`
	Output   string `yaml:"output"`
	FilePath string `yaml:"file_path,omitempty"`
}

type AlertConfig struct {
	DiscordWebhook   string `yaml:"discord_webhook"`
	TelegramBotToken string `yaml:"telegram_bot_token"`
	TelegramChatID   string `yaml:"telegram_chat_id"`
}

type BGPConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Experimental  bool   `yaml:"experimental"`
	LocalASN      uint32 `yaml:"local_asn"`
	RouterID      string `yaml:"router_id"`
	AnycastPrefix string `yaml:"anycast_prefix"`
}

type TunnelConfig struct {
	Enabled           bool   `yaml:"enabled"`
	Experimental      bool   `yaml:"experimental"`
	Type              string `yaml:"type"`
	LocalIP           string `yaml:"local_ip"`
	RemoteIP          string `yaml:"remote_ip"`
	InterfaceName     string `yaml:"interface_name"`
	MTU               int    `yaml:"mtu"`
	KeepaliveInterval int    `yaml:"keepalive_interval"`
}

// Load reads and parses the YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := &Config{
		Thresholds: ThresholdConfig{
			UDPPPS:          1000,
			SYNFlood:        5000,
			ICMPPPS:         50,
			DNSResponseSize: 512,
		},
		Minecraft: MinecraftConfig{
			ServerPort:  25565,
			MaxConnRate: 10,
			MaxPingRate: 5,
		},
		ControlPlane: ControlPlaneConfig{
			APIListen:         "127.0.0.1:9090",
			MetricsListen:     "127.0.0.1:9100",
			CooldownSeconds:   60,
			AutoBlockDuration: 300,
			ExposeRemote:      false,
			AllowedOrigins:    []string{},
			AllowedCIDRs:      []string{"127.0.0.1/32"},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Output: "stdout",
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate enforces secure-by-default control-plane settings.
func (c *Config) Validate() error {
	if c.ControlPlane.ExposeRemote {
		if c.ControlPlane.AuthToken == "" {
			return fmt.Errorf("control_plane.auth_token is required when expose_remote=true")
		}
		if len(c.ControlPlane.AllowedCIDRs) == 0 {
			return fmt.Errorf("control_plane.allowed_cidrs is required when expose_remote=true")
		}
	} else {
		if !isLoopbackBind(c.ControlPlane.APIListen) {
			return fmt.Errorf("control_plane.api_listen must be loopback when expose_remote=false")
		}
		if !isLoopbackBind(c.ControlPlane.MetricsListen) {
			return fmt.Errorf("control_plane.metrics_listen must be loopback when expose_remote=false")
		}
	}

	for _, cidr := range c.ControlPlane.AllowedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid CIDR in control_plane.allowed_cidrs (%s): %w", cidr, err)
		}
	}

	return nil
}

func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
