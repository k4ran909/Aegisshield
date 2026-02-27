//! Configuration module — Parse YAML configuration into Rust structures.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

/// Top-level configuration.
#[derive(Debug, Deserialize)]
pub struct AegisConfig {
    pub thresholds: ThresholdConfig,
    #[serde(default)]
    pub blocklist: Vec<String>,
    #[serde(default)]
    pub acl_rules: Vec<AclRuleConfig>,
    #[serde(default)]
    pub minecraft: MinecraftConfig,
    #[serde(default)]
    pub control_plane: ControlPlaneConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Rate limiting thresholds.
#[derive(Debug, Deserialize)]
pub struct ThresholdConfig {
    #[serde(default = "default_udp_pps")]
    pub udp_pps: u64,
    #[serde(default = "default_syn_flood")]
    pub syn_flood: u64,
    #[serde(default = "default_icmp_pps")]
    pub icmp_pps: u64,
    #[serde(default = "default_dns_response_size")]
    pub dns_response_size: u16,
}

/// ACL rule from YAML.
#[derive(Debug, Deserialize)]
pub struct AclRuleConfig {
    pub priority: u32,
    pub protocol: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub action: String,
}

/// Minecraft-specific configuration.
#[derive(Debug, Deserialize, Default)]
pub struct MinecraftConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mc_port")]
    pub server_port: u16,
    #[serde(default = "default_mc_conn_rate")]
    pub max_conn_rate: u64,
    #[serde(default = "default_mc_ping_rate")]
    pub max_ping_rate: u64,
}

/// Control plane settings.
#[derive(Debug, Deserialize, Default)]
pub struct ControlPlaneConfig {
    #[serde(default = "default_api_listen")]
    pub api_listen: String,
    #[serde(default = "default_metrics_listen")]
    pub metrics_listen: String,
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: u64,
    #[serde(default = "default_block_duration")]
    pub auto_block_duration: u64,
}

/// Logging settings.
#[derive(Debug, Deserialize, Default)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_output")]
    pub output: String,
    pub file_path: Option<String>,
}

// Default value functions
fn default_udp_pps() -> u64 { 1000 }
fn default_syn_flood() -> u64 { 5000 }
fn default_icmp_pps() -> u64 { 50 }
fn default_dns_response_size() -> u16 { 512 }
fn default_mc_port() -> u16 { 25565 }
fn default_mc_conn_rate() -> u64 { 10 }
fn default_mc_ping_rate() -> u64 { 5 }
fn default_api_listen() -> String { "127.0.0.1:9090".to_string() }
fn default_metrics_listen() -> String { "0.0.0.0:9100".to_string() }
fn default_cooldown() -> u64 { 60 }
fn default_block_duration() -> u64 { 300 }
fn default_log_level() -> String { "info".to_string() }
fn default_log_output() -> String { "stdout".to_string() }

/// Load and parse the YAML configuration file.
pub fn load_config(path: &str) -> Result<AegisConfig> {
    let content = fs::read_to_string(path)
        .context(format!("Read config file: {}", path))?;

    let config: AegisConfig = serde_yaml::from_str(&content)
        .context("Parse YAML configuration")?;

    Ok(config)
}
