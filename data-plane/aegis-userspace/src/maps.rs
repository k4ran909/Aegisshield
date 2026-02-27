//! Userspace BPF Map Helpers
//!
//! High-level wrappers for reading and writing pinned BPF maps.
//! The XDP loader pins maps to /sys/fs/bpf/aegis/*, and this module
//! opens those pinned maps for configuration updates and stats reading.

use anyhow::{Context, Result, bail};
use aya::maps::{HashMap, Array, PerCpuArray, PerCpuValues, MapData};
use std::net::Ipv4Addr;
use std::path::Path;
use log::{info, warn};
use aegis_common::*;

/// Standard pin path for AegisShield BPF maps.
pub const BPF_PIN_PATH: &str = "/sys/fs/bpf/aegis";

/// Read aggregate statistics from the per-CPU stats array.
/// Sums values across all CPUs for each stat index.
pub fn read_stats(stats_map: &PerCpuArray<MapData, u64>) -> Result<Vec<(String, u64)>> {
    let mut results = Vec::new();

    for idx in 0..NUM_STATS {
        let per_cpu_vals = stats_map
            .get(&idx, 0)
            .context(format!("Read stat index {}", idx))?;

        let total: u64 = per_cpu_vals.iter().sum();
        let name = stat_name(idx).to_string();
        results.push((name, total));
    }

    Ok(results)
}

/// Print a formatted stats dashboard to stdout.
pub fn print_stats_dashboard(stats: &[(String, u64)]) {
    println!("╔═══════════════════════════════════════════════╗");
    println!("║        AegisShield XDP Statistics             ║");
    println!("╠═══════════════════════════════════════════════╣");

    for (name, value) in stats {
        println!("║  {:<25} {:>15} ║", name, format_number(*value));
    }

    println!("╚═══════════════════════════════════════════════╝");
}

/// Load the IP blocklist from a config list into the BPF HashMap.
pub fn load_blocklist(
    blocklist_map: &mut HashMap<MapData, u32, u64>,
    ip_list: &[String],
) -> Result<usize> {
    let mut count = 0;

    for ip_str in ip_list {
        match ip_str.parse::<Ipv4Addr>() {
            Ok(ip) => {
                let ip_u32 = u32::from(ip);
                // Value = 1 (blocked permanently) or timestamp for auto-expiry.
                blocklist_map
                    .insert(ip_u32, 1u64, 0)
                    .context(format!("Insert blocklist entry for {}", ip_str))?;
                count += 1;
                info!("Blocked IP: {}", ip_str);
            }
            Err(e) => {
                warn!("Invalid IP in blocklist '{}': {}", ip_str, e);
            }
        }
    }

    info!("Loaded {} IPs into XDP blocklist", count);
    Ok(count)
}

/// Push the global configuration to the CONFIG BPF Array.
pub fn update_config(
    config_map: &mut Array<MapData, GlobalConfig>,
    udp_pps: u64,
    syn_flood: u64,
    icmp_pps: u64,
    dns_max_size: u16,
    frag_policy: u8,
    conntrack_enabled: bool,
    cookie_secret: u32,
) -> Result<()> {
    let cfg = GlobalConfig {
        udp_rate_threshold: udp_pps,
        syn_flood_threshold: syn_flood,
        icmp_rate_threshold: icmp_pps,
        dns_max_response_size: dns_max_size,
        fragment_policy: frag_policy,
        conntrack_enabled: if conntrack_enabled { 1 } else { 0 },
        syn_cookie_secret: cookie_secret,
        _pad: [0u8; 4],
    };

    config_map.set(0, cfg, 0).context("Write GlobalConfig to BPF map")?;
    info!(
        "XDP config updated: UDP={} pps, SYN={} pps, ICMP={} pps, DNS max={}B, frag={}, conntrack={}",
        udp_pps, syn_flood, icmp_pps, dns_max_size, frag_policy, conntrack_enabled
    );

    Ok(())
}

/// Load ACL rules into the ACL_RULES BPF Array.
pub fn load_acl_rules(
    acl_map: &mut Array<MapData, AclRule>,
    rules: &[crate::config::AclRuleConfig],
) -> Result<usize> {
    let mut count = 0;

    for (i, rule) in rules.iter().enumerate() {
        if i >= MAX_ACL_RULES as usize {
            warn!("Maximum ACL rules ({}) reached, ignoring remaining", MAX_ACL_RULES);
            break;
        }

        let protocol = match rule.protocol.as_str() {
            "tcp" | "TCP" => 6u8,
            "udp" | "UDP" => 17u8,
            "icmp" | "ICMP" => 1u8,
            "gre" | "GRE" => 47u8,
            "any" | "*" => 0u8,
            _ => {
                warn!("Unknown protocol '{}' in ACL rule {}", rule.protocol, i);
                continue;
            }
        };

        let action = match rule.action.as_str() {
            "allow" | "ALLOW" | "pass" | "PASS" => 1u8,
            "deny" | "DENY" | "drop" | "DROP" => 0u8,
            _ => {
                warn!("Unknown action '{}' in ACL rule {}", rule.action, i);
                continue;
            }
        };

        let bpf_rule = AclRule {
            priority: rule.priority,
            protocol,
            enabled: 1,
            dst_port: rule.dst_port.unwrap_or(0),
            src_port: rule.src_port.unwrap_or(0),
            action,
            direction: 2, // Both directions
        };

        acl_map.set(i as u32, bpf_rule, 0)
            .context(format!("Write ACL rule {} to BPF map", i))?;
        count += 1;
    }

    // Disable remaining slots.
    for i in count..MAX_ACL_RULES as usize {
        let empty_rule = AclRule {
            priority: i as u32,
            protocol: 0,
            enabled: 0,
            dst_port: 0,
            src_port: 0,
            action: 1,
            direction: 0,
        };
        let _ = acl_map.set(i as u32, empty_rule, 0);
    }

    info!("Loaded {} ACL rules into XDP firewall", count);
    Ok(count)
}

/// Add a single IP to the blocklist (for runtime updates via API).
pub fn block_ip(
    blocklist_map: &mut HashMap<MapData, u32, u64>,
    ip: Ipv4Addr,
    expiry_ns: u64,
) -> Result<()> {
    let ip_u32 = u32::from(ip);
    blocklist_map
        .insert(ip_u32, expiry_ns, 0)
        .context(format!("Block IP {}", ip))?;
    info!("🔒 Blocked IP {} (expiry: {}ns)", ip, expiry_ns);
    Ok(())
}

/// Remove a single IP from the blocklist.
pub fn unblock_ip(
    blocklist_map: &mut HashMap<MapData, u32, u64>,
    ip: Ipv4Addr,
) -> Result<()> {
    let ip_u32 = u32::from(ip);
    blocklist_map
        .remove(&ip_u32)
        .context(format!("Unblock IP {}", ip))?;
    info!("🔓 Unblocked IP {}", ip);
    Ok(())
}

/// Format a large number with comma separators.
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}
