//! Userspace BPF Map Helpers
//!
//! High-level wrappers for reading/writing BPF maps via aya 0.13 API.

use aegis_common::*;
use anyhow::{Context, Result};
use aya::maps::{Array, HashMap, PerCpuArray};
use aya::Ebpf;
use log::{info, warn};
use std::net::Ipv4Addr;

/// Standard pin path for AegisShield BPF maps.
pub const BPF_PIN_PATH: &str = "/sys/fs/bpf/aegis";

/// Read aggregate statistics from the per-CPU stats array.
pub fn read_stats(bpf: &Ebpf) -> Result<Vec<(String, u64)>> {
    let stats_map: PerCpuArray<_, u64> =
        PerCpuArray::try_from(bpf.map("STATS").context("STATS map not found")?)?;

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

/// Print a formatted stats dashboard to stdout (updates in-place).
pub fn print_stats_dashboard(stats: &[(String, u64)]) {
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PREV_LINES: AtomicUsize = AtomicUsize::new(0);

    let prev = PREV_LINES.load(Ordering::Relaxed);
    let mut out = std::io::stdout().lock();

    // Move cursor up to overwrite previous output
    if prev > 0 {
        write!(out, "\x1b[{}A\r", prev).ok();
    }

    // Count lines as we print
    let mut lines = 0;

    writeln!(out, "╔═══════════════════════════════════════════════╗").ok();
    lines += 1;
    writeln!(out, "║        AegisShield XDP Statistics             ║").ok();
    lines += 1;
    writeln!(out, "╠═══════════════════════════════════════════════╣").ok();
    lines += 1;

    for (name, value) in stats {
        writeln!(out, "║  {:<25} {:>15} ║", name, format_number(*value)).ok();
        lines += 1;
    }

    writeln!(out, "╠═══════════════════════════════════════════════╣").ok();
    lines += 1;
    writeln!(out, "║  Press Ctrl-C to stop                        ║").ok();
    lines += 1;
    writeln!(out, "╚═══════════════════════════════════════════════╝").ok();
    lines += 1;

    out.flush().ok();
    PREV_LINES.store(lines, Ordering::Relaxed);
}

/// Load the IP blocklist from config into the BPF HashMap.
pub fn load_blocklist(bpf: &mut Ebpf, ip_list: &[String]) -> Result<usize> {
    let mut blocklist_map: HashMap<_, u32, u64> = HashMap::try_from(
        bpf.map_mut("BLOCKLIST")
            .context("BLOCKLIST map not found")?,
    )?;

    let mut count = 0;
    for ip_str in ip_list {
        match ip_str.parse::<Ipv4Addr>() {
            Ok(ip) => {
                let ip_u32 = u32::from(ip);
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
    bpf: &mut Ebpf,
    udp_pps: u64,
    syn_flood: u64,
    icmp_pps: u64,
    dns_max_size: u16,
    frag_policy: u8,
    conntrack_enabled: bool,
    cookie_secret: u32,
) -> Result<()> {
    let mut config_map: Array<_, GlobalConfig> =
        Array::try_from(bpf.map_mut("CONFIG").context("CONFIG map not found")?)?;

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

    config_map
        .set(0, cfg, 0)
        .context("Write GlobalConfig to BPF map")?;
    info!(
        "XDP config updated: UDP={} pps, SYN={} pps, ICMP={} pps, DNS max={}B",
        udp_pps, syn_flood, icmp_pps, dns_max_size
    );

    Ok(())
}

/// Load ACL rules into the ACL_RULES BPF Array.
pub fn load_acl_rules(bpf: &mut Ebpf, rules: &[crate::config::AclRuleConfig]) -> Result<usize> {
    let mut acl_map: Array<_, AclRule> = Array::try_from(
        bpf.map_mut("ACL_RULES")
            .context("ACL_RULES map not found")?,
    )?;

    let mut count = 0;
    for (i, rule) in rules.iter().enumerate() {
        if i >= MAX_ACL_RULES as usize {
            warn!(
                "Maximum ACL rules ({}) reached, ignoring remaining",
                MAX_ACL_RULES
            );
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
            direction: 2,
        };

        acl_map
            .set(i as u32, bpf_rule, 0)
            .context(format!("Write ACL rule {} to BPF map", i))?;
        count += 1;
    }

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
