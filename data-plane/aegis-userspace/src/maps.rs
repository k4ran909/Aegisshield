//! Userspace BPF map helpers.

use aegis_common::*;
use anyhow::{Context, Result};
use aya::maps::{Array, HashMap, PerCpuArray};
use aya::Ebpf;
use log::{debug, info, warn};
use std::collections::HashMap as StdHashMap;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

/// Standard pin path for AegisShield BPF maps.
pub const BPF_PIN_PATH: &str = "/sys/fs/bpf/aegis";

const DASH_WIDTH: usize = 90;
const STAT_ORDER: [&str; 14] = [
    "rx_packets",
    "dropped_total",
    "passed_total",
    "tx_packets",
    "blocklist_drops",
    "acl_drops",
    "udp_rate_drops",
    "syn_flood_drops",
    "icmp_rate_drops",
    "dns_amp_drops",
    "gre_flood_drops",
    "fragment_drops",
    "conntrack_bypass",
    "syn_cookies_sent",
];

/// Live terminal dashboard renderer.
pub struct Dashboard {
    interface: String,
    refresh_every: Duration,
    started_at: Instant,
    last_render_at: Instant,
    previous: StdHashMap<String, u64>,
    frame: u64,
    event_line: String,
}

impl Dashboard {
    /// Create a new dashboard renderer.
    pub fn new(interface: impl Into<String>, refresh_every: Duration) -> Self {
        let now = Instant::now();
        Self {
            interface: interface.into(),
            refresh_every,
            started_at: now,
            last_render_at: now,
            previous: StdHashMap::new(),
            frame: 0,
            event_line: "Dashboard online".to_string(),
        }
    }

    /// Record a short status event shown in the next frame.
    pub fn set_event(&mut self, event: impl Into<String>) {
        self.event_line = event.into();
    }

    /// Render one full dashboard frame.
    pub fn render(&mut self, stats: &[(String, u64)]) {
        let mut out = std::io::stdout().lock();
        let now = Instant::now();
        let elapsed = now
            .saturating_duration_since(self.last_render_at)
            .as_secs_f64()
            .max(1.0);

        let current: StdHashMap<String, u64> = stats.iter().cloned().collect();

        let rx = lookup(&current, "rx_packets");
        let dropped = lookup(&current, "dropped_total");
        let passed = lookup(&current, "passed_total");
        let prev_rx = lookup_or(&self.previous, "rx_packets", rx);
        let prev_drop = lookup_or(&self.previous, "dropped_total", dropped);
        let prev_pass = lookup_or(&self.previous, "passed_total", passed);

        let rx_pps = rate(rx, prev_rx, elapsed);
        let drop_pps = rate(dropped, prev_drop, elapsed);
        let pass_pps = rate(passed, prev_pass, elapsed);
        let drop_ratio = ratio(dropped, rx);
        let pass_ratio = ratio(passed, rx);

        // Hide cursor and redraw the whole frame to avoid line corruption.
        write!(out, "\x1b[?25l\x1b[2J\x1b[H").ok();

        print_border(&mut out, '=');
        print_line(
            &mut out,
            "AegisShield Tactical Console | eBPF/XDP Wire-Speed Guard",
        );
        print_border(&mut out, '-');

        print_line(
            &mut out,
            &format!(
                "Interface: {:<12}  Refresh: {:>2}s  Uptime: {:<10}  Frame: {}",
                self.interface,
                self.refresh_every.as_secs(),
                format_duration(now.saturating_duration_since(self.started_at)),
                self.frame
            ),
        );
        print_line(
            &mut out,
            &format!(
                "Flow rate: RX {:>10}/s | PASS {:>10}/s | DROP {:>10}/s",
                format_number(rx_pps),
                format_number(pass_pps),
                format_number(drop_pps)
            ),
        );
        print_line(
            &mut out,
            &format!(
                "Traffic mix: PASS {:>6.2}% | DROP {:>6.2}% | Event: {}",
                pass_ratio, drop_ratio, self.event_line
            ),
        );
        print_border(&mut out, '-');
        print_line(
            &mut out,
            "Metric                        Total              Rate/s              Signal",
        );
        print_border(&mut out, '-');

        for metric in STAT_ORDER {
            let total = lookup(&current, metric);
            let prev = lookup_or(&self.previous, metric, total);
            let per_sec = rate(total, prev, elapsed);
            let signal = signal_for(metric, per_sec);
            print_line(
                &mut out,
                &format!(
                    "{:<26} {:>16} {:>18} {:>18}",
                    metric,
                    format_number(total),
                    format_number(per_sec),
                    signal
                ),
            );
        }

        print_border(&mut out, '-');
        print_line(
            &mut out,
            "Controls: Ctrl-C stop | API panel: http://127.0.0.1:9090/ui/",
        );
        print_border(&mut out, '=');
        out.flush().ok();

        self.previous = current;
        self.last_render_at = now;
        self.frame = self.frame.saturating_add(1);
    }

    /// Restore terminal cursor visibility.
    pub fn shutdown(&self) {
        let mut out = std::io::stdout().lock();
        write!(out, "\x1b[0m\x1b[?25h\n").ok();
        out.flush().ok();
    }
}

impl Drop for Dashboard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Pin shared maps so the control plane can open them from bpffs.
pub fn pin_maps(bpf: &mut Ebpf, pin_path: &str) -> Result<()> {
    std::fs::create_dir_all(pin_path)
        .with_context(|| format!("Create BPF pin path {}", pin_path))?;

    let pin_targets = ["STATS", "BLOCKLIST", "CONFIG", "ACL_RULES"];
    for map_name in pin_targets {
        let target = Path::new(pin_path).join(map_name);
        if target.exists() {
            std::fs::remove_file(&target)
                .with_context(|| format!("Remove existing pin {}", target.display()))?;
        }
        let map = bpf
            .map_mut(map_name)
            .with_context(|| format!("Map {} not found for pinning", map_name))?;
        map.pin(&target)
            .with_context(|| format!("Pin map {} at {}", map_name, target.display()))?;
    }

    info!("Pinned shared maps at {}", pin_path);
    Ok(())
}

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
                    .insert(ip_u32, 0u64, 0)
                    .context(format!("Insert blocklist entry for {}", ip_str))?;
                count += 1;
                debug!("Blocked IP from config: {}", ip_str);
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
    debug!(
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

    // Deterministic priority order: lower number first, stable by original order.
    let mut sorted_rules = rules.to_vec();
    sorted_rules.sort_by_key(|r| r.priority);

    let mut count = 0;
    for (i, rule) in sorted_rules.iter().enumerate() {
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

fn print_border(out: &mut impl Write, fill: char) {
    let border = fill.to_string().repeat(DASH_WIDTH + 2);
    writeln!(out, "+{}+", border).ok();
}

fn print_line(out: &mut impl Write, text: &str) {
    let clean = if text.len() > DASH_WIDTH {
        let mut clipped = text.to_string();
        clipped.truncate(DASH_WIDTH);
        clipped
    } else {
        text.to_string()
    };
    writeln!(out, "| {:<width$} |", clean, width = DASH_WIDTH).ok();
}

fn lookup(stats: &StdHashMap<String, u64>, key: &str) -> u64 {
    *stats.get(key).unwrap_or(&0)
}

fn lookup_or(stats: &StdHashMap<String, u64>, key: &str, fallback: u64) -> u64 {
    *stats.get(key).unwrap_or(&fallback)
}

fn rate(current: u64, previous: u64, elapsed_seconds: f64) -> u64 {
    if current < previous || elapsed_seconds <= 0.0 {
        return 0;
    }
    ((current - previous) as f64 / elapsed_seconds) as u64
}

fn ratio(part: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (part as f64 / total as f64) * 100.0
}

fn signal_for(metric: &str, per_sec: u64) -> &'static str {
    if metric.contains("drop") {
        if per_sec >= 50_000 {
            "CRITICAL"
        } else if per_sec > 0 {
            "ACTIVE"
        } else {
            "CLEAR"
        }
    } else if metric == "conntrack_bypass" {
        if per_sec > 0 {
            "FASTPATH"
        } else {
            "IDLE"
        }
    } else if per_sec > 0 {
        "FLOW"
    } else {
        "IDLE"
    }
}

fn format_duration(duration: Duration) -> String {
    let total = duration.as_secs();
    let hours = total / 3600;
    let mins = (total % 3600) / 60;
    let secs = total % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
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
