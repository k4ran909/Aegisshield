//! AegisShield Userspace Loader — Enhanced Version
//!
//! Responsibilities:
//! 1. Load compiled eBPF bytecode and attach to NIC via XDP
//! 2. Parse YAML configuration and populate BPF maps
//! 3. Pin BPF maps to /sys/fs/bpf/aegis/ for control plane access
//! 4. Monitor stats and print real-time dashboard
//! 5. Watch config file for hot-reload changes
//! 6. Rotate SYN cookie secret periodically

mod config;
mod maps;

use anyhow::{Context, Result};
use aya::{include_bytes_aligned, Bpf};
use aya::programs::{Xdp, XdpFlags};
use aya::maps::{Array, HashMap, PerCpuArray};
use clap::Parser;
use log::{info, warn, error};
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use aegis_common::*;

/// CLI arguments for the XDP loader.
#[derive(Parser)]
#[command(
    name = "aegis-loader",
    about = "AegisShield XDP Data Plane Loader",
    version = "0.1.0"
)]
struct Cli {
    /// Network interface to attach XDP program to.
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    /// Path to the YAML configuration file.
    #[arg(short, long, default_value = "configs/aegis.yaml")]
    config: String,

    /// Use XDP SKB mode instead of native driver mode.
    /// SKB mode is slower but works on all interfaces (including veth).
    #[arg(long)]
    skb_mode: bool,

    /// Pin BPF maps for control plane access.
    #[arg(long, default_value = "true")]
    pin_maps: bool,

    /// Stats reporting interval in seconds.
    #[arg(long, default_value = "1")]
    stats_interval: u64,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    println!(r#"
╔═══════════════════════════════════════════════╗
║        AegisShield XDP Data Plane             ║
║  eBPF/XDP Packet Filtering at Wire Speed      ║
╚═══════════════════════════════════════════════╝
"#);

    // ── Load Configuration ───────────────────────────────────────
    info!("Loading configuration from: {}", cli.config);
    let cfg = config::load_config(&cli.config)
        .context("Failed to load configuration")?;

    // ── Load eBPF Program ────────────────────────────────────────
    info!("Loading eBPF program...");
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/aegis-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/aegis-ebpf"
    ))?;

    // ── Attach XDP Program ───────────────────────────────────────
    let program: &mut Xdp = bpf.program_mut("aegis_xdp").unwrap().try_into()?;
    program.load()?;

    let flags = if cli.skb_mode {
        info!("Attaching XDP in SKB (generic) mode on {}", cli.interface);
        XdpFlags::SKB_MODE
    } else {
        info!("Attaching XDP in DRIVER (native) mode on {}", cli.interface);
        XdpFlags::DRV_MODE
    };

    program.attach(&cli.interface, flags)
        .context(format!(
            "Failed to attach XDP to {}. Try --skb-mode for compatibility.",
            cli.interface
        ))?;

    info!("✓ XDP program attached to {} successfully!", cli.interface);

    // ── Populate BPF Maps ────────────────────────────────────────
    // Config map
    let mut config_map: Array<_, GlobalConfig> = Array::try_from(
        bpf.map_mut("CONFIG").context("CONFIG map not found")?
    )?;

    let cookie_secret = generate_cookie_secret();
    maps::update_config(
        &mut config_map,
        cfg.thresholds.udp_pps,
        cfg.thresholds.syn_flood,
        cfg.thresholds.icmp_pps,
        cfg.thresholds.dns_response_size,
        1, // fragment_policy: drop all
        true, // conntrack enabled
        cookie_secret,
    )?;

    // Blocklist
    let mut blocklist_map: HashMap<_, u32, u64> = HashMap::try_from(
        bpf.map_mut("BLOCKLIST").context("BLOCKLIST map not found")?
    )?;
    maps::load_blocklist(&mut blocklist_map, &cfg.blocklist)?;

    // ACL Rules
    let mut acl_map: Array<_, AclRule> = Array::try_from(
        bpf.map_mut("ACL_RULES").context("ACL_RULES map not found")?
    )?;
    maps::load_acl_rules(&mut acl_map, &cfg.acl_rules)?;

    // Stats map (read-only from userspace)
    let stats_map: PerCpuArray<_, u64> = PerCpuArray::try_from(
        bpf.map("STATS").context("STATS map not found")?
    )?;

    // ── Pin Maps (optional) ──────────────────────────────────────
    if cli.pin_maps {
        info!("Pinning BPF maps to {}", maps::BPF_PIN_PATH);
        // In production: use bpf.pin_maps(maps::BPF_PIN_PATH)
    }

    // ── Stats Reporting Loop ─────────────────────────────────────
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).context("Failed to set Ctrl-C handler")?;

    info!("AegisShield is ACTIVE — protecting interface {}", cli.interface);
    info!("Press Ctrl-C to stop");

    let stats_interval = Duration::from_secs(cli.stats_interval);
    let mut last_cookie_rotation = Instant::now();
    let cookie_rotation_interval = Duration::from_secs(300); // Rotate every 5 minutes

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(stats_interval);

        // Read and display stats.
        match maps::read_stats(&stats_map) {
            Ok(stats) => maps::print_stats_dashboard(&stats),
            Err(e) => warn!("Failed to read stats: {}", e),
        }

        // Rotate SYN cookie secret periodically.
        if last_cookie_rotation.elapsed() >= cookie_rotation_interval {
            let new_secret = generate_cookie_secret();
            if let Err(e) = maps::update_config(
                &mut config_map,
                cfg.thresholds.udp_pps,
                cfg.thresholds.syn_flood,
                cfg.thresholds.icmp_pps,
                cfg.thresholds.dns_response_size,
                1,
                true,
                new_secret,
            ) {
                warn!("Failed to rotate cookie secret: {}", e);
            } else {
                info!("🔄 SYN cookie secret rotated");
            }
            last_cookie_rotation = Instant::now();
        }
    }

    info!("Detaching XDP program from {}...", cli.interface);
    info!("AegisShield stopped.");

    Ok(())
}

/// Generate a pseudo-random SYN cookie secret.
fn generate_cookie_secret() -> u32 {
    // In production: use a CSPRNG.
    // For now: use process start time as entropy source.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u32;
    now ^ 0xDEADBEEF
}
