//! AegisShield userspace loader.
//!
//! Loads eBPF bytecode, attaches it via TC (Traffic Control) ingress, and manages shared BPF maps.
//! Uses TC instead of XDP for maximum kernel compatibility.

mod config;
mod maps;

use anyhow::{Context, Result};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;
use clap::Parser;
use log::{debug, info, warn};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// CLI arguments for the TC loader.
#[derive(Parser)]
#[command(
    name = "aegis-loader",
    about = "AegisShield TC/eBPF data plane loader",
    version = "0.3.0"
)]
struct Cli {
    /// Network interface to attach TC program to.
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    /// Path to the YAML configuration file.
    #[arg(short, long, default_value = "configs/aegis.yaml")]
    config: String,

    /// Pin BPF maps for control-plane access.
    #[arg(long, default_value = "true")]
    pin_maps: bool,

    /// Stats refresh interval in seconds.
    #[arg(long, default_value = "1")]
    stats_interval: u64,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    println!(
        r#"
    _                _     ____  _     _      _     _
   / \   ___  __ _  (_)___/ ___|| |__ (_) ___| | __| |
  / _ \ / _ \/ _` | | / __\___ \| '_ \| |/ _ \ |/ _` |
 / ___ \  __/ (_| | | \__ \___) | | | | |  __/ | (_| |
/_/   \_\___|\___, |_|_|___/____/|_| |_|_|\___|_|\__,_|
             |___/

  eBPF/TC packet filtering at wire speed  [v0.3.0]
  Mode: TC ingress (kernel-compatible)
"#
    );

    // ── Clean up any stale TC qdiscs ────────────────────────────────
    cleanup_tc(&cli.interface);

    info!("Loading configuration from {}", cli.config);
    let cfg = config::load_config(&cli.config).context("Failed to load configuration")?;

    info!("Loading eBPF program...");
    #[cfg(debug_assertions)]
    let ebpf_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/bpfel-unknown-none/debug/aegis-ebpf"
    );
    #[cfg(not(debug_assertions))]
    let ebpf_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/bpfel-unknown-none/release/aegis-ebpf"
    );

    info!("Loading eBPF from {}", ebpf_path);
    let ebpf_bytes =
        std::fs::read(ebpf_path).context(format!("Failed to read eBPF binary: {}", ebpf_path))?;
    info!("eBPF binary size: {} bytes", ebpf_bytes.len());

    let mut bpf = Ebpf::load(&ebpf_bytes).context("Failed to parse eBPF ELF object")?;

    // ── Add clsact qdisc (required for TC ingress) ──────────────────
    info!("Creating clsact qdisc on {}...", cli.interface);
    tc::qdisc_add_clsact(&cli.interface)
        .context(format!("Failed to add clsact qdisc on {}", cli.interface))?;

    // ── Load and attach TC classifier ───────────────────────────────
    let program: &mut SchedClassifier = bpf.program_mut("aegis_tc").unwrap().try_into()?;
    program.load()?;

    match program.attach(&cli.interface, TcAttachType::Ingress) {
        Ok(_) => {
            info!(
                "✓ TC classifier attached to {} ingress successfully!",
                cli.interface
            );
        }
        Err(e) => {
            anyhow::bail!(
                "Failed to attach TC classifier to {}: {}. Try: sudo tc qdisc del dev {} clsact",
                cli.interface,
                e,
                cli.interface
            );
        }
    }

    let cookie_secret = generate_cookie_secret();
    maps::update_config(
        &mut bpf,
        cfg.thresholds.udp_pps,
        cfg.thresholds.syn_flood,
        cfg.thresholds.icmp_pps,
        cfg.thresholds.dns_response_size,
        cfg.fragment_policy,
        cfg.conntrack_enabled,
        cookie_secret,
    )?;
    info!(
        "TC thresholds: UDP={}/s SYN={}/s ICMP={}/s DNS_MAX={}B",
        cfg.thresholds.udp_pps,
        cfg.thresholds.syn_flood,
        cfg.thresholds.icmp_pps,
        cfg.thresholds.dns_response_size
    );

    maps::load_blocklist(&mut bpf, &cfg.blocklist)?;
    maps::load_acl_rules(&mut bpf, &cfg.acl_rules)?;

    if cli.pin_maps {
        // Clean stale pins first
        let _ = std::fs::remove_dir_all(maps::BPF_PIN_PATH);
        info!("Pinning BPF maps to {}", maps::BPF_PIN_PATH);
        maps::pin_maps(&mut bpf, maps::BPF_PIN_PATH)?;
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let iface_for_handler = cli.interface.clone();
    ctrlc::set_handler(move || {
        eprintln!(
            "\n[!] Shutting down — detaching TC from {}...",
            iface_for_handler
        );
        cleanup_tc(&iface_for_handler);
        r.store(false, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl-C handler")?;

    info!(
        "AegisShield is ACTIVE — protecting interface {} via TC ingress (Ctrl-C to stop)",
        cli.interface
    );

    let stats_interval = Duration::from_secs(cli.stats_interval.max(1));
    let mut dashboard = maps::Dashboard::new(cli.interface.clone(), stats_interval);
    dashboard.set_event("TC classifier attached and map sync complete");

    let mut last_cookie_rotation = Instant::now();
    let cookie_rotation_interval = Duration::from_secs(300);

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(stats_interval);

        match maps::read_stats(&bpf) {
            Ok(stats) => dashboard.render(&stats),
            Err(err) => {
                dashboard.set_event(format!("stats read failed: {}", err));
            }
        }

        if last_cookie_rotation.elapsed() >= cookie_rotation_interval {
            let new_secret = generate_cookie_secret();
            if let Err(err) = maps::update_config(
                &mut bpf,
                cfg.thresholds.udp_pps,
                cfg.thresholds.syn_flood,
                cfg.thresholds.icmp_pps,
                cfg.thresholds.dns_response_size,
                cfg.fragment_policy,
                cfg.conntrack_enabled,
                new_secret,
            ) {
                dashboard.set_event(format!("cookie rotation failed: {}", err));
            } else {
                dashboard.set_event("SYN cookie secret rotated");
                debug!("SYN cookie secret rotated");
            }
            last_cookie_rotation = Instant::now();
        }
    }

    dashboard.shutdown();

    // Final cleanup
    info!("Detaching TC classifier from {}", cli.interface);
    cleanup_tc(&cli.interface);
    let _ = std::fs::remove_dir_all(maps::BPF_PIN_PATH);
    info!("AegisShield stopped cleanly");
    Ok(())
}

/// Clean up TC qdisc from the given interface.
fn cleanup_tc(interface: &str) {
    let _ = Command::new("tc")
        .args(["qdisc", "del", "dev", interface, "clsact"])
        .output();
    let _ = std::fs::remove_dir_all(maps::BPF_PIN_PATH);
    debug!("Cleaned up TC from {}", interface);
}

/// Generate a pseudo-random SYN cookie secret using kernel entropy.
fn generate_cookie_secret() -> u32 {
    let mut buf = [0u8; 4];
    if let Ok(f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let mut f = f;
        let _ = f.read_exact(&mut buf);
    }
    if buf == [0, 0, 0, 0] {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u32;
        now ^ 0xDEADBEEF
    } else {
        u32::from_ne_bytes(buf)
    }
}
