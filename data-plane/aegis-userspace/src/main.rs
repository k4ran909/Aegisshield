//! AegisShield userspace loader.
//!
//! Loads eBPF bytecode, attaches it to the NIC via XDP, and manages shared BPF maps.

mod config;
mod maps;

use anyhow::{Context, Result};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use clap::Parser;
use log::{debug, info, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// CLI arguments for the XDP loader.
#[derive(Parser)]
#[command(
    name = "aegis-loader",
    about = "AegisShield XDP data plane loader",
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
    #[arg(long)]
    skb_mode: bool,

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
/_/   \_\___|\__, |_|_|___/____/|_| |_|_|\___|_|\__,_|
             |___/

  eBPF/XDP packet filtering at wire speed
"#
    );

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

    let program: &mut Xdp = bpf.program_mut("aegis_xdp").unwrap().try_into()?;
    program.load()?;

    let flags = if cli.skb_mode {
        info!("Attaching XDP in SKB mode on {}", cli.interface);
        XdpFlags::SKB_MODE
    } else {
        info!("Attaching XDP in DRV mode on {}", cli.interface);
        XdpFlags::DRV_MODE
    };

    program.attach(&cli.interface, flags).context(format!(
        "Failed to attach XDP to {}. Try --skb-mode for compatibility.",
        cli.interface
    ))?;
    info!("XDP program attached to {} successfully", cli.interface);

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
        "XDP thresholds active: UDP={} SYN={} ICMP={} DNS_MAX={}",
        cfg.thresholds.udp_pps,
        cfg.thresholds.syn_flood,
        cfg.thresholds.icmp_pps,
        cfg.thresholds.dns_response_size
    );

    maps::load_blocklist(&mut bpf, &cfg.blocklist)?;
    maps::load_acl_rules(&mut bpf, &cfg.acl_rules)?;

    if cli.pin_maps {
        info!("Pinning BPF maps to {}", maps::BPF_PIN_PATH);
        maps::pin_maps(&mut bpf, maps::BPF_PIN_PATH)?;
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl-C handler")?;

    info!(
        "AegisShield is ACTIVE on {} (Ctrl-C to stop)",
        cli.interface
    );

    let stats_interval = Duration::from_secs(cli.stats_interval.max(1));
    let mut dashboard = maps::Dashboard::new(cli.interface.clone(), stats_interval);
    dashboard.set_event("XDP attached and map sync complete");

    let mut last_cookie_rotation = Instant::now();
    let cookie_rotation_interval = Duration::from_secs(300);

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(stats_interval);

        match maps::read_stats(&bpf) {
            Ok(stats) => dashboard.render(&stats),
            Err(err) => {
                dashboard.set_event(format!("stats read failed: {}", err));
                warn!("Failed to read stats: {}", err);
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
                warn!("Failed to rotate SYN cookie secret: {}", err);
            } else {
                dashboard.set_event("SYN cookie secret rotated");
                debug!("SYN cookie secret rotated");
            }
            last_cookie_rotation = Instant::now();
        }
    }

    dashboard.shutdown();
    info!("Detaching XDP program from {}", cli.interface);
    info!("AegisShield stopped");
    Ok(())
}

/// Generate a pseudo-random SYN cookie secret.
fn generate_cookie_secret() -> u32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u32;
    now ^ 0xDEADBEEF
}
