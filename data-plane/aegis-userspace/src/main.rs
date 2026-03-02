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
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// CLI arguments for the XDP loader.
#[derive(Parser)]
#[command(
    name = "aegis-loader",
    about = "AegisShield XDP data plane loader",
    version = "0.2.0"
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

    /// Force detach any existing XDP program before attaching.
    #[arg(long, default_value = "true")]
    force_attach: bool,
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

  eBPF/XDP packet filtering at wire speed  [v0.2.0]
"#
    );

    // ── Force detach any stale XDP program ─────────────────────────────
    if cli.force_attach {
        force_detach_xdp(&cli.interface);
    }

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

    // Retry attach up to 3 times with force detach between attempts
    let mut attached = false;
    for attempt in 1..=3 {
        match program.attach(&cli.interface, flags) {
            Ok(_) => {
                attached = true;
                break;
            }
            Err(e) => {
                warn!(
                    "Attach attempt {}/3 failed: {}. Force-detaching and retrying...",
                    attempt, e
                );
                force_detach_xdp(&cli.interface);
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }

    if !attached {
        anyhow::bail!(
            "Failed to attach XDP to {} after 3 attempts. Try rebooting or run: sudo ip link set dev {} xdp off",
            cli.interface,
            cli.interface
        );
    }

    info!("✓ XDP program attached to {} successfully!", cli.interface);

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
        "XDP thresholds: UDP={}/s SYN={}/s ICMP={}/s DNS_MAX={}B",
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
        // Clean detach on Ctrl-C
        eprintln!(
            "\n[!] Shutting down — detaching XDP from {}...",
            iface_for_handler
        );
        let _ = Command::new("ip")
            .args(["link", "set", "dev", &iface_for_handler, "xdp", "off"])
            .output();
        let _ = Command::new("ip")
            .args([
                "link",
                "set",
                "dev",
                &iface_for_handler,
                "xdpgeneric",
                "off",
            ])
            .output();
        r.store(false, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl-C handler")?;

    info!(
        "AegisShield is ACTIVE — protecting interface {} (Ctrl-C to stop)",
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
    info!("Detaching XDP program from {}", cli.interface);
    force_detach_xdp(&cli.interface);
    let _ = std::fs::remove_dir_all(maps::BPF_PIN_PATH);
    info!("AegisShield stopped cleanly");
    Ok(())
}

/// Force-detach any existing XDP program from the given interface.
fn force_detach_xdp(interface: &str) {
    for mode in &["xdp", "xdpgeneric", "xdpdrv", "xdpoffload"] {
        let _ = Command::new("ip")
            .args(["link", "set", "dev", interface, mode, "off"])
            .output();
    }
    // Also clean stale pinned maps
    let _ = std::fs::remove_dir_all(maps::BPF_PIN_PATH);
    debug!("Force-detached XDP from {}", interface);
}

/// Generate a pseudo-random SYN cookie secret using kernel entropy.
fn generate_cookie_secret() -> u32 {
    let mut buf = [0u8; 4];
    if std::fs::read("/dev/urandom")
        .ok()
        .and_then(|_| None::<Vec<u8>>)
        .is_none()
    {
        // Read 4 bytes from /dev/urandom for real randomness
        if let Ok(f) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            let mut f = f;
            let _ = f.read_exact(&mut buf);
        }
    }
    if buf == [0, 0, 0, 0] {
        // Fallback: time-based
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u32;
        now ^ 0xDEADBEEF
    } else {
        u32::from_ne_bytes(buf)
    }
}
