use std::env;
/// AegisShield xtask — Cross-compile eBPF bytecode.
///
/// Usage:
///   cargo xtask build-ebpf          # Build eBPF in debug mode
///   cargo xtask build-ebpf --release  # Build eBPF in release mode (optimised)
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
enum Cli {
    /// Build the eBPF program (cross-compile to BPF target).
    BuildEbpf {
        /// Build in release mode with optimizations.
        #[clap(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::BuildEbpf { release } => build_ebpf(release),
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    // Find the workspace root (parent of xtask/).
    let workspace_dir = env::current_dir().context("Failed to get current directory")?;

    println!("🔨 Building eBPF program...");
    println!("   Target: bpfel-unknown-none (little-endian BPF)");
    println!("   Package: aegis-ebpf");
    println!("   Profile: {}", if release { "release" } else { "dev" });

    let mut cmd = Command::new("cargo");

    cmd.current_dir(&workspace_dir)
        .env_remove("RUSTUP_TOOLCHAIN") // Use nightly from rust-toolchain.toml
        .args([
            "+nightly",
            "build",
            "--package",
            "aegis-ebpf",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .context("Failed to run cargo build for eBPF target")?;

    if !status.success() {
        bail!("eBPF build failed with exit code: {:?}", status.code());
    }

    let profile = if release { "release" } else { "debug" };
    let output_path = workspace_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("aegis-ebpf");

    println!();
    println!("✅ eBPF program built successfully!");
    println!("   Output: {}", output_path.display());
    println!();
    println!("   Next: Run the userspace loader to attach it:");
    println!("   sudo cargo run --package aegis-userspace --release -- \\");
    println!("       --interface eth0 --config ../../configs/aegis.yaml");

    Ok(())
}
