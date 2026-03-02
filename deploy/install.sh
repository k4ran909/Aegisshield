#!/bin/bash
# AegisShield Quick Install Script
# Run on a fresh Ubuntu/Debian VPS as root

set -euo pipefail

GREEN='\033[1;32m'
CYAN='\033[1;36m'
RED='\033[1;31m'
RESET='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║     AegisShield Quick Deploy Script              ║"
echo "║     eBPF/XDP DDoS Protection at Wire Speed       ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Check root ──────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] This script must be run as root${RESET}"
    exit 1
fi

INSTALL_DIR="/root/Aegisshield"
REPO="https://github.com/k4ran909/Aegisshield.git"

# ── Install system dependencies ─────────────────────────
echo -e "${GREEN}[1/7] Installing system dependencies...${RESET}"
apt-get update -qq
apt-get install -y -qq build-essential clang llvm libbpf-dev \
    linux-headers-$(uname -r) pkg-config git curl

# ── Install Rust ────────────────────────────────────────
if ! command -v rustup &>/dev/null; then
    echo -e "${GREEN}[2/7] Installing Rust toolchain...${RESET}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo -e "${GREEN}[2/7] Rust already installed${RESET}"
fi
source "$HOME/.cargo/env"

# ── Install nightly + bpf-linker ────────────────────────
echo -e "${GREEN}[3/7] Setting up nightly toolchain...${RESET}"
rustup toolchain install nightly --component rust-src
rustup default nightly

if ! command -v bpf-linker &>/dev/null; then
    echo -e "${GREEN}[4/7] Installing bpf-linker...${RESET}"
    cargo install bpf-linker
else
    echo -e "${GREEN}[4/7] bpf-linker already installed${RESET}"
fi

# ── Clone or update repo ───────────────────────────────
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${GREEN}[5/7] Updating AegisShield...${RESET}"
    cd "$INSTALL_DIR"
    git pull origin main
else
    echo -e "${GREEN}[5/7] Cloning AegisShield...${RESET}"
    git clone "$REPO" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# ── Build ──────────────────────────────────────────────
echo -e "${GREEN}[6/7] Building eBPF + userspace...${RESET}"
cd "$INSTALL_DIR/data-plane"
cargo build --package aegis-ebpf --target bpfel-unknown-none -Z build-std=core --release
cargo build --package aegis-userspace --release

# ── Install systemd service ────────────────────────────
echo -e "${GREEN}[7/7] Installing systemd service...${RESET}"
cp "$INSTALL_DIR/deploy/aegisshield.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable aegisshield

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗"
echo -e "║     ✓ AegisShield installed successfully!        ║"
echo -e "╠══════════════════════════════════════════════════╣"
echo -e "║                                                  ║"
echo -e "║  Start:   systemctl start aegisshield            ║"
echo -e "║  Stop:    systemctl stop aegisshield             ║"
echo -e "║  Status:  systemctl status aegisshield           ║"
echo -e "║  Logs:    journalctl -u aegisshield -f           ║"
echo -e "║                                                  ║"
echo -e "║  Config:  /root/Aegisshield/configs/aegis.yaml   ║"
echo -e "║                                                  ║"
echo -e "║  Or run manually:                                ║"
echo -e "║  cd /root/Aegisshield/data-plane                 ║"
echo -e "║  sudo RUST_LOG=info ./target/release/aegis-loader \\\\║"
echo -e "║    --interface eth0 --skb-mode \\\\                 ║"
echo -e "║    --config ../configs/aegis.yaml                ║"
echo -e "╚══════════════════════════════════════════════════╝${RESET}"
