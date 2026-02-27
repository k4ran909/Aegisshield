#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# AegisShield — Quick Install Script
# One-liner: curl -sSf https://install.aegisshield.dev | bash
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════╗"
echo "║         AegisShield Quick Installer           ║"
echo "║     Enterprise DDoS Protection for Linux      ║"
echo "╚═══════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Check Prerequisites ──────────────────────────────────────────
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
        exit 1
    fi
}

check_os() {
    if [ ! -f /etc/os-release ]; then
        echo -e "${RED}Error: Unsupported operating system${NC}"
        exit 1
    fi
    . /etc/os-release
    echo -e "${GREEN}✓ Detected OS: ${NAME} ${VERSION}${NC}"
}

check_kernel() {
    KERNEL_VER=$(uname -r | cut -d. -f1-2)
    MAJOR=$(echo $KERNEL_VER | cut -d. -f1)
    MINOR=$(echo $KERNEL_VER | cut -d. -f2)

    if [ "$MAJOR" -lt 5 ] || ([ "$MAJOR" -eq 5 ] && [ "$MINOR" -lt 15 ]); then
        echo -e "${RED}Error: Kernel >= 5.15 required for full eBPF/XDP support${NC}"
        echo -e "${RED}Current kernel: $(uname -r)${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Kernel version: $(uname -r)${NC}"
}

# ── Install Dependencies ─────────────────────────────────────────
install_deps() {
    echo -e "${YELLOW}Installing system dependencies...${NC}"
    apt-get update -qq
    apt-get install -y -qq \
        clang llvm libelf-dev \
        linux-headers-$(uname -r) \
        haproxy \
        curl wget git \
        build-essential \
        pkg-config \
        > /dev/null 2>&1
    echo -e "${GREEN}✓ System dependencies installed${NC}"
}

# ── Install Rust ─────────────────────────────────────────────────
install_rust() {
    if command -v rustup &> /dev/null; then
        echo -e "${GREEN}✓ Rust already installed${NC}"
    else
        echo -e "${YELLOW}Installing Rust toolchain...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
        source "$HOME/.cargo/env"
    fi
    rustup install nightly > /dev/null 2>&1
    rustup component add rust-src --toolchain nightly > /dev/null 2>&1
    cargo install bpf-linker > /dev/null 2>&1 || true
    echo -e "${GREEN}✓ Rust nightly + bpf-linker ready${NC}"
}

# ── Install Go ───────────────────────────────────────────────────
install_go() {
    if command -v go &> /dev/null; then
        echo -e "${GREEN}✓ Go already installed: $(go version)${NC}"
    else
        echo -e "${YELLOW}Installing Go 1.22...${NC}"
        wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
        tar -C /usr/local -xzf /tmp/go.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
        export PATH=$PATH:/usr/local/go/bin
        echo -e "${GREEN}✓ Go installed${NC}"
    fi
}

# ── Create Directory Structure ────────────────────────────────────
setup_dirs() {
    mkdir -p /etc/aegisshield
    mkdir -p /var/log/aegisshield
    mkdir -p /sys/fs/bpf/aegis
    echo -e "${GREEN}✓ Directories created${NC}"
}

# ── Main ──────────────────────────────────────────────────────────
main() {
    check_root
    check_os
    check_kernel
    echo ""
    install_deps
    install_rust
    install_go
    setup_dirs

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  AegisShield environment is ready!${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
    echo ""
    echo "  Next steps:"
    echo "    1. cd aegisshield"
    echo "    2. make build"
    echo "    3. sudo make install"
    echo "    4. Edit /etc/aegisshield/aegis.yaml"
    echo "    5. sudo systemctl start aegis-xdp aegisd"
    echo ""
}

main "$@"
