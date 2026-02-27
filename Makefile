# ═══════════════════════════════════════════════════════════════════
# AegisShield — Unified Build System
# ═══════════════════════════════════════════════════════════════════
#
# Usage:
#   make build          — Build everything
#   make build-xdp      — Build XDP data plane (Rust eBPF)
#   make build-control   — Build Go control plane
#   make test           — Run all tests
#   make bench          — Run benchmarks
#   make install        — Install to /usr/local/bin
#   make clean          — Clean all build artifacts
#   make dev-setup      — Set up development environment

SHELL := /bin/bash
.PHONY: all build build-xdp build-userspace build-control test bench install clean dev-setup lint

# ─── Variables ────────────────────────────────────────────────────
RUST_TARGET_BPF := bpfel-unknown-none
RUST_FLAGS_BPF := -C debuginfo=2 -C link-arg=--btf
GO_MODULE := github.com/aegisshield/aegisshield
INSTALL_DIR := /usr/local/bin

# ─── Default Target ──────────────────────────────────────────────
all: build

# ─── Build Everything ─────────────────────────────────────────────
build: build-xdp build-userspace build-control
	@echo ""
	@echo "═══════════════════════════════════════════════"
	@echo "  AegisShield build complete!"
	@echo "═══════════════════════════════════════════════"

# ─── Build XDP eBPF Program (Rust → BPF Bytecode) ────────────────
build-xdp:
	@echo "🔧 Building XDP eBPF data plane..."
	cd data-plane && \
		cargo +nightly build \
			-p aegis-ebpf \
			-Z build-std=core \
			--target $(RUST_TARGET_BPF) \
			--release
	@echo "✓ XDP eBPF program compiled"

# ─── Build Userspace Loader (Rust) ────────────────────────────────
build-userspace: build-xdp
	@echo "🔧 Building userspace loader..."
	cd data-plane && cargo build -p aegis-userspace --release
	@echo "✓ Userspace loader compiled"

# ─── Build Go Control Plane ──────────────────────────────────────
build-control:
	@echo "🔧 Building Go control plane..."
	cd control-plane && go build -o ../bin/aegisd ./cmd/aegisd/
	cd control-plane && go build -o ../bin/aegis ./cmd/aegis/
	@echo "✓ Control plane binaries compiled"

# ─── Run All Tests ────────────────────────────────────────────────
test: test-rust test-go
	@echo "✓ All tests passed"

test-rust:
	@echo "🧪 Running Rust tests..."
	cd data-plane && cargo test -p aegis-common
	cd data-plane && cargo test -p aegis-userspace

test-go:
	@echo "🧪 Running Go tests..."
	cd control-plane && go test ./... -v

# ─── Benchmarks ──────────────────────────────────────────────────
bench:
	@echo "📊 Running benchmarks..."
	cd control-plane && go test -bench=. ./...

# ─── Linting ─────────────────────────────────────────────────────
lint: lint-rust lint-go

lint-rust:
	@echo "🔍 Linting Rust..."
	cd data-plane && cargo clippy -p aegis-common -p aegis-userspace -- -D warnings

lint-go:
	@echo "🔍 Linting Go..."
	cd control-plane && golangci-lint run ./...

# ─── Install ─────────────────────────────────────────────────────
install: build
	@echo "📦 Installing AegisShield..."
	sudo cp bin/aegisd $(INSTALL_DIR)/aegisd
	sudo cp bin/aegis $(INSTALL_DIR)/aegis
	sudo cp data-plane/target/release/aegis-loader $(INSTALL_DIR)/aegis-loader
	sudo mkdir -p /etc/aegisshield
	sudo cp configs/aegis.yaml /etc/aegisshield/aegis.yaml
	sudo cp deploy/systemd/aegisd.service /etc/systemd/system/
	sudo cp deploy/systemd/aegis-xdp.service /etc/systemd/system/
	sudo systemctl daemon-reload
	@echo "✓ Installed! Run: sudo systemctl start aegis-xdp aegisd"

# ─── Development Environment Setup ──────────────────────────────
dev-setup:
	@echo "🛠  Setting up AegisShield development environment..."
	@echo ""
	@echo "1. Installing Rust nightly + eBPF target..."
	rustup install nightly
	rustup component add rust-src --toolchain nightly
	cargo install bpf-linker
	@echo ""
	@echo "2. Installing Go tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo ""
	@echo "3. Installing system dependencies..."
	sudo apt-get update
	sudo apt-get install -y clang llvm libelf-dev linux-headers-$$(uname -r) haproxy
	@echo ""
	@echo "✓ Development environment ready!"

# ─── Clean ───────────────────────────────────────────────────────
clean:
	@echo "🧹 Cleaning build artifacts..."
	cd data-plane && cargo clean
	rm -rf bin/
	cd control-plane && go clean
	@echo "✓ Clean"
