# 🛡️ AegisShield — XDP-Powered DDoS Protection

> **Line-rate DDoS mitigation from L3 to L7**, built with Rust eBPF/XDP and Go.
> Designed for Minecraft servers, VPS instances, and bare-metal infrastructure.

---

## ⚡ Architecture

```
Internet Traffic
       │
       ▼
┌──────────────────┐
│  NIC (10/40 GbE) │
└──────┬───────────┘
       │
       ▼
┌──────────────────────────────────────────┐
│         XDP Data Plane (Rust/eBPF)       │
│                                          │
│  ┌──────────┐  ┌──────────┐  ┌───────`─┐ │
│  │ Blocklist│→ │ Fragment │→ │Conntrack│ │
│  │  Filter  │  │  Filter  │  │ Lookup  │ │
│  └──────────┘  └──────────┘  └──────-──┘ │
│       │              │            │      │
│       ▼              ▼            ▼      │
│  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │   ACL    │→ │Protocol  │→ │  Stats │  │
│  │  Engine  │  │Filters   │  │Counter │  │
│  └──────────┘  │SYN/UDP/  │  └────────┘  │
│                │DNS/ICMP/ │              │
│                │GRE       │              │
│                └──────────┘              │
│        ↓ PASS        ↓ DROP              │
└────────┬─────────────┬─────────────────-─┘
         │             │
         ▼             ✗ (wire speed)
┌──────────────────┐
│   HAProxy L7     │
│ TLS + JA4+ +     │
│ HTTP/2 Shield    │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│   Origin Server  │
│  (Minecraft/Web) │
└──────────────────┘
```

## 🚀 Features

### L3/L4 — XDP Data Plane (Wire Speed)
- **IP Blocklist** — Instant DROP for known-bad IPs (65K entries)
- **SYN Proxy** — Stateless SYN cookie validation against SYN floods
- **UDP Rate Limiter** — Per-IP with amplification-port-specific thresholds
- **DNS Amplification Filter** — Deep payload inspection + TxID tracking
- **ICMP Flood Filter** — Blocks redirects, rate-limits echo requests
- **GRE Flood Filter** — Header validation + tunnel endpoint whitelisting
- **Fragment Attack Filter** — Teardrop, tiny fragment, and bypass detection
- **Connection Tracking** — LRU 5-tuple tracking, bypasses filters for known flows
- **ACL Firewall** — Priority-ordered rules with protocol/port matching

### L7 — HAProxy Reverse Proxy
- **TLS 1.3 Termination** with modern cipher suites
- **JA4+ Fingerprinting** — Bot detection via TLS Client Hello analysis
- **HTTP/2 Rapid Reset Shield** — Stream creation/cancellation ratio tracking
- **Per-IP Rate Limiting** — Stick-table + Lua-based path rate limiting

### Control Plane (Go)
- **EWMA Anomaly Detector** — Learns baseline traffic, alerts at 3σ deviation
- **Graduated Auto-Responder** — LOW→notify, MEDIUM→tighten, HIGH→emergency
- **REST API** � status + management endpoints with optional Bearer auth
- **Prometheus Metrics** � local-by-default metrics endpoint
- **Alert Notifications** — Discord webhook + Telegram Bot API
- **BGP Manager (Experimental)** � scaffolding for Anycast/Flowspec/RTBH
- **Tunnel Manager (Experimental)** � scaffolding for GRE/IPIP/WireGuard delivery
- **Minecraft Bot Detector** — 5-factor behavioral scoring engine

### 🎮 Minecraft-Specific
- Protocol-aware handshake validation
- Per-IP connection + ping rate limiting
- Bot detection: name rotation, timing analysis, protocol version clustering
- Separate protection profile with tuned thresholds

## 📁 Project Structure

```
aegisshield/
├── data-plane/                    # Rust eBPF/XDP
│   ├── aegis-ebpf/src/           # Kernel-space XDP programs
│   │   ├── main.rs               # XDP entry point (6-stage pipeline)
│   │   ├── acl.rs                # ACL firewall engine
│   │   ├── syn_proxy.rs          # SYN cookie SYNPROXY
│   │   ├── udp_filter.rs         # UDP rate limiter
│   │   ├── dns_filter.rs         # DNS amplification filter
│   │   ├── icmp_filter.rs        # ICMP flood filter
│   │   ├── gre_filter.rs         # GRE flood filter
│   │   ├── fragment_filter.rs    # IP fragment attack filter
│   │   └── conntrack.rs          # Connection tracking
│   ├── aegis-userspace/src/      # Userspace XDP loader
│   └── aegis-common/src/         # Shared types
├── control-plane/                 # Go control plane
│   ├── cmd/aegisd/               # Daemon binary
│   ├── cmd/aegis/                # CLI tool
│   └── internal/
│       ├── api/                  # REST API server
│       ├── alerts/               # Discord/Telegram notifier
│       ├── bgp/                  # BGP session manager
│       ├── bpf/                  # BPF map manager
│       ├── config/               # YAML config parser
│       ├── engine/               # Mitigation engine + detector + responder
│       ├── metrics/              # Prometheus exporter
│       ├── minecraft/            # Protocol parser + bot detector
│       └── tunnel/               # GRE/IPIP/WG tunnel manager
├── l7-proxy/                      # HAProxy L7 protection
│   ├── haproxy.cfg
│   └── lua/                      # JA4+, HTTP/2 shield, rate limiter
├── configs/                       # Configuration files
│   ├── aegis.yaml                # Master config
│   ├── minecraft.yaml            # Minecraft profile
│   └── grafana-dashboard.json    # Grafana dashboard
├── deploy/                        # Deployment scripts
│   ├── systemd/                  # Service units
│   └── scripts/install.sh
└── Makefile                       # Build system
```

## 🔧 Quick Start

### Prerequisites
- Linux kernel ≥ 5.15 (XDP support)
- Rust nightly + `bpf-linker`
- Go ≥ 1.21
- HAProxy ≥ 3.0 (optional, for L7)

### Build & Install

```bash
# Build everything
make all

# Install (copies binaries + configs + systemd units)
sudo make install

# Or use the install script
sudo bash deploy/scripts/install.sh
```

### Configure

```bash
# Edit the master config
sudo nano /etc/aegis/aegis.yaml

# For Minecraft servers, use the specialized profile:
sudo cp configs/minecraft.yaml /etc/aegis/aegis.yaml
```

### Run

```bash
# Start XDP data plane
sudo systemctl start aegis-xdp

# Start control plane daemon
sudo systemctl start aegisd

# Check status
aegis status

# Block an IP
aegis block 10.0.0.1

# View dashboard
# Import configs/grafana-dashboard.json into Grafana
```

## 📊 Monitoring

| Endpoint | Description |
|----------|-------------|
| `http://localhost:9090/api/v1/status` | Current protection state |
| `http://127.0.0.1:9100/metrics` | Prometheus metrics |
| `http://127.0.0.1:9100/health` | Health check |

Import `configs/grafana-dashboard.json` into Grafana for a full visual dashboard with 12 panels covering packet throughput, per-filter drops, attack history, and Minecraft bot scores.

## ⚙️ Configuration

See [`configs/aegis.yaml`](configs/aegis.yaml) for the full configuration reference with inline comments.

Key sections:
- **thresholds** — Rate limiting PPS thresholds
- **blocklist** — Static IP blocklist
- **acl_rules** — Edge Network Firewall rules
- **minecraft** — Minecraft protocol-aware settings
- **alerts** — Discord/Telegram notification webhooks
- **bgp** — BGP Anycast (optional, for multi-node)
- **tunnel** — Clean traffic delivery (optional)

## 📜 License

MIT License — See [LICENSE](LICENSE) for details.


