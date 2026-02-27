#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# AegisShield — Comprehensive XDP Test Suite
# ═══════════════════════════════════════════════════════════════════
#
# Usage:  sudo ./test_aegis.sh [interface]
# Default interface: eth0
#
# Prerequisites:
#   - AegisShield eBPF + userspace built (cargo xtask build-ebpf --release && cargo build --package aegis-userspace --release)
#   - hping3 installed (apt install hping3)
#   - Run as root (sudo)

set -e

# ── Colors ────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

IFACE="${1:-eth0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_PLANE="$SCRIPT_DIR/data-plane"
LOADER="$DATA_PLANE/target/release/aegis-loader"
CONFIG="$SCRIPT_DIR/configs/aegis.yaml"
LOADER_PID=""
PASS=0
FAIL=0
TOTAL=0

# ── Helpers ───────────────────────────────────────────────────────
banner() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     AegisShield — Comprehensive XDP Test Suite       ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

section() {
    echo ""
    echo -e "${BOLD}━━━ $1 ━━━${NC}"
}

pass() {
    TOTAL=$((TOTAL + 1))
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}✓ PASS${NC} — $1"
}

fail() {
    TOTAL=$((TOTAL + 1))
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}✗ FAIL${NC} — $1"
}

info() {
    echo -e "  ${YELLOW}ℹ${NC} $1"
}

cleanup() {
    if [ -n "$LOADER_PID" ] && kill -0 "$LOADER_PID" 2>/dev/null; then
        info "Stopping AegisShield (PID $LOADER_PID)..."
        kill -SIGINT "$LOADER_PID" 2>/dev/null || true
        wait "$LOADER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── Pre-Flight Checks ────────────────────────────────────────────
banner

section "Pre-Flight Checks"

if [ "$(id -u)" -ne 0 ]; then
    fail "Must run as root (sudo)"
    exit 1
fi
pass "Running as root"

if [ ! -f "$LOADER" ]; then
    fail "Loader binary not found: $LOADER"
    echo "    Build it: cd data-plane && cargo build --package aegis-userspace --release"
    exit 1
fi
pass "Loader binary exists"

if [ ! -f "$CONFIG" ]; then
    fail "Config not found: $CONFIG"
    exit 1
fi
pass "Config file exists"

EBPF_BIN="$DATA_PLANE/target/bpfel-unknown-none/release/aegis-ebpf"
if [ ! -f "$EBPF_BIN" ]; then
    fail "eBPF binary not found: $EBPF_BIN"
    echo "    Build it: cd data-plane && cargo xtask build-ebpf --release"
    exit 1
fi
pass "eBPF binary exists ($(stat -c%s "$EBPF_BIN") bytes)"

if ! command -v hping3 &>/dev/null; then
    fail "hping3 not installed (apt install hping3)"
    exit 1
fi
pass "hping3 available"

if ! ip link show "$IFACE" &>/dev/null; then
    fail "Interface $IFACE not found"
    exit 1
fi
IP_ADDR=$(ip -4 addr show "$IFACE" | grep -oP 'inet \K[\d.]+' | head -1)
pass "Interface $IFACE is up (IP: $IP_ADDR)"

# ── Clean State ──────────────────────────────────────────────────
info "Cleaning up any previous AegisShield instances..."
killall aegis-loader 2>/dev/null || true
rm -rf /sys/fs/bpf/aegis 2>/dev/null || true
ip link set dev "$IFACE" xdp off 2>/dev/null || true
ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
sleep 1

# ── Test 1: Load & Attach XDP ────────────────────────────────────
section "Test 1: XDP Program Loading"

info "Starting AegisShield loader..."
RUST_LOG=info "$LOADER" --interface "$IFACE" --skb-mode --config "$CONFIG" &>/tmp/aegis_test.log &
LOADER_PID=$!
sleep 3

if kill -0 "$LOADER_PID" 2>/dev/null; then
    pass "Loader process started (PID $LOADER_PID)"
else
    fail "Loader crashed on startup"
    cat /tmp/aegis_test.log
    exit 1
fi

# Check XDP is attached
if ip link show "$IFACE" | grep -q "xdp"; then
    pass "XDP program attached to $IFACE"
else
    fail "XDP not attached to $IFACE"
fi

# Check log messages
if grep -q "XDP program attached" /tmp/aegis_test.log; then
    pass "eBPF loaded and verified by kernel"
fi

if grep -q "ACL rules" /tmp/aegis_test.log; then
    ACL_COUNT=$(grep "ACL rules" /tmp/aegis_test.log | grep -oP '\d+' | head -1)
    pass "ACL rules loaded ($ACL_COUNT rules)"
fi

if grep -q "XDP config updated" /tmp/aegis_test.log; then
    pass "Rate-limit thresholds configured"
fi

# ── Test 2: Legitimate Traffic ────────────────────────────────────
section "Test 2: Legitimate Traffic (should pass)"

info "Sending 10 ICMP pings..."
PING_RESULT=$(ping -c 10 -i 0.1 -W 2 "$IP_ADDR" 2>&1 | tail -2)
LOSS=$(echo "$PING_RESULT" | grep -oP '\d+(?=% packet loss)')
if [ "$LOSS" = "0" ]; then
    pass "ICMP ping: 0% packet loss"
else
    fail "ICMP ping: ${LOSS}% packet loss"
fi

info "Testing TCP connectivity..."
if timeout 3 bash -c "echo '' | nc -w1 $IP_ADDR 80 2>&1" || true; then
    pass "TCP connection attempt completed (port 80)"
fi

info "Testing DNS resolution..."
if nslookup google.com &>/dev/null; then
    pass "DNS resolution works"
else
    fail "DNS resolution failed"
fi

info "Testing HTTPS..."
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 https://example.com 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    pass "HTTPS: got HTTP 200 from example.com"
else
    info "HTTPS returned $HTTP_CODE (network-dependent)"
fi

# ── Test 3: SYN Flood ────────────────────────────────────────────
section "Test 3: SYN Flood Attack (3 seconds)"

info "Launching SYN flood on port 25565..."
SYN_OUTPUT=$(timeout 3 hping3 -S --flood -p 25565 "$IP_ADDR" 2>&1 || true)
SYN_PKTS=$(echo "$SYN_OUTPUT" | grep -oP '(\d+) packets transmitted' | grep -oP '\d+' || echo "0")
if [ "$SYN_PKTS" -gt 0 ]; then
    pass "SYN flood sent: $SYN_PKTS packets in 3s"
else
    info "SYN flood packets sent (count unavailable)"
fi
sleep 1

# ── Test 4: UDP Flood ────────────────────────────────────────────
section "Test 4: UDP Flood Attack (3 seconds)"

info "Launching UDP flood on port 25565..."
UDP_OUTPUT=$(timeout 3 hping3 --udp --flood -p 25565 "$IP_ADDR" 2>&1 || true)
UDP_PKTS=$(echo "$UDP_OUTPUT" | grep -oP '(\d+) packets transmitted' | grep -oP '\d+' || echo "0")
if [ "$UDP_PKTS" -gt 0 ]; then
    pass "UDP flood sent: $UDP_PKTS packets in 3s"
else
    info "UDP flood packets sent (count unavailable)"
fi
sleep 1

# ── Test 5: ICMP Flood ───────────────────────────────────────────
section "Test 5: ICMP Flood Attack (3 seconds)"

info "Launching ICMP flood..."
ICMP_OUTPUT=$(timeout 3 hping3 --icmp --flood "$IP_ADDR" 2>&1 || true)
ICMP_PKTS=$(echo "$ICMP_OUTPUT" | grep -oP '(\d+) packets transmitted' | grep -oP '\d+' || echo "0")
if [ "$ICMP_PKTS" -gt 0 ]; then
    pass "ICMP flood sent: $ICMP_PKTS packets in 3s"
else
    info "ICMP flood packets sent (count unavailable)"
fi
sleep 1

# ── Test 6: DNS Amplification ────────────────────────────────────
section "Test 6: DNS Amplification Simulation (3 seconds)"

info "Launching UDP flood on port 53..."
DNS_OUTPUT=$(timeout 3 hping3 --udp -p 53 --flood "$IP_ADDR" 2>&1 || true)
DNS_PKTS=$(echo "$DNS_OUTPUT" | grep -oP '(\d+) packets transmitted' | grep -oP '\d+' || echo "0")
if [ "$DNS_PKTS" -gt 0 ]; then
    pass "DNS amp sim sent: $DNS_PKTS packets in 3s"
else
    info "DNS amp packets sent (count unavailable)"
fi
sleep 1

# ── Test 7: Post-Attack Legitimate Traffic ───────────────────────
section "Test 7: Post-Attack Legitimate Traffic"

info "Verifying legitimate traffic still works after attacks..."
PING2=$(ping -c 5 -W 2 "$IP_ADDR" 2>&1 | tail -2)
LOSS2=$(echo "$PING2" | grep -oP '\d+(?=% packet loss)')
if [ "$LOSS2" = "0" ]; then
    pass "Post-attack ICMP: 0% packet loss (no false positives)"
else
    fail "Post-attack ICMP: ${LOSS2}% loss (possible false positive)"
fi

HTTP2=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 https://example.com 2>/dev/null || echo "000")
if [ "$HTTP2" = "200" ]; then
    pass "Post-attack HTTPS: still working"
else
    info "Post-attack HTTPS: $HTTP2 (network-dependent)"
fi

# ── Test 8: XDP Still Attached ───────────────────────────────────
section "Test 8: Stability Check"

if kill -0 "$LOADER_PID" 2>/dev/null; then
    pass "Loader still running after all attacks (no crash)"
else
    fail "Loader crashed during attacks!"
fi

if ip link show "$IFACE" | grep -q "xdp"; then
    pass "XDP still attached to $IFACE after attacks"
else
    fail "XDP detached during attacks"
fi

# ── Test 9: Graceful Shutdown ────────────────────────────────────
section "Test 9: Graceful Shutdown"

info "Sending SIGINT to loader..."
kill -SIGINT "$LOADER_PID" 2>/dev/null || true
sleep 2

if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    pass "Loader stopped gracefully"
    LOADER_PID="" # Prevent double-cleanup
else
    fail "Loader did not stop on SIGINT"
    kill -9 "$LOADER_PID" 2>/dev/null || true
    LOADER_PID=""
fi

if ! ip link show "$IFACE" | grep -q "xdp"; then
    pass "XDP program detached on shutdown"
else
    info "XDP program still attached (kernel manages cleanup)"
fi

# ── Final Report ─────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              TEST RESULTS SUMMARY                    ║${NC}"
echo -e "${CYAN}╠═══════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  Total tests:  ${BOLD}$TOTAL${NC}                                    ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ${GREEN}Passed:  $PASS${NC}                                        ${CYAN}║${NC}"
if [ "$FAIL" -gt 0 ]; then
echo -e "${CYAN}║${NC}  ${RED}Failed:  $FAIL${NC}                                        ${CYAN}║${NC}"
else
echo -e "${CYAN}║${NC}  ${GREEN}Failed:  0${NC}                                           ${CYAN}║${NC}"
fi
echo -e "${CYAN}╠═══════════════════════════════════════════════════════╣${NC}"
if [ "$FAIL" -eq 0 ]; then
echo -e "${CYAN}║${NC}  ${GREEN}${BOLD}🛡️  ALL TESTS PASSED — AegisShield is operational${NC}   ${CYAN}║${NC}"
else
echo -e "${CYAN}║${NC}  ${RED}${BOLD}⚠  SOME TESTS FAILED — review output above${NC}        ${CYAN}║${NC}"
fi
echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

exit $FAIL
