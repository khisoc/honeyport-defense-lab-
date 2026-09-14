#!/usr/bin/env python3
"""
Smart honeypot with automated response — auto-blocks an attacker's IP via
iptables once they've connected too many times.

RECONSTRUCTED for the GitHub write-up of this lab. No source for this file
was visible in the lab document, only its behavior in the terminal:

    [+] Smart honeypot listening on port 9999
    [+] Auto-blocking IPs after 3 attempts

and its log output in logs/smart_honeypot.sample.log. This reproduces that
behavior; swap in your real smart_honeypot.py from the lab VM if you still
have it. The iptables block requires root (`sudo ./smart_honeypot.py`).
"""
import socket
import threading
import logging
import subprocess
from collections import defaultdict

PORT = 9999
BLOCK_AFTER_ATTEMPTS = 3

logging.basicConfig(
    filename="smart_honeypot.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

attempts = defaultdict(int)
blocked_ips = set()
lock = threading.Lock()


def block_ip(ip):
    if ip in blocked_ips:
        return
    blocked_ips.add(ip)
    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
        )
        logging.critical(f"BLOCKED: {ip} auto-blocked after {BLOCK_AFTER_ATTEMPTS} attempts")
    except Exception as e:
        logging.error(f"Failed to block {ip}: {e}")


def handle_connection(conn, addr):
    ip = addr[0]
    with lock:
        attempts[ip] += 1
        count = attempts[ip]

    logging.warning(f"SMART ALERT: {ip} connection attempt #{count} on port {PORT}")

    if count >= BLOCK_AFTER_ATTEMPTS:
        block_ip(ip)

    conn.close()


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", PORT))
    sock.listen(5)

    logging.info(f"Smart honeypot started on port {PORT}")
    print(f"[+] Smart honeypot listening on port {PORT}")
    print(f"[+] Auto-blocking IPs after {BLOCK_AFTER_ATTEMPTS} attempts")

    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
