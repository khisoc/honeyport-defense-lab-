#!/usr/bin/env python3
"""
Advanced multi-port honeypot ("honeyport") system.

RECONSTRUCTED for the GitHub write-up of this lab. The lab document's
screenshots only show this file up to the start of `port_config` (see
assets/08-honeyport-source-excerpt.jpg) — everything below that point
(the per-port handlers, offender tracking, and alert escalation logic)
is written from scratch to reproduce the exact log lines, JSON alert
shape, and port behavior documented in logs/honeypot_activity.sample.log
and the README. Swap in your real honeyport.py from the lab VM if you
still have it.

Ports 23, 8080, 8443, 9000, 9090 and 9999 must all be free, and port 23
needs root privileges to bind (`sudo python3 honeyport.py`).
"""
import socket
import threading
import datetime
import logging
import json
import time
from collections import defaultdict

logging.basicConfig(
    filename='honeyport_activity.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# An IP is escalated to a CRITICAL "repeated_offender" alert once it has
# touched the honeyports this many times, and on every attempt after that.
ESCALATION_THRESHOLD = 3
# Window used to count "recent_attacks" separately from lifetime total_attempts.
RECENT_WINDOW_SECONDS = 300


class AdvancedHoneyport:
    def __init__(self):
        # Track offenders and their attack patterns
        self.offenders = defaultdict(int)
        self.attack_patterns = defaultdict(list)  # ip -> [(timestamp, port), ...]
        self.active_ports = {}
        self.lock = threading.Lock()

        # Define our honeyports and what they pretend to be
        self.port_config = {
            23: {
                "name": "Telnet",
                "behavior": "close",
            },
            8080: {
                "name": "HTTP Admin",
                "behavior": "http_401",
            },
            8443: {
                "name": "HTTPS Service",
                "behavior": "generic",
            },
            9000: {
                "name": "SSH Service",
                "behavior": "ssh_banner",
                "banner": b"SSH-2.0-OpenSSH_7.9\r\n",
            },
            9090: {
                "name": "Web Admin",
                "behavior": "generic",
            },
            9999: {
                "name": "Mystery Port",
                "behavior": "generic",
            },
        }

    def start(self):
        for port, config in self.port_config.items():
            t = threading.Thread(target=self._listen, args=(port, config), daemon=True)
            t.start()
            self.active_ports[port] = t

        # Keep the main thread alive while the listener threads run
        while True:
            time.sleep(1)

    def _listen(self, port, config):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
            logging.info(f"Honeyport '{config['name']}' started on port {port}")
        except PermissionError:
            logging.error(f"Permission denied binding port {port} (try running with sudo)")
            return
        except OSError as e:
            logging.error(f"Could not bind port {port}: {e}")
            return

        while True:
            try:
                conn, addr = sock.accept()
            except OSError:
                break
            threading.Thread(
                target=self._handle_connection,
                args=(conn, addr, port, config),
                daemon=True,
            ).start()

    def _handle_connection(self, conn, addr, port, config):
        ip, src_port = addr[0], addr[1]
        name = config["name"]

        logging.warning(
            f"INTRUSION DETECTED: {ip}:{src_port} probed {name} service on port {port}"
        )
        self._check_escalation(ip, port)

        try:
            behavior = config["behavior"]
            if behavior == "close":
                # Telnet: accept then hang up immediately, like a filtered/closed service
                pass

            elif behavior == "ssh_banner":
                conn.sendall(config["banner"])

            elif behavior == "http_401":
                conn.settimeout(1)
                try:
                    request = conn.recv(4096).decode(errors="replace")
                except socket.timeout:
                    request = ""
                if request:
                    logging.info(f"Data from {ip} on port {port}: {request.strip()}")
                response = (
                    "HTTP/1.1 401 Unauthorized\r\n"
                    'WWW-Authenticate: Basic realm="Restricted Area"\r\n'
                    "Content-Length: 0\r\n\r\n"
                )
                conn.sendall(response.encode())

            else:  # generic: just log and hold the connection briefly
                conn.settimeout(1)
                try:
                    conn.recv(4096)
                except socket.timeout:
                    pass
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            conn.close()

    def _check_escalation(self, ip, port):
        now = datetime.datetime.now()
        with self.lock:
            self.offenders[ip] += 1
            self.attack_patterns[ip].append((now, port))

            attempts = self.attack_patterns[ip]
            total_attempts = len(attempts)
            recent_attacks = sum(
                1 for ts, _ in attempts
                if (now - ts).total_seconds() <= RECENT_WINDOW_SECONDS
            )
            ports_targeted = list({p for _, p in attempts})
            first_seen = attempts[0][0]

            if total_attempts >= ESCALATION_THRESHOLD:
                alert = {
                    "alert_type": "repeated_offender",
                    "source_ip": ip,
                    "total_attempts": total_attempts,
                    "recent_attacks": recent_attacks,
                    "ports_targeted": ports_targeted,
                    "first_seen": first_seen.isoformat(),
                    "last_seen": now.isoformat(),
                }
                logging.critical(f"SECURITY ALERT: {json.dumps(alert)}")


if __name__ == "__main__":
    honeyport = AdvancedHoneyport()
    honeyport.start()
