#!/usr/bin/env python3
"""
Honeyport Dashboard — live attack map, top-attacker table, and 24h timeline.

RECONSTRUCTED for the GitHub write-up of this lab. The lab document's
screenshots show roughly the first half of this file (imports, Flask app
init, and the start of get_logs() — see
assets/09-dashboard-source-excerpt.jpg), cut off partway through. The
get_logs() regex below matches what was visible verbatim; get_coords(),
the /api/data route, and templates/index.html are written from scratch to
reproduce what the dashboard screenshot actually shows. Swap in your real
dash.py (and its template) from the lab VM if you still have it.
"""
from flask import Flask, jsonify, render_template
import re
import os
import json
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime

app = Flask(__name__)

LOG_PATH = os.environ.get(
    "HONEYPORT_LOG",
    os.path.expanduser("~/Desktop/honeyport/honeypot_activity.log"),
)

# Loopback/private addresses don't resolve on public geolocation APIs. Rather
# than dropping them from the map, fall back to a fixed point (roughly the
# center of the continental US) so local testing still renders a marker —
# same as the dashboard screenshot shows for 127.0.0.1.
PRIVATE_IP_FALLBACK = (37.0902, -95.7129)


def is_private(ip):
    return ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip == "::1"


def get_logs():
    data = []
    try:
        with open(LOG_PATH) as f:
            for line in f:
                # Try multiple log formats
                m = re.search(
                    r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(\d+\.\d+\.\d+\.\d+).*?port\s+(\d+)',
                    line,
                )
                if m:
                    data.append({'time': m[1], 'ip': m[2], 'port': m[3]})
                else:
                    m2 = re.search(
                        r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(\d+\.\d+\.\d+\.\d+)',
                        line,
                    )
                    if m2:
                        data.append({'time': m2[1], 'ip': m2[2], 'port': 'unknown'})
    except Exception as e:
        print(f"Error reading logs: {e}")
    return data


def get_coords(ip):
    if is_private(ip):
        return PRIVATE_IP_FALLBACK
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}", timeout=2) as resp:
            info = json.loads(resp.read())
            if info.get("status") == "success":
                return (info["lat"], info["lon"])
    except Exception:
        pass
    return PRIVATE_IP_FALLBACK


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/data")
def api_data():
    logs = get_logs()
    ip_counts = Counter(entry["ip"] for entry in logs)

    markers = []
    for ip, hits in ip_counts.items():
        lat, lon = get_coords(ip)
        markers.append({"ip": ip, "hits": hits, "lat": lat, "lon": lon})

    # Bucket attacks per hour for the timeline chart
    timeline = defaultdict(int)
    for entry in logs:
        try:
            ts = datetime.strptime(entry["time"], "%Y-%m-%d %H:%M:%S")
            timeline[ts.strftime("%Y-%m-%d %H:00")] += 1
        except ValueError:
            continue

    return jsonify({
        "top_ips": ip_counts.most_common(10),
        "markers": markers,
        "timeline": dict(sorted(timeline.items())),
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
