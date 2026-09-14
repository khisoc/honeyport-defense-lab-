#!/bin/bash
echo "[*] Simulating attacker scanning our honeyports..."

# Simulate an attacker scanning our honeyport range
for port in 23 8080 8443 9000 9090 9999; do
    echo "Scanning port $port..."
    timeout 2 nc -w 1 localhost $port > /dev/null 2>&1
    sleep 0.5
done

echo "[*] Attack simulation complete"
echo "[*] Check honeyport_activity.log for detection results"
