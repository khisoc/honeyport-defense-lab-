#!/bin/bash
echo "[*] Attack Scenario 2: DoS Attack Using hping3"
echo "[*] Flooding honeyport 9999 with TCP SYN packets..."

# Flood port 9999 with TCP SYN packets (DoS simulation)
sudo timeout 10s hping3 -S -p 9999 -c 100 --flood localhost

echo "[*] DoS attack simulation completed"
echo "[*] Check honeyport logs to see detection results"
