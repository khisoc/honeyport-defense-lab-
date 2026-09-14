#!/bin/bash
echo "[*] Attack Scenario 1: Nmap Port Scanning"
echo "[*] Performing stealth SYN scan against honeyports..."

# Perform a SYN scan against our honeyport range
nmap -sS -p 23,8080,8443,9000,9090,9999 localhost

echo "[*] Nmap scan completed"
echo "[*] Check honeyport logs to see detection results"
