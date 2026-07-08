#!/bin/bash
# PRISM Blue Team — Kernel Hook Installer
# Installs custom auditd rules and restarts the daemon.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[Blue] Error: This script must be run as root to modify audit rules."
   exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RULES_FILE="${SCRIPT_DIR}/prism.rules"

echo "[Blue] Installing PRISM audit rules from ${RULES_FILE}..."
cp "$RULES_FILE" /etc/audit/rules.d/prism.rules

echo "[Blue] Loading rules into kernel..."
augenrules --load

echo "[Blue] Restarting auditd service..."
systemctl restart auditd

echo "[Blue] Verifying rules..."
auditctl -l | grep prism

echo "[Blue] Kernel hooks installed successfully."
