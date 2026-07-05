#!/bin/bash
# PRISM Red Team — Master Emulation Harness
# Triggers both T1036 (Masquerading) and T1003 (Credential Dumping) simulations.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "=========================================================="
echo "    PRISM: RED TEAM ADVERSARY EMULATION HARNESS"
echo "=========================================================="
echo "[*] Triggering T1036: Process Masquerading..."
bash "${SCRIPT_DIR}/t1036_masquerade/run_t1036.sh"

echo ""
echo "[*] Triggering T1003: OS Credential Dumping..."
bash "${SCRIPT_DIR}/t1003_cred_dump/run_t1003.sh"

echo "=========================================================="
echo "    ALL ADVERSARY EMULATIONS COMPLETE"
echo "    Verify telemetry in logs/raw/"
echo "=========================================================="
