#!/bin/bash
# PRISM Red Team — T1003: Shadow File Access Simulation
# Simulates an adversary reading /etc/shadow (requires elevated privileges).
# In a real attack, this is the first step toward offline password cracking.
# Here we only confirm read access and log the event — no contents are stored.

set -euo pipefail

LOG_DIR="$(dirname "$0")/../../logs/raw"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)
LOGFILE="${LOG_DIR}/t1003_shadow_${TIMESTAMP}.log"

echo "[T1003] Shadow file access simulation — $(date)" | tee "$LOGFILE"

if [[ $EUID -ne 0 ]]; then
    echo "[T1003] WARNING: Not running as root. /etc/shadow access will likely fail." | tee -a "$LOGFILE"
    echo "[T1003] Run with: sudo bash shadow_access.sh" | tee -a "$LOGFILE"
fi

echo "[T1003] Attempting to open /etc/shadow..." | tee -a "$LOGFILE"

# Simulation: check readability (do NOT print or store content)
if head -c 1 /etc/shadow > /dev/null 2>&1 || sudo head -c 1 /etc/shadow > /dev/null 2>&1; then
    echo "[T1003] SUCCESS: /etc/shadow is readable. Audit event generated." | tee -a "$LOGFILE"
    echo "[T1003] Real attack would extract hashes for offline cracking." | tee -a "$LOGFILE"
    echo "[T1003] PRISM only confirms access — no content is captured." | tee -a "$LOGFILE"
else
    echo "[T1003] FAIL: Could not read /etc/shadow (expected if unprivileged)." | tee -a "$LOGFILE"
fi

echo "[T1003] Simulation complete." | tee -a "$LOGFILE"
