#!/bin/bash
# PRISM Red Team — T1036.003: Rename System Utilities
# Emulates adversary copying a legitimate binary under a masquerading name,
# then executing it. Demonstrates how argv[0] and exe path diverge.

set -euo pipefail

LOG_DIR="$(dirname "$0")/../../logs/raw"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)
LOGFILE="${LOG_DIR}/t1036_rename_${TIMESTAMP}.log"

echo "[T1036.003] Starting rename_exec simulation at ${TIMESTAMP}" | tee -a "$LOGFILE"

# Step 1: Copy a benign system binary under a masquerading name
DECOY_NAME="systemd-helper"           # Name of a plausible-looking system process
DECOY_PATH="/tmp/${DECOY_NAME}"

echo "[T1036.003] Copying /bin/sleep to ${DECOY_PATH}" | tee -a "$LOGFILE"
cp /bin/sleep "${DECOY_PATH}"
chmod +x "${DECOY_PATH}"

# Step 2: Execute the masqueraded binary
# This causes: exe=/tmp/systemd-helper but comm=systemd-helper
# A weak rule watching only process names will miss this
echo "[T1036.003] Executing masqueraded binary (sleep 5) as ${DECOY_NAME}" | tee -a "$LOGFILE"
"${DECOY_PATH}" 5 &
MASQ_PID=$!

echo "[T1036.003] Masqueraded process PID: ${MASQ_PID}" | tee -a "$LOGFILE"
echo "[T1036.003] Check: /proc/${MASQ_PID}/exe should point to /tmp/${DECOY_NAME}" | tee -a "$LOGFILE"
ls -la /proc/${MASQ_PID}/exe 2>/dev/null | tee -a "$LOGFILE" || true
cat /proc/${MASQ_PID}/comm 2>/dev/null | tee -a "$LOGFILE" || true

wait $MASQ_PID 2>/dev/null || true

# Step 3: Clean up
echo "[T1036.003] Cleaning up ${DECOY_PATH}" | tee -a "$LOGFILE"
rm -f "${DECOY_PATH}"

echo "[T1036.003] Simulation complete. Log: ${LOGFILE}" | tee -a "$LOGFILE"
