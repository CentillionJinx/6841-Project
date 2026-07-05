#!/bin/bash
# PRISM Red Team — T1036 Master Runner
# Executes all T1036 simulation steps in sequence and captures audit logs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}/../.."
LOG_DIR="${ROOT_DIR}/logs/raw"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)
MASTER_LOG="${LOG_DIR}/t1036_master_${TIMESTAMP}.log"

echo "========================================" | tee "$MASTER_LOG"
echo "[T1036] PRISM Red Team — Process Masquerading Simulation" | tee -a "$MASTER_LOG"
echo "[T1036] Start time: $(date)" | tee -a "$MASTER_LOG"
echo "========================================" | tee -a "$MASTER_LOG"

# Capture audit log line count BEFORE simulation (for diffing afterward)
if [ -f /var/log/audit/audit.log ]; then
    AUDIT_LINE_BEFORE=$(wc -l < /var/log/audit/audit.log)
else
    AUDIT_LINE_BEFORE=0
fi
echo "[T1036] Audit log line count before: ${AUDIT_LINE_BEFORE}" | tee -a "$MASTER_LOG"

# --- Step 1: Binary Rename Emulation ---
echo "[T1036] Running rename_exec.sh..." | tee -a "$MASTER_LOG"
bash "${SCRIPT_DIR}/rename_exec.sh" 2>&1 | tee -a "$MASTER_LOG"
sleep 2

# --- Step 2: Compile and run prctl spoof ---
echo "[T1036] Compiling prctl_spoof.c..." | tee -a "$MASTER_LOG"
gcc -o /tmp/prism_prctl_spoof "${SCRIPT_DIR}/prctl_spoof.c" 2>&1 | tee -a "$MASTER_LOG"
echo "[T1036] Running prctl_spoof..." | tee -a "$MASTER_LOG"
/tmp/prism_prctl_spoof &
PRCTL_PID=$!
sleep 2
kill -9 $PRCTL_PID 2>/dev/null || true

# --- Capture delta audit events ---
if [ -f /var/log/audit/audit.log ]; then
    AUDIT_LINE_AFTER=$(wc -l < /var/log/audit/audit.log)
    AUDIT_DELTA_FILE="${LOG_DIR}/t1036_audit_delta_${TIMESTAMP}.log"
    echo "[T1036] Capturing $((AUDIT_LINE_AFTER - AUDIT_LINE_BEFORE)) new audit events..." | tee -a "$MASTER_LOG"
    tail -n +$((AUDIT_LINE_BEFORE + 1)) /var/log/audit/audit.log > "$AUDIT_DELTA_FILE"
    echo "[T1036] Audit delta saved to: ${AUDIT_DELTA_FILE}" | tee -a "$MASTER_LOG"
else
    echo "[T1036] WARNING: /var/log/audit/audit.log not found. Skip capturing delta." | tee -a "$MASTER_LOG"
fi

# --- Cleanup ---
rm -f /tmp/prism_prctl_spoof

echo "========================================" | tee -a "$MASTER_LOG"
echo "[T1036] Simulation complete. End time: $(date)" | tee -a "$MASTER_LOG"
echo "========================================" | tee -a "$MASTER_LOG"
