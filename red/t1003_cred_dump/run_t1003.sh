#!/bin/bash
# PRISM Red Team — T1003 Master Runner
# Executes all T1003 simulation steps in sequence and captures audit logs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}/../.."
LOG_DIR="${ROOT_DIR}/logs/raw"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)
MASTER_LOG="${LOG_DIR}/t1003_master_${TIMESTAMP}.log"

echo "========================================" | tee "$MASTER_LOG"
echo "[T1003] PRISM Red Team — Credential Dumping Simulation" | tee -a "$MASTER_LOG"
echo "[T1003] Start time: $(date)" | tee -a "$MASTER_LOG"
echo "========================================" | tee -a "$MASTER_LOG"

# Capture audit log line count BEFORE simulation
if [ -f /var/log/audit/audit.log ]; then
    AUDIT_LINE_BEFORE=$(wc -l < /var/log/audit/audit.log)
else
    AUDIT_LINE_BEFORE=0
fi
echo "[T1003] Audit log line count before: ${AUDIT_LINE_BEFORE}" | tee -a "$MASTER_LOG"

# Ensure dummy target is running
if ! pgrep -f "dummy_cred_holder" > /dev/null; then
    echo "[T1003] Starting dummy_cred_holder.sh in background..." | tee -a "$MASTER_LOG"
    if [ -x /usr/local/bin/dummy_cred_holder.sh ]; then
        /usr/local/bin/dummy_cred_holder.sh &
    else
        echo "[T1003] Error: dummy_cred_holder.sh not found." | tee -a "$MASTER_LOG"
    fi
fi
sleep 2

# --- Step 1: Shadow File Access ---
echo "[T1003] Running shadow_access.sh..." | tee -a "$MASTER_LOG"
bash "${SCRIPT_DIR}/shadow_access.sh" 2>&1 | tee -a "$MASTER_LOG" || true
sleep 2

# --- Step 2: /proc Memory Traversal ---
echo "[T1003] Running proc_mem_scan.py..." | tee -a "$MASTER_LOG"
python3 "${SCRIPT_DIR}/proc_mem_scan.py" 2>&1 | tee -a "$MASTER_LOG" || true
sleep 2

# --- Capture delta audit events ---
if [ -f /var/log/audit/audit.log ]; then
    AUDIT_LINE_AFTER=$(wc -l < /var/log/audit/audit.log)
    AUDIT_DELTA_FILE="${LOG_DIR}/t1003_audit_delta_${TIMESTAMP}.log"
    echo "[T1003] Capturing $((AUDIT_LINE_AFTER - AUDIT_LINE_BEFORE)) new audit events..." | tee -a "$MASTER_LOG"
    tail -n +$((AUDIT_LINE_BEFORE + 1)) /var/log/audit/audit.log > "$AUDIT_DELTA_FILE"
    echo "[T1003] Audit delta saved to: ${AUDIT_DELTA_FILE}" | tee -a "$MASTER_LOG"
else
    echo "[T1003] WARNING: /var/log/audit/audit.log not found. Skip capturing delta." | tee -a "$MASTER_LOG"
fi

echo "========================================" | tee -a "$MASTER_LOG"
echo "[T1003] Simulation complete. End time: $(date)" | tee -a "$MASTER_LOG"
echo "========================================" | tee -a "$MASTER_LOG"
