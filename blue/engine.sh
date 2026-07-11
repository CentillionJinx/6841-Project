#!/bin/bash
# PRISM Blue Team — Behavioral Engine Orchestrator
# Runs the log parser, correlator, and alerter in sequence.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_FILE="/var/log/audit/audit.log"
PARSED_JSON="${SCRIPT_DIR}/../logs/parsed/parsed_telemetry.json"
DETECTIONS_JSON="${SCRIPT_DIR}/../logs/parsed/detections.json"

echo "=========================================================="
echo "    PRISM: BLUE TEAM BEHAVIORAL ENGINE"
echo "=========================================================="

if [ ! -f "$LOG_FILE" ]; then
    echo "[Engine] Error: Audit log not found at $LOG_FILE"
    echo "[Engine] Hint: Is auditd running? Did you run install_hooks.sh?"
    exit 1
fi

echo "[*] Step 1: Parsing raw telemetry..."
python3 "${SCRIPT_DIR}/parser/log_parser.py" "$LOG_FILE"

if [ -f "$PARSED_JSON" ]; then
    echo "[*] Step 2: Correlating behavioral telemetry..."
    python3 "${SCRIPT_DIR}/parser/correlator.py" "$PARSED_JSON"
fi

if [ -f "$DETECTIONS_JSON" ]; then
    echo "[*] Step 3: Emitting alerts..."
    python3 "${SCRIPT_DIR}/parser/alerter.py" "$DETECTIONS_JSON"
fi

echo "=========================================================="
echo "    ENGINE CYCLE COMPLETE"
echo "=========================================================="
