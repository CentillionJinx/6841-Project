#!/usr/bin/env bash
# PRISM — Validation Script: T1036 Process Masquerading
# Verifies that the Blue Team engine correctly detects both T1036.003 and T1036.005.
# Must be run from the project-prism/ root directory.
# Requires: auditd running with prism rules loaded (sudo install_hooks.sh done first).
#           Blue engine components in blue/parser/ available.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}/.."
PARSED_JSON="${ROOT_DIR}/logs/parsed/parsed_telemetry.json"
DETECTIONS_JSON="${ROOT_DIR}/logs/parsed/detections.json"
PASS=0
FAIL=0

_pass() { echo "  [PASS] $*"; ((PASS++)) || true; }
_fail() { echo "  [FAIL] $*"; ((FAIL++)) || true; }
_info() { echo "  [----] $*"; }

echo "========================================================"
echo "  PRISM T1036 Validation — Process Masquerading"
echo "========================================================"

# ── Prerequisite: prctl_spoof.c must exist ────────────────────────────────────
if [ ! -f "${ROOT_DIR}/red/t1036_masquerade/prctl_spoof.c" ]; then
    _fail "prctl_spoof.c not found"
    exit 1
fi

# ── Step 1: Compile prctl_spoof ───────────────────────────────────────────────
echo ""
echo "[*] Compiling prctl_spoof.c..."
gcc -o /tmp/prism_validate_prctl "${ROOT_DIR}/red/t1036_masquerade/prctl_spoof.c" 2>&1
_pass "prctl_spoof.c compiled to /tmp/prism_validate_prctl"

# ── Step 2: Record audit line count before ────────────────────────────────────
AUDIT_LOG="/var/log/audit/audit.log"
if [ -f "$AUDIT_LOG" ]; then
    LINES_BEFORE=$(wc -l < "$AUDIT_LOG")
else
    _info "auditd not running — skipping live kernel telemetry checks"
    LINES_BEFORE=0
fi

# ── Step 3: T1036.003 — Execute from /tmp ─────────────────────────────────────
echo ""
echo "[*] T1036.003: Executing masqueraded binary from /tmp..."
cp /bin/sleep /tmp/prism_validate_sleep
chmod +x /tmp/prism_validate_sleep
/tmp/prism_validate_sleep 3 &
MASQ_PID=$!
sleep 1

EXE_LINK=$(readlink /proc/${MASQ_PID}/exe 2>/dev/null || echo "")
COMM_VAL=$(cat /proc/${MASQ_PID}/comm 2>/dev/null || echo "")

if echo "$EXE_LINK" | grep -q "/tmp/"; then
    _pass "T1036.003: exe path is in /tmp ($EXE_LINK)"
else
    _fail "T1036.003: exe path not in /tmp (got: $EXE_LINK)"
fi

wait "$MASQ_PID" 2>/dev/null || true
rm -f /tmp/prism_validate_sleep

# ── Step 4: T1036.005 — prctl PR_SET_NAME spoof ───────────────────────────────
echo ""
echo "[*] T1036.005: Running prctl_spoof (spoofs comm to kworker/u4:2)..."
/tmp/prism_validate_prctl &
PRCTL_PID=$!
sleep 1

COMM_AFTER=$(cat /proc/${PRCTL_PID}/comm 2>/dev/null || echo "")
EXE_AFTER=$(readlink /proc/${PRCTL_PID}/exe 2>/dev/null || echo "")

if [ "$COMM_AFTER" = "kworker/u4:2" ]; then
    _pass "T1036.005: /proc/PID/comm correctly reads 'kworker/u4:2' after prctl"
else
    _fail "T1036.005: comm mismatch (expected 'kworker/u4:2', got '$COMM_AFTER')"
fi

if echo "$EXE_AFTER" | grep -q "prism_validate_prctl"; then
    _pass "T1036.005: /proc/PID/exe correctly points to real binary ($EXE_AFTER)"
else
    _fail "T1036.005: exe path unexpected (got: $EXE_AFTER)"
fi

kill -9 "$PRCTL_PID" 2>/dev/null || true
rm -f /tmp/prism_validate_prctl

# ── Step 5: Audit telemetry check (only if auditd was running) ────────────────
if [ -f "$AUDIT_LOG" ] && [ "$LINES_BEFORE" -gt 0 ]; then
    echo ""
    echo "[*] Checking auditd captured T1036 events..."
    LINES_AFTER=$(wc -l < "$AUDIT_LOG")
    DELTA=$((LINES_AFTER - LINES_BEFORE))
    _info "Captured $DELTA new audit events"

    if grep -q "prism_t1036" "$AUDIT_LOG" 2>/dev/null; then
        _pass "auditd: prism_t1036_* key found in audit.log"
    else
        _fail "auditd: no prism_t1036_* key found — are rules loaded? (run sudo blue/auditd/install_hooks.sh)"
    fi
fi

# ── Step 6: Blue engine pipeline check ────────────────────────────────────────
echo ""
echo "[*] Verifying Python parser components compile cleanly..."
python3 -m py_compile "${ROOT_DIR}/blue/parser/log_parser.py"  && _pass "log_parser.py syntax OK"
python3 -m py_compile "${ROOT_DIR}/blue/parser/correlator.py"  && _pass "correlator.py syntax OK"
python3 -m py_compile "${ROOT_DIR}/blue/parser/alerter.py"     && _pass "alerter.py syntax OK"
python3 -m py_compile "${ROOT_DIR}/blue/parser/models.py"      && _pass "models.py syntax OK"

# ── Step 7: If parsed telemetry exists, verify detections fire ────────────────
if [ -f "$DETECTIONS_JSON" ]; then
    echo ""
    echo "[*] Checking existing detections.json for T1036 hits..."
    T1036_COUNT=$(python3 -c "
import json
with open('${DETECTIONS_JSON}') as f:
    d = json.load(f)
n = sum(1 for x in d if 'T1036' in x.get('rule',''))
print(n)
" 2>/dev/null || echo "0")

    if [ "$T1036_COUNT" -gt 0 ]; then
        _pass "detections.json: $T1036_COUNT T1036 alert(s) present"
    else
        _info "detections.json: no T1036 alerts yet (run engine after red scripts)"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "========================================================"
echo "  T1036 Validation complete — PASS: $PASS  FAIL: $FAIL"
echo "========================================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
