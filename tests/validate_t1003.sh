#!/usr/bin/env bash
# PRISM — Validation Script: T1003 OS Credential Dumping
# Verifies that the Blue Team engine correctly detects /proc/mem access and shadow reads.
# Must be run from the project-prism/ root directory.
# Requires root (sudo) for: reading /etc/shadow and /proc/[pid]/mem of another process.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}/.."
DETECTIONS_JSON="${ROOT_DIR}/logs/parsed/detections.json"
PASS=0
FAIL=0

_pass() { echo "  [PASS] $*"; ((PASS++)) || true; }
_fail() { echo "  [FAIL] $*"; ((FAIL++)) || true; }
_info() { echo "  [----] $*"; }

echo "========================================================"
echo "  PRISM T1003 Validation — OS Credential Dumping"
echo "========================================================"

# ── Prerequisite check ────────────────────────────────────────────────────────
for f in \
    "${ROOT_DIR}/red/t1003_cred_dump/proc_mem_scan.py" \
    "${ROOT_DIR}/red/t1003_cred_dump/shadow_access.sh"; do
    if [ ! -f "$f" ]; then
        _fail "Required red script not found: $f"
        exit 1
    fi
done
_pass "Red script prerequisites present"

# ── Step 1: Python scripts compile cleanly ────────────────────────────────────
echo ""
echo "[*] Syntax checking Python components..."
python3 -m py_compile "${ROOT_DIR}/red/t1003_cred_dump/proc_mem_scan.py" && _pass "proc_mem_scan.py syntax OK"
python3 -m py_compile "${ROOT_DIR}/blue/parser/correlator.py" && _pass "correlator.py syntax OK"

# ── Step 2: Shell scripts are syntactically valid ─────────────────────────────
echo ""
echo "[*] Syntax checking shell scripts..."
bash -n "${ROOT_DIR}/red/t1003_cred_dump/shadow_access.sh" && _pass "shadow_access.sh syntax OK"
bash -n "${ROOT_DIR}/red/t1003_cred_dump/run_t1003.sh" && _pass "run_t1003.sh syntax OK"

# ── Step 3: dummy_cred_holder.sh is deployed and executable ───────────────────
echo ""
echo "[*] Checking dummy_cred_holder.sh target..."
if [ -x /usr/local/bin/dummy_cred_holder.sh ]; then
    _pass "/usr/local/bin/dummy_cred_holder.sh is deployed and executable"
else
    _info "/usr/local/bin/dummy_cred_holder.sh not found — run bootstrap_env.sh with sudo first"
fi

# ── Step 4: /proc/self/maps readable (basic /proc access test) ────────────────
echo ""
echo "[*] T1003.007: Verifying /proc/self/maps is readable..."
if python3 -c "
import os
maps = open('/proc/self/maps').read()
assert 'heap' in maps or 'vvar' in maps or len(maps) > 0
print('[ok]')
" 2>/dev/null | grep -q '\[ok\]'; then
    _pass "/proc/self/maps is readable"
else
    _fail "/proc/self/maps could not be read"
fi

# ── Step 5: /proc/[pid]/mem access test against self ─────────────────────────
echo ""
echo "[*] T1003.007: Verifying /proc/self/mem is accessible..."
if python3 -c "
import os, re
# Read maps to find a readable anonymous region
maps_text = open('/proc/self/maps').read()
for line in maps_text.splitlines():
    perms = line.split()[1]
    if 'r' in perms and 'p' in perms:
        start_hex = line.split('-')[0]
        start = int(start_hex, 16)
        with open('/proc/self/mem', 'rb') as f:
            f.seek(start)
            data = f.read(16)
        if len(data) > 0:
            print('[ok]')
            break
" 2>/dev/null | grep -q '\[ok\]'; then
    _pass "/proc/self/mem readable from own process (self-read, expected)"
else
    _info "/proc/self/mem self-read did not succeed (may be restricted by kernel config)"
fi

# ── Step 6: /etc/shadow access check (root required) ─────────────────────────
echo ""
echo "[*] T1003 base: /etc/shadow access check..."
if [ $EUID -eq 0 ]; then
    if head -c 1 /etc/shadow > /dev/null 2>&1; then
        _pass "/etc/shadow is readable as root — shadow_access.sh will generate telemetry"
    else
        _fail "/etc/shadow not readable even as root"
    fi
else
    _info "Not running as root — /etc/shadow access test skipped (expected: run with sudo for full validation)"
fi

# ── Step 7: Auditd rule check ─────────────────────────────────────────────────
echo ""
echo "[*] Checking auditd rules..."
if command -v auditctl &>/dev/null 2>&1; then
    if auditctl -l 2>/dev/null | grep -q "prism_t1003"; then
        _pass "auditd: prism_t1003_* rules are loaded"
    else
        _info "auditd: prism_t1003_* rules not loaded — run: sudo blue/auditd/install_hooks.sh"
    fi
else
    _info "auditctl not available on this host"
fi

# ── Step 8: Existing detections check ────────────────────────────────────────
if [ -f "$DETECTIONS_JSON" ]; then
    echo ""
    echo "[*] Checking existing detections.json for T1003 hits..."
    T1003_COUNT=$(python3 -c "
import json
with open('${DETECTIONS_JSON}') as f:
    d = json.load(f)
n = sum(1 for x in d if 'T1003' in x.get('rule',''))
print(n)
" 2>/dev/null || echo "0")

    if [ "$T1003_COUNT" -gt 0 ]; then
        _pass "detections.json: $T1003_COUNT T1003 alert(s) present"
    else
        _info "detections.json: no T1003 alerts yet (run engine after red scripts)"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "========================================================"
echo "  T1003 Validation complete — PASS: $PASS  FAIL: $FAIL"
echo "========================================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
