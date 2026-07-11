#!/usr/bin/env python3
"""
PRISM Blue Team — Behavioral Correlator
Consumes normalized JSON from the log parser and applies detection logic
to identify MITRE T1036 (Masquerading) and T1003 (Credential Dumping).

Audit key mapping (prism.rules → detector):
  prism_t1036_exec_tmp / _shmem / _vartmp  → detect_t1036_masquerading (T1036.003)
  prism_t1036_prctl                         → detect_t1036_masquerading (T1036.005)
  prism_t1003_proc_open                     → detect_t1003_credential_dumping (T1003.007)
  prism_t1003_shadow / _gshadow             → detect_t1003_credential_dumping (T1003 base)
  prism_t1003_ptrace                        → detect_t1003_credential_dumping (future)
"""

import os
import json
import sys

# T1036 audit keys (from prism.rules)
T1036_KEYS = {
    "prism_t1036_exec_tmp",
    "prism_t1036_exec_shmem",
    "prism_t1036_exec_vartmp",
    "prism_t1036_prctl",
}

# T1003 audit keys (from prism.rules)
T1003_KEYS = {
    "prism_t1003_proc_open",
    "prism_t1003_shadow",
    "prism_t1003_gshadow",
    "prism_t1003_ptrace",
}

# Binaries legitimately allowed to read /proc/*/mem or /etc/shadow
WHITELISTED_PROCMEM_BINARIES = [
    "/bin/ps",
    "/usr/bin/ps",
    "/bin/top",
    "/usr/bin/top",
    "/usr/bin/htop",
    "/usr/lib/systemd/systemd",
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/sbin/unix_chkpwd",
]

# Known-good exe patterns that call prctl (JVM threads, Go runtime, Python)
KNOWN_PRCTL_CALLERS = ["java", "python", "go", "node", "ruby"]

def load_telemetry(filepath):
    """Loads normalized telemetry JSON."""
    if not os.path.exists(filepath):
        print(f"[Correlator] Error: Telemetry file {filepath} not found.", file=sys.stderr)
        return []
    with open(filepath, 'r') as f:
        return json.load(f)

def detect_t1036_masquerading(transaction):
    """
    Detects Process Masquerading (T1036.003 and T1036.005).

    T1036.003 — Rename System Utilities:
      Triggered by prism_t1036_exec_tmp / _shmem / _vartmp.
      A binary executes from a writable temp directory — a location no
      legitimate system service uses as a home.

    T1036.005 — Match Legitimate Name or Location:
      Triggered by prism_t1036_prctl.
      A process calls prctl(PR_SET_NAME) and its new comm name mimics a
      kernel thread or system daemon, while /proc/PID/exe points elsewhere.
    """
    tx_keys = set(transaction.get('keys', []))
    if not tx_keys & T1036_KEYS:
        return None

    exe  = transaction.get('exe') or ""
    comm = transaction.get('comm') or ""

    # Suppress known-good prctl callers (JVM, Python threading, Go runtime)
    if any(k in exe for k in KNOWN_PRCTL_CALLERS):
        return None

    TEMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")
    KERNEL_NAMES = ("kworker", "systemd", "syslogd", "kthreadd", "ksoftirqd",
                    "migration", "rcu_", "watchdog", "irq/")

    exe_basename = os.path.basename(exe)

    # Rule T1036.003 — execution from writable temp directory
    if any(exe.startswith(d) for d in TEMP_DIRS):
        claims_sys_name = any(n in comm for n in KERNEL_NAMES)
        rule_id  = "T1036.005-Masquerade" if claims_sys_name else "T1036.003-TempExec"
        severity = "HIGH"
        desc = (
            f"Process in temp directory claimed legitimate system name: exe={exe} | comm={comm}"
            if claims_sys_name else
            f"Binary executed from writable temp path: exe={exe} | comm={comm}"
        )
        return {"rule": rule_id, "severity": severity, "description": desc,
                "audit_id": transaction['audit_id']}

    # Rule T1036.005 — prctl name spoof: basename(exe) ≠ comm AND comm mimics system name
    if "prism_t1036_prctl" in tx_keys and exe and comm:
        if exe_basename != comm and any(n in comm for n in KERNEL_NAMES):
            return {
                "rule": "T1036.005-Masquerade-Prctl",
                "severity": "HIGH",
                "description": f"Process explicitly renamed to system thread via prctl: exe={exe} | comm={comm}",
                "audit_id": transaction['audit_id'],
            }

    return None


def detect_t1003_credential_dumping(transaction):
    """
    Detects OS Credential Dumping (T1003.007 and T1003 base).

    T1003.007 — /proc Filesystem:
      Triggered by prism_t1003_proc_open.
      Any non-whitelisted binary opening /proc/[pid]/mem or /proc/[pid]/maps
      is flagged. /proc/self/* reads are excluded (self-inspection is normal).

    T1003 base — Shadow File Access:
      Triggered by prism_t1003_shadow / prism_t1003_gshadow.
      Any non-whitelisted binary opening /etc/shadow or /etc/gshadow is CRITICAL.
    """
    tx_keys = set(transaction.get('keys', []))
    if not tx_keys & T1003_KEYS:
        return None

    exe   = transaction.get('exe') or ""
    paths = transaction.get('paths', [])

    # Whitelisted binaries — skip entirely
    if exe in WHITELISTED_PROCMEM_BINARIES:
        return None

    for path in paths:
        # Exclude self-reads (/proc/self/*) — JVM, Go runtime, sanitisers do this
        if "/proc/self/" in path:
            continue

        # T1003.007 — reading another process's memory or maps
        if "/mem" in path or ("/maps" in path and "/proc/" in path):
            return {
                "rule": "T1003.007-CredentialDump",
                "severity": "CRITICAL",
                "description": f"Unauthorized /proc memory access: exe={exe} | target={path}",
                "audit_id": transaction['audit_id'],
            }

        # T1003 base — shadow file access
        if "shadow" in path:
            return {
                "rule": "T1003-ShadowAccess",
                "severity": "CRITICAL",
                "description": f"Unauthorized shadow file access: exe={exe} | target={path}",
                "audit_id": transaction['audit_id'],
            }

    return None

def analyze(telemetry):
    """Runs all detection rules against the telemetry set."""
    detections = []
    for tx in telemetry:
        # Run T1036
        alert_1036 = detect_t1036_masquerading(tx)
        if alert_1036:
            detections.append(alert_1036)
            
        # Run T1003
        alert_1003 = detect_t1003_credential_dumping(tx)
        if alert_1003:
            detections.append(alert_1003)
            
    return detections

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 correlator.py <path_to_parsed_telemetry.json>")
        sys.exit(1)
        
    input_file = sys.argv[1]
    output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../logs/parsed/detections.json")
    
    print(f"[Correlator] Analyzing {input_file}...")
    telemetry = load_telemetry(input_file)
    
    hits = analyze(telemetry)
    
    with open(output_file, 'w') as f:
        json.dump(hits, f, indent=4)
        
    print(f"[Correlator] Analysis complete. {len(hits)} behavioral anomalies detected.")
    print(f"[Correlator] Detections written to {output_file}")

if __name__ == "__main__":
    main()
