# ADS: Process Masquerading on Linux Endpoints
**Technique:** MITRE ATT&CK T1036 / T1036.003 / T1036.005
**Status:** Production-Ready (PRISM Lab)
**Author:** Gururam Subramanian (z5636559)
**Last Updated:** 2026-06-30
**Priority:** HIGH

---

## Goal

Detect adversary attempts to disguise malicious processes by either (a) executing a
renamed copy of a legitimate system binary from a non-standard path (`/tmp`, `/dev/shm`,
`/var/tmp`), or (b) spoofing a process's reported name via `prctl(PR_SET_NAME)`, causing
the process to appear as a legitimate kernel daemon in process listings while the
underlying `exe` path remains malicious.

---

## Categorization

- **MITRE ATT&CK Parent:** Defense Evasion / T1036 — Masquerading
- **Sub-techniques in scope:**
  - T1036.003 — Rename System Utilities (executable copied to `/tmp`, `/dev/shm`, `/var/tmp`)
  - T1036.005 — Match Legitimate Name or Location (`prctl PR_SET_NAME` name spoofing)
- **Kill Chain Phase:** Defense Evasion (post-initial access, pre-execution of payload)
- **Asset Type:** Linux endpoint (Ubuntu 22.04 LTS, kernel 5.15+)
- **Data Source:** Linux auditd (`execve` syscall events, `prctl` syscall events)

---

## Strategy Abstract

This ADS monitors two behavioral indicators at the kernel syscall level:

**Rule 1 — Execution from writable temp path (T1036.003):**
The detection subscribes to `execve` syscall events where the `exe` field resolves to a
path under `/tmp`, `/dev/shm`, or `/var/tmp`. Legitimate system processes virtually never
originate from these directories; execution from them is a strong indicator that an
adversary copied a binary out of a monitored path to evade file-integrity monitoring.
The `exe` field is sourced directly from the kernel's process table (not `argv[0]`) and
cannot be trivially forged from userspace.

**Rule 2 — Process name spoofing via prctl (T1036.005):**
The detection subscribes to `prctl` syscall events with `option=15` (`PR_SET_NAME`). After
a successful call, the process's name as shown by `ps`, `top`, and `/proc/PID/comm` changes
to the adversary-controlled string, while `/proc/PID/exe` still points to the true binary.
The mismatch between `comm` (reported name) and `basename(exe)` (actual binary) is the
definitive indicator of this technique.

Both rules emit HIGH severity alerts upon detection.

---

## Technical Context

### OS Mechanism

On Linux, every process has two distinct name fields:

- `/proc/PID/comm` — a 15-character string readable/writable via `prctl(PR_SET_NAME)`
- `/proc/PID/exe` — a symlink to the actual file on disk that was `exec()`'d (kernel-set,
  cannot be changed by the process itself)

The `auditd` subsystem hooks into the kernel's audit framework and logs `execve()` calls
as `SYSCALL type=59` records, including the `exe` field from the kernel's task struct.
`prctl()` calls are logged as `SYSCALL type=158` records with the `a0` field encoding the
prctl option (`0x0f = 15 = PR_SET_NAME`).

### Why Standard Defenses Miss This

- **Signature-based AV/EDR:** Compares file hash or file name. A renamed copy of
  `/bin/sleep` still has the same hash but a different path — a hash-based tool detects it
  only if it walks the full filesystem; a name-based tool does not.
- **Process name monitors:** Tools watching `/proc/PID/comm` or `ps aux` output are
  trivially defeated by `prctl(PR_SET_NAME)` — they see only the spoofed name.
- **Missing behavioral correlation:** Most tools alert on individual events. The real
  signal is the *relationship* between `comm ≠ basename(exe)`, or `exe path ∉ {/usr, /bin, /sbin}`.

### Audit Rule Syntax

```
# Execution from writable temp directories
-a always,exit -F arch=b64 -S execve -F dir=/tmp     -k prism_t1036_exec_tmp
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k prism_t1036_exec_shmem
-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k prism_t1036_exec_vartmp

# Process name spoofing via prctl (syscall 158, option PR_SET_NAME = 15)
-a always,exit -F arch=b64 -S prctl -k prism_t1036_prctl
```

### Sample Raw Audit Event (T1036.003)

```
type=SYSCALL msg=audit(1751302903.456:5492): arch=c000003e syscall=59 success=yes
exit=0 a0=7ffe1234 a1=7ffe5678 a2=7ffecafe items=2 ppid=224809 pid=224813
auid=1000 uid=0 gid=0 euid=0 egid=0 tty=pts0 ses=1
comm="systemd-helper" exe="/tmp/systemd-helper" key="prism_t1036_exec_tmp"
```

Key fields: `exe=/tmp/systemd-helper` (not in `/usr`, `/bin`, `/sbin`), `comm=systemd-helper`
(mimics a legitimate systemd process name). Mismatch is the detection signal.

### Sample Raw Audit Event (T1036.005)

```
type=SYSCALL msg=audit(1751302910.123:5501): arch=c000003e syscall=158 success=yes
exit=0 a0=f a1=7fff1234 a2=0 a3=0 items=0 ppid=224801 pid=224820
auid=1000 uid=0 gid=0 comm="prctl_spoof" exe="/tmp/prism_prctl_spoof"
key="prism_t1036_prctl"
```

Key fields: `syscall=158` (prctl), `a0=f` (option=15=PR_SET_NAME), `exe=/tmp/prism_prctl_spoof`
reveals the true binary despite `comm` being renamed to `kworker/u4:2`.

---

## Blind Spots and Assumptions

1. **Legitimate temp-path execution:** Some CI/CD pipelines or package managers temporarily
   extract and execute binaries from `/tmp` during installation. These trigger the rule and
   must be suppressed by tracking known-good installation contexts (filter by `ppid=apt-get`, `dpkg`).

2. **prctl called before audit rules load:** If the attacker calls `PR_SET_NAME` before
   `auditd` loads its rules at boot (e.g., from early persistence), the event will be missed.

3. **In-memory execution (fileless):** If an adversary executes a payload entirely in
   memory via `memfd_create + fexecve()`, this rule will not fire. A complementary rule
   monitoring `memfd_create()` (syscall 319) would be required.

4. **Container environments:** Paths in containerised workloads may legitimately use
   `/tmp` for execution. This rule should be scoped to host processes only when deployed
   in a container-heavy environment.

5. **Kernel version dependency:** `prctl PR_SET_NAME` audit logging requires kernel ≥ 4.15
   and `auditd` ≥ 2.8.

---

## False Positives

The following are known legitimate scenarios that trigger this rule:

| Source | Rule Triggered | Suppression Logic |
|--------|----------------|-------------------|
| `python3` threading | T1036.005 — prctl | Filter: `exe` contains `python3` or `python` |
| `java` JVM threads | T1036.005 — prctl | Filter: `exe` contains `java` |
| `go` runtime goroutines | T1036.005 — prctl | Filter: `exe` contains go binary path |
| `cmake` / `make` test runners | T1036.003 — tmp exec | Filter: `ppid` resolves to `cmake` or `make` |
| Package manager postinst scripts | T1036.003 — tmp exec | Filter: `ppid` resolves to `dpkg` or `apt` |

All suppression logic is implemented in `blue/parser/correlator.py` within
`KNOWN_PRCTL_CALLERS` and via the whitelisted parent process check.

---

## Validation

To generate a true positive for this ADS:

**T1036.003 Validation:**
```bash
cp /bin/sleep /tmp/systemd-helper
chmod +x /tmp/systemd-helper
/tmp/systemd-helper 5 &
# Expected: Alert T1036.003-TempExec fires after blue/engine.sh runs
ls -la /proc/$!/exe   # Confirms exe=/tmp/systemd-helper
rm /tmp/systemd-helper
```

**T1036.005 Validation:**
```bash
gcc -o /tmp/prism_prctl_spoof red/t1036_masquerade/prctl_spoof.c
/tmp/prism_prctl_spoof &
cat /proc/$!/comm     # Should read: kworker/u4:2
ls -la /proc/$!/exe   # Should read: /tmp/prism_prctl_spoof (mismatch!)
kill %1
rm /tmp/prism_prctl_spoof
# Expected: Alert T1036.005-Masquerade-Prctl fires after blue/engine.sh runs
```

**Automated validation:**
```bash
bash tests/validate_t1036.sh
# Expected exit code: 0 (PASS)
```

---

## Priority

| Condition | Severity |
|-----------|----------|
| Execution from `/tmp` + `uid=0` (root) + comm mimics kernel name | HIGH |
| Execution from `/tmp` + `uid≠0` | HIGH |
| `prctl PR_SET_NAME` + `exe` in `/tmp` + `comm` = known system name | HIGH |
| `prctl PR_SET_NAME` + `exe` in normal path + `comm` = known system name | MEDIUM |

---

## Response

Upon alert:

1. **Triage (< 5 min):** Note `pid`, `exe`, `ppid` from alert evidence. Check if process
   is still running: `ls -la /proc/<PID>/exe`
2. **Confirm (< 10 min):** Compare `comm` vs `basename(exe)`. If `comm` mimics a system
   daemon name (e.g., `kworker`) but `exe` is not under `/usr/lib/systemd/` → escalate.
3. **Preserve:** Capture full process tree: `ps aux | grep -P "<PID>|<PPID>"`
   Capture open files: `lsof -p <PID>`
   Capture network connections: `ss -tp | grep <PID>`
4. **Isolate:** If confirmed malicious, terminate the process and take a memory snapshot
   before termination if forensics are required: `gcore <PID>`
5. **Hunt:** Search audit logs for additional `execve` events from the same `PPID` (parent
   process may have spawned multiple masqueraded children).

---

## Additional Resources

- MITRE ATT&CK T1036: https://attack.mitre.org/techniques/T1036/
- Linux `prctl(2)` man page: https://man7.org/linux/man-pages/man2/prctl.2.html
- Linux Audit Syscall Reference: https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl
- Palantir ADS Framework: https://github.com/palantir/alerting-detection-strategy-framework
- Project PRISM correlator rule: `blue/parser/correlator.py` → `detect_t1036_masquerading`
