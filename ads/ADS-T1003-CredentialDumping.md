# ADS: OS Credential Dumping via /proc Filesystem and Shadow File Access
**Technique:** MITRE ATT&CK T1003 / T1003.007
**Status:** Production-Ready (PRISM Lab)
**Author:** Gururam Subramanian (z5636559)
**Last Updated:** 2026-06-30
**Priority:** CRITICAL

---

## Goal

Detect adversaries reading process memory via the Linux `/proc` filesystem
(specifically `/proc/[pid]/mem`) to extract in-memory credentials, authentication tokens,
or secrets from running processes without triggering traditional file-based detection.
Additionally, detect unauthorised access to `/etc/shadow` and `/etc/gshadow` for offline
password cracking.

---

## Categorization

- **MITRE ATT&CK Parent:** Credential Access / T1003 — OS Credential Dumping
- **Sub-techniques in scope:**
  - T1003.007 — `/proc` Filesystem (memory reading via `/proc/PID/mem`)
  - T1003 (general) — `/etc/shadow` and `/etc/gshadow` direct access
- **Kill Chain Phase:** Credential Access
- **Asset Type:** Linux endpoint (Ubuntu 22.04 LTS)
- **Data Source:** Linux auditd (`open`/`openat` syscall events on `/proc/*/mem`, `/etc/shadow`)

---

## Strategy Abstract

This ADS monitors two credential theft vectors at the system call level:

**Rule 1 — `/proc/[pid]/mem` surgical read (T1003.007):**
Subscribes to `open` and `openat` syscall events where the `name` (path) field matches
`/proc/[numeric-pid]/mem` or `/proc/[numeric-pid]/maps`. The `/proc/<pid>/mem` pseudofile
provides direct read access to the virtual address space of any process whose UID the
reader can match (or any process if running as root). Adversaries use this to extract
plaintext credentials, session tokens, and encryption keys held in the heap or stack of
running processes (e.g., SSH agents, web browsers, password managers). This path is the
Linux equivalent of Windows LSASS memory dumping. `/proc/self/mem` reads (self-inspection)
are filtered out to eliminate JVM, Go runtime, and sanitiser false positives.

**Rule 2 — `/etc/shadow` access (T1003 general):**
Subscribes to `open`/`openat` events on `/etc/shadow` and `/etc/gshadow` from processes
whose `exe` is not in a hardcoded whitelist of legitimate authentication binaries.
`/etc/shadow` contains salted password hashes for all local users; reading it enables
offline dictionary or brute-force attacks.

Both rules emit CRITICAL severity alerts immediately upon detection.

---

## Technical Context

### /proc/PID/mem Mechanism

The Linux virtual filesystem exports process memory through `/proc/[pid]/mem`. The kernel
enforces access control: a process can only read another's `/mem` file if it either has
the same effective UID (and ptrace permissions) or is running as root (`CAP_SYS_PTRACE`).

**Adversarial workflow:**
1. List `/proc/` to find target PIDs
2. Read `/proc/[pid]/maps` to identify virtual memory regions (heap, stack, mmap'd files)
3. Open `/proc/[pid]/mem` with `O_RDONLY`
4. Seek to offset within a readable region and read
5. Grep the extracted buffer for credential patterns

This leaves a minimal filesystem footprint compared to tool-based approaches (no
Mimikatz-style binary, no `ptrace()` calls), making it highly evasive. The `auditd`
kernel hook catches the `open()` syscall regardless of how the read is performed.

**PRISM Lab result (2026-07-01):** `proc_mem_scan.py` successfully located the dummy
target (`dummy_cred_holder.sh`, PID 223290), parsed its `/proc/223290/maps`, and extracted
`password=DUMMY_LAB_SECRET_PRISM_2024` from the `[heap]` region at address `0x55f71ed91000`.

### /etc/shadow Mechanism

Shadow passwords were introduced to move hashed passwords out of world-readable
`/etc/passwd` into root-only `/etc/shadow` (mode 640, owner root:shadow). Adversaries
with root or shadow group membership read the file directly. The hashes can then be
cracked offline using `hashcat` or `john`.

**PRISM Lab result (2026-07-01):** `shadow_access.sh` successfully confirmed read access
to `/etc/shadow`, triggering the `prism_t1003_shadow` audit key.

### Why Standard Defenses Miss This

- **File integrity monitoring:** Monitors *writes* to shadow, not *reads*. A read of
  `/etc/shadow` produces no hash change and triggers no FIM alert.
- **AV/EDR signature scanning:** No malicious binary is necessarily on disk. The attack
  is performed with a Python script or even a bash read loop — both are signed, trusted binaries.
- **Process name monitoring:** The attacker may combine this with T1036 (masquerading)
  to further confuse monitoring.
- **SELinux/AppArmor:** May restrict `/proc/<pid>/mem` access in some policies but is
  often disabled or configured permissively in practice.

### Audit Rule Syntax

```
# /proc filesystem access — catches open() of any path under /proc
-a always,exit -F arch=b64 -S open,openat -F dir=/proc -k prism_t1003_proc_open

# ptrace (alternative credential dump vector — higher FP risk)
-a always,exit -F arch=b64 -S ptrace -k prism_t1003_ptrace

# Shadow file access
-w /etc/shadow  -p rwa -k prism_t1003_shadow
-w /etc/gshadow -p rwa -k prism_t1003_gshadow
```

### Sample Raw Audit Event (T1003.007 — /proc/mem read)

```
type=SYSCALL msg=audit(1751303016.789:6001): arch=c000003e syscall=2 success=yes
exit=3 a0=7fff1234 a1=0 a2=1b6 items=1 ppid=223280 pid=223299
auid=0 uid=0 gid=0 euid=0 egid=0 tty=pts0 ses=1
comm="python3" exe="/usr/bin/python3" key="prism_t1003_proc_open"

type=PATH msg=audit(1751303016.789:6001): item=0 name="/proc/223290/mem"
inode=131072 dev=00:05 mode=0100400 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL
```

Key fields: `name=/proc/223290/mem` (definitive indicator), `uid=0` (root reader),
`exe=/usr/bin/python3` (no dedicated dump binary — evasive).

### Sample Raw Audit Event (T1003 — shadow access)

```
type=SYSCALL msg=audit(1751303014.111:5900): arch=c000003e syscall=2 success=yes
exit=5 a0=7ffe9abc a1=0 items=1 ppid=223280 pid=223295
auid=0 uid=0 gid=0 comm="bash" exe="/usr/bin/bash" key="prism_t1003_shadow"

type=PATH msg=audit(1751303014.111:5900): item=0 name="/etc/shadow"
```

Key fields: `name=/etc/shadow`, `exe=/usr/bin/bash` (bash reading shadow = highly suspicious).

---

## Blind Spots and Assumptions

1. **Kernel-level reading without open():** An adversary with a kernel module or eBPF
   program can read process memory directly via kernel APIs without using `open()` on
   `/proc/<pid>/mem`. This rule will not detect such techniques.

2. **ptrace-based reading:** Debuggers (`gdb`, `strace`) and tools like `gcore` use `ptrace()`
   rather than `/proc/mem`. While a complementary `ptrace` rule exists in `prism.rules`, it
   has higher false positive risk and is not yet correlated in the engine.

3. **Reading from within the same process:** A process reading its own `/proc/self/mem`
   is legitimate for self-inspection and JIT compilation. The current implementation
   filters `/proc/self/` paths to suppress this.

4. **Container escape scenario:** In a container environment, an attacker escaping to
   the host namespace could read `/proc/<host-pid>/mem`. Container-aware PID namespace
   filtering would be needed.

5. **High-privilege PAM modules:** Some PAM modules legitimately open `/etc/shadow` with
   expected `exe` paths. The whitelist in the correlator covers common cases; novel PAM
   modules may require additional suppression.

---

## False Positives

| Source | Rule Triggered | Suppression Logic |
|--------|----------------|-------------------|
| `sudo passwd` / `su` | T1003 shadow access | Whitelist: `exe` in `{/usr/bin/sudo, /usr/bin/su, /usr/bin/passwd}` |
| `unix_chkpwd` (PAM) | T1003 shadow access | Whitelist: `exe = /sbin/unix_chkpwd` |
| `gdb` debugging own process | T1003.007 proc/mem | Filter: `/proc/self/mem` paths excluded |
| JVM self-inspection | T1003.007 proc/mem | Filter: `/proc/self/mem` paths excluded |
| `systemd` reading `/proc/pressure/memory` | T1003.007 proc/mem | Filter: correlator excludes `/proc/pressure/*` |
| Monitoring tools (`ps`, `top`, `htop`) | T1003.007 proc/mem | Whitelist: standard diagnostic binaries |

---

## Validation

To generate a true positive:

**T1003.007 Validation:**
```bash
# Step 1: Start the dummy credential holder target
sudo /usr/local/bin/dummy_cred_holder.sh &
TARGET_PID=$!
sleep 2

# Step 2: Run the memory scanner (requires root)
sudo python3 red/t1003_cred_dump/proc_mem_scan.py
# Expected: proc_mem_scan.py finds dummy_cred_holder at PID=$TARGET_PID
#           Extracts: password=DUMMY_LAB_SECRET_PRISM_2024 from [heap]
#           Alert T1003.007-CredentialDump fires after blue/engine.sh runs

# Cleanup
sudo kill $TARGET_PID
```

**T1003 Shadow Validation:**
```bash
sudo bash red/t1003_cred_dump/shadow_access.sh
# Expected: Alert T1003-ShadowAccess fires after blue/engine.sh runs
```

**Automated validation:**
```bash
sudo bash tests/validate_t1003.sh
# Expected exit code: 0 (PASS)
```

---

## Priority

| Condition | Severity |
|-----------|----------|
| `/proc/[pid]/mem` opened by root from non-standard exe | CRITICAL |
| `/proc/[pid]/mem` opened by user from temp path | CRITICAL |
| `/etc/shadow` read by non-whitelisted exe as root | CRITICAL |
| `/etc/shadow` read by non-whitelisted exe as user | HIGH |
| `ptrace()` called on process with different UID | HIGH |

---

## Response

Upon alert:

1. **Triage (< 5 min):** Identify which process opened `/proc/<target-pid>/mem` or
   `/etc/shadow`. Identify the target PID — what process was being read?
2. **Confirm (< 10 min):** Was the reading process expected to perform memory inspection?
   (Is it a debugger? Is it a known security tool?) If not → confirmed credential theft.
3. **Assess impact:** What process was the target? Was it an SSH agent, a web server,
   a browser, a password manager? Assess the blast radius.
4. **Preserve:** Capture `/proc/<reading-pid>/cmdline`, `/proc/<reading-pid>/exe`,
   `/proc/<reading-pid>/maps`. If still running, take a memory snapshot: `gcore <reading-pid>`.
5. **Escalate:** Shadow file access: assume all local password hashes are compromised
   and initiate forced password rotation for all local accounts.
6. **Hunt:** Search for lateral movement — were stolen credentials used to pivot to
   another host? Review SSH auth logs and `/var/log/auth.log`.

---

## Additional Resources

- MITRE ATT&CK T1003.007: https://attack.mitre.org/techniques/T1003/007/
- Linux `/proc` man page: https://man7.org/linux/man-pages/man5/proc.5.html
- `proc_mem_scan.py` implementation: `red/t1003_cred_dump/proc_mem_scan.py`
- Palantir ADS Framework: https://github.com/palantir/alerting-detection-strategy-framework
- Project PRISM correlator rules: `blue/parser/correlator.py` → `detect_t1003_credential_dumping`
