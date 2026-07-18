# PRISM Purple Team Matrix
## Red → Telemetry → Detection Mapping

> This matrix maps every offensive action to the raw kernel telemetry it produces and
> the exact detection rule that fires. Gap rows document where detection fails and why.
> Run evidence collected 2026-07-01 in isolated Ubuntu 22.04 LTS VM.

---

| ID | Technique | Offensive Action | Kernel Event | Audit Key | Raw Fields | Detection Rule | Alert Title | Detected? | Latency | Gap / Notes |
|----|-----------|-----------------|-------------|-----------|------------|---------------|-------------|----------|---------|-------------|
| 1 | T1036.003 | `cp /bin/sleep /tmp/systemd-helper && /tmp/systemd-helper 5` (`rename_exec.sh`) | SYSCALL `execve` (59) | `prism_t1036_exec_tmp` | `exe=/tmp/systemd-helper`, `comm=systemd-helper` | `detect_t1036_masquerading` → `T1036.005-Masquerade` | Process in temp directory claimed legitimate system name | ✅ YES | < 8 s | Detected. `exe` path in `/tmp` with `systemd` in `comm` satisfied both conditions. |
| 2 | T1036.005 | `prctl(PR_SET_NAME, "kworker/u4:2")` (`prctl_spoof.c`) | SYSCALL `prctl` (158), `a0=0xf` | `prism_t1036_prctl` | `syscall=158`, `exe=/tmp/prism_prctl_spoof`, `comm=kworker/u4:2` | `detect_t1036_masquerading` → `T1036.005-Masquerade-Prctl` | Process explicitly renamed to system thread via prctl | ✅ YES | < 8 s | Detected. `comm=kworker/u4:2` vs `exe=/tmp/prism_prctl_spoof` mismatch fired the rule. |
| 3 | T1003.007 | `open("/proc/223290/mem", O_RDONLY)` + read (`proc_mem_scan.py`) | SYSCALL `open` (2) + PATH | `prism_t1003_proc_open` | `name=/proc/223290/mem`, `exe=/usr/bin/python3` | `detect_t1003_credential_dumping` → `T1003.007-CredentialDump` | Unauthorized /proc memory access | ✅ YES | < 8 s | Detected. Dummy credential `password=DUMMY_LAB_SECRET_PRISM_2024` extracted from `[heap]` at `0x55f71ed91000`. |
| 4 | T1003 | `open("/etc/shadow", O_RDONLY)` (`shadow_access.sh`) | SYSCALL `open` (2) + PATH | `prism_t1003_shadow` | `name=/etc/shadow`, `exe=/usr/bin/bash` | `detect_t1003_credential_dumping` → `T1003-ShadowAccess` | Unauthorized shadow file access | ✅ YES | < 8 s | Detected. Non-whitelisted `bash` read on `/etc/shadow` confirmed readable, audit event generated. |
| 5 | T1036.003 | Binary rename + exec from `/dev/shm` | SYSCALL `execve` (59) | `prism_t1036_exec_shmem` | `exe=/dev/shm/*` | `detect_t1036_masquerading` → `T1036.003-TempExec` | Binary executed from writable temp path | ✅ YES (rule) | — | Rule covers `/dev/shm` via `prism_t1036_exec_shmem` key. Not explicitly run in lab; covered by same correlator branch. |
| 6 | GAP | `prctl(PR_SET_NAME)` called before auditd rules load (early persistence) | None | — | — | None | — | ⚠️ BLIND SPOT | — | Mitigation: use auditd immutable mode (`-e 2`) and `augenrules` in early-boot systemd unit to close the init window. |
| 7 | GAP | `memfd_create + fexecve` (fileless execution — no `execve` on a real path) | SYSCALL `memfd_create` (319) | Not monitored | — | None | — | ⚠️ BLIND SPOT | — | Future: add `-S memfd_create -k prism_t1036_memfd`. Correlate with subsequent `fexecve` to confirm payload execution. |
| 8 | GAP | `ptrace`-based memory access (`gdb`, `gcore`) | SYSCALL `ptrace` (101) | `prism_t1003_ptrace` | — | Not yet correlated | — | ⚠️ PARTIAL | — | Audit key exists in `prism.rules` but correlator does not yet emit alerts for it. High FP risk from legitimate debuggers; future: correlate ptrace PEEK_DATA by non-debug exe. |

---

## Run Evidence Summary

| Metric | Value |
|--------|-------|
| Total offensive actions emulated | 4 (+ 3 gap scenarios) |
| Fully detected | 4 (rows 1–4) |
| Partially detected (rule exists, no correlator logic) | 1 (row 8 — ptrace) |
| Confirmed blind spots | 2 (rows 6–7) |
| Total alerts fired (raw engine output) | 112 |
| True positive alerts (T1036 + T1003 simulation-matched) | 4 |
| False positives observed | 108 (T1003.007 on `/proc/self/maps` — fixed in updated correlator by filtering `/proc/self/*`) |
| Simulation run date | 2026-07-01 |
| Run latency (red script → audit log capture) | < 8 s |
