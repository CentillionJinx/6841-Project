# PRISM Project — Research Notes

## MITRE ATT&CK T1036: Process Masquerading
- **T1036.003 Rename System Utilities:** Execution path (`exe`) differs from the perceived execution name (`argv[0]`).
- **T1036.005 Match Legitimate Name or Location:** A process explicitly rewrites its own thread name using `prctl(PR_SET_NAME)`. This changes the `comm` field in the kernel.
- **Syscall Trigger:** `execve`, `prctl`.
- **Audit Event Mapping:** `EXECVE`, `PRCTL` events mapping mismatches between the execution path (e.g., `/tmp/xyz`) and thread name (e.g., `kworker`).

## MITRE ATT&CK T1003: OS Credential Dumping
- **T1003.007 /proc Filesystem:** Accessing `/proc/[pid]/mem` and `/proc/[pid]/maps` allows an adversary to directly scrape the virtual memory space of other processes.
- **Syscall Trigger:** `open`, `openat`, `ptrace` targeting `/proc/*/mem` or `/etc/shadow`.
- **Audit Event Mapping:** `SYSCALL` with `PATH` resolving to sensitive process memory files or the shadow file, triggered by an unauthorized (non-system) binary.