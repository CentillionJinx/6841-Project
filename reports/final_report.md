# PRISM Project — Final Report
## Purple-Red Intelligence & Surveillance Monitor
**Date:** 2026-06-30
**Status:** COMPLETED

### 1. Project Overview
Project PRISM successfully established an automated, self-contained Purple Team feedback loop. We engineered surgical offensive capabilities targeting T1036 (Process Masquerading) and T1003 (OS Credential Dumping) and developed a corresponding bespoke Blue Team detection engine using `auditd` kernel hooks and Python-based log correlation.

### 2. Offensive Engineering Accomplishments
The Red Team successfully developed low-level simulation binaries and scripts:
- **T1036:** Created `rename_exec.sh` (argv[0] spoofing) and `prctl_spoof.c` (prctl thread renaming) to simulate advanced masquerading tactics that bypass naive process listing checks.
- **T1003:** Created a surgical Python memory scraper (`proc_mem_scan.py`) that successfully located a target process and extracted simulated credentials from `/proc/[pid]/mem` without dropping malicious executables on disk.

### 3. Defensive Engineering Accomplishments
The Blue Team successfully established a high-fidelity telemetry pipeline:
- Deployed strict `auditd` rules (`prism.rules`) hooking into `execve`, `prctl`, and `/proc` directory access.
- Developed `log_parser.py` which transforms raw kernel audit trails into normalized JSON datasets.
- Developed `correlator.py` which successfully flags the execution of masqueraded binaries and unauthorized memory access.
- Designed `alerter.py` to output the results cleanly and traceably.

### 4. Limitations and Future Work
- **Root Requirement:** The deployment of kernel hooks (`auditd` configuration) strictly requires root (`sudo`) access. In a production environment, deployment of the sensor must be handled via orchestration (e.g., Ansible/Chef).
- **Static Whitelist:** The current iteration of the T1003 correlator relies on a hardcoded whitelist (e.g., `/bin/ps`, `/bin/top`). In a larger environment, this must be dynamically tied to an authorized software inventory or hash registry to prevent administrative false positives.

### 5. Conclusion
Project PRISM met all primary objectives, demonstrating a functional closed-loop EDR emulation suite. The repository now contains actionable Palantir ADS documentation and the necessary code logic to deploy these detections into an enterprise SOC environment.
