# PRISM Project Proposal
## Purple-Red Intelligence & Surveillance Monitor

**Status:** APPROVED (Week 3 Deliverable)

### 1. Executive Summary
Project PRISM focuses on establishing a closed-loop Purple Team emulation environment. We are engineering surgical Red Team scripts to emulate MITRE ATT&CK techniques T1036 (Process Masquerading) and T1003 (OS Credential Dumping). Concurrently, we are building a custom Blue Team telemetry and alerting engine based on `auditd` and custom Python correlation logic to detect these exact behaviors with zero false positives.

### 2. Offensive Emulation Details (Red Team)
- **T1036 (Process Masquerading):**
  - **T1036.003:** We copy benign binaries to `tmp` paths and execute them under false names, forcing an incongruity between the `exe` and `argv[0]` fields.
  - **T1036.005:** We use a custom C binary that leverages `prctl(PR_SET_NAME)` to dynamically overwrite its kernel thread name to mimic `kworker`, obfuscating its true binary path.
- **T1003 (Credential Dumping):**
  - **T1003.007:** We use a Python-based memory scanner to parse `/proc/[pid]/maps` and surgically extract simulated credentials directly from the virtual memory space `/proc/[pid]/mem` of a dummy process, bypassing standard file-based credential stores.
  - **Shadow Access:** We simulate reading `/etc/shadow` to trigger standard credential access alarms.

### 3. Defensive Engineering Plan (Blue Team)
- **Kernel Auditing:** We will deploy strict `auditd` rules (`prism.rules`) hooking into `execve`, `prctl`, `open`, `openat`, and `ptrace` system calls.
- **Log Pipeline:** A custom Python daemon (`log_parser.py`) will continuously monitor `/var/log/audit/audit.log`, parsing raw audit streams into JSON.
- **Correlation Logic:**
  - For T1036, the engine (`correlator.py`) will dynamically compare the `exe` and `comm` strings. If a binary executing from a non-standard path (e.g., `/tmp/`) claims a `comm` name associated with kernel threads (e.g., `kworker`), an alert is fired.
  - For T1003, the engine will monitor any non-whitelisted binary accessing `/proc/*/mem`, immediately flagging the access as a credential dumping attempt.

### 4. Definition of Done
The project is complete when the Red Team scripts run successfully, the Blue Team engine parses the resulting telemetry in real-time, and high-fidelity Palantir ADS documents are finalized proving the detection efficacy.