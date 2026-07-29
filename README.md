# PRISM — Purple-Red Intelligence & Surveillance Monitor

**Author:** Gururam Subramanian (z5636559)
**Course:** COMP6841 — Security Engineering
**Platform:** Linux (Ubuntu 22.04 LTS — isolated VM)

> All scripts in `red/` are **educational simulations** for controlled sandbox use only. Never run against production systems or without prior written authorisation.

---

## What is PRISM?

PRISM is a self-contained **Purple Team feedback loop** implementing:

- **Red Team** — surgical, low-noise adversary emulation targeting two MITRE ATT&CK techniques:
  - **T1036** (Process Masquerading) — copying system binaries to `/tmp` under fake names, and spoofing process names via `prctl(PR_SET_NAME)`
  - **T1003** (OS Credential Dumping) — scanning process memory via `/proc/[pid]/mem` and accessing `/etc/shadow`

- **Blue Team** — a custom behavioral detection engine built on Linux `auditd` kernel hooks and a Python log→correlation→alert pipeline

- **Purple Matrix** — a mapping from every offensive action to the kernel telemetry it generates and the detection rule that catches it

The project follows the [Palantir Alerting & Detection Strategy (ADS) Framework](https://github.com/palantir/alerting-detection-strategy-framework) for all detection documentation.

---

## Repository Layout

```
project-prism/
├── red/                        # Offensive simulation suite
│   ├── t1036_masquerade/
│   │   ├── rename_exec.sh      # T1036.003 — binary copy+rename execution
│   │   ├── prctl_spoof.c       # T1036.005 — prctl PR_SET_NAME name spoof
│   │   └── run_t1036.sh        # T1036 master runner
│   ├── t1003_cred_dump/
│   │   ├── proc_mem_scan.py    # T1003.007 — /proc/[pid]/mem surgical scanner
│   │   ├── shadow_access.sh    # T1003 — /etc/shadow read simulation
│   │   └── run_t1003.sh        # T1003 master runner
│   └── red_runner.sh           # Top-level attack harness
├── blue/                       # Defensive monitoring engine
│   ├── auditd/
│   │   ├── prism.rules         # Custom auditd rules
│   │   └── install_hooks.sh    # Deploys rules into kernel
│   ├── parser/
│   │   ├── log_parser.py       # Parses audit.log → JSON
│   │   ├── correlator.py       # Behavioral detection logic
│   │   ├── alerter.py          # Alert output formatter
│   │   └── models.py           # Data classes (AuditEvent, Transaction, Alert)
│   ├── engine.sh               # Orchestrates the pipeline
│   └── requirements.txt
├── ads/                        # Palantir ADS documents
│   ├── ADS-T1036-ProcessMasquerading.md
│   └── ADS-T1003-CredentialDumping.md
├── matrix/
│   └── purple_matrix.md        # Red → Telemetry → Detection mapping
├── reports/
│   ├── proposal.md             # Week 3 deliverable
│   └── final_report.md         # Week 8 deliverable
├── tests/
│   ├── validate_t1036.sh
│   └── validate_t1003.sh
├── logs/                       # Runtime artefacts (git-ignored)
└── bootstrap_env.sh            # One-time VM setup
```

---

## Setup

### 1. VM Requirements

Ubuntu 22.04 LTS, root access, `auditd` ≥ 2.8, Python ≥ 3.10, `gcc`.

### 2. Bootstrap (run once, as root)

```bash
sudo bash bootstrap_env.sh
```

This installs `auditd`, `gcc`, `python3`, creates the `prism_test` user, and deploys the `dummy_cred_holder.sh` target process.

### 3. Install Kernel Hooks (requires root)

```bash
sudo bash blue/auditd/install_hooks.sh
```

Copies `prism.rules` into `/etc/audit/rules.d/` and reloads via `augenrules --load`.

### 4. Python Dependencies

```bash
cd blue && python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

---

## Running the Simulation

### Run all Red Team attacks

```bash
bash red/red_runner.sh
```

This triggers T1036 (masquerade) and T1003 (credential dump) in sequence. Raw audit delta logs are captured to `logs/raw/`.

### Run the Blue Team engine

```bash
bash blue/engine.sh
```

Steps: parse `audit.log` → correlate → emit alerts. Outputs:
- `logs/parsed/parsed_telemetry.json` — normalized events
- `logs/parsed/detections.json` — fired alerts

### Run individual attacks

```bash
bash red/t1036_masquerade/run_t1036.sh   # T1036 only
sudo bash red/t1003_cred_dump/run_t1003.sh   # T1003 only (needs root)
```

### Validate detections

```bash
bash tests/validate_t1036.sh
sudo bash tests/validate_t1003.sh
```

---

## Detection Logic Summary

| MITRE ID | Audit Key | Correlator Rule | Severity |
|---|---|---|---|
| T1036.003 | `prism_t1036_exec_tmp` / `_shmem` / `_vartmp` | `detect_t1036_masquerading` | HIGH |
| T1036.005 | `prism_t1036_prctl` | `detect_t1036_masquerading` | HIGH |
| T1003.007 | `prism_t1003_proc_open` | `detect_t1003_credential_dumping` | CRITICAL |
| T1003 base | `prism_t1003_shadow` / `_gshadow` | `detect_t1003_credential_dumping` | CRITICAL |

---

## Disclaimer

All offensive scripts are **educational simulations** targeting a controlled dummy process with planted fake credentials. No real credentials are extracted. Run only in the designated isolated VM. Not for use on any system without explicit written authorisation from the system owner.
