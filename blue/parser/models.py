"""
PRISM Blue Team — Data Models
Structured data classes for audit events, normalized transactions, and alerts.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AuditEvent:
    """
    A single parsed line from /var/log/audit/audit.log.
    One audit transaction (audit_id) typically spans multiple AuditEvent rows
    (e.g., a SYSCALL record followed by one or more PATH records).
    """
    timestamp: str
    audit_id: str
    event_type: str          # e.g., SYSCALL, PATH, EXECVE, PROCTITLE
    data: dict               # raw key=value fields extracted from the line
    raw: str                 # original log line, preserved for forensics


@dataclass
class Transaction:
    """
    A normalized, flattened view of all AuditEvents sharing the same audit_id.
    The log_parser collapses multi-line audit records into a single Transaction
    so the correlator can reason about a complete syscall event at once.
    """
    timestamp: str
    audit_id: str
    event_types: List[str] = field(default_factory=list)
    keys: List[str] = field(default_factory=list)   # auditd -k tags, e.g. prism_t1036_exec_tmp
    exe: Optional[str] = None                        # /proc/PID/exe — true binary path (kernel-set)
    comm: Optional[str] = None                       # /proc/PID/comm — thread name (user-spoofable)
    syscall: Optional[str] = None                    # syscall number as string
    name: Optional[str] = None                       # primary PATH record name field
    paths: List[str] = field(default_factory=list)   # all PATH record name values in this tx

    @classmethod
    def from_dict(cls, d: dict) -> "Transaction":
        """Deserialise a Transaction from the JSON format written by log_parser."""
        return cls(
            timestamp=d.get("timestamp", ""),
            audit_id=d.get("audit_id", ""),
            event_types=d.get("event_types", []),
            keys=d.get("keys", []),
            exe=d.get("exe"),
            comm=d.get("comm"),
            syscall=d.get("syscall"),
            name=d.get("name"),
            paths=d.get("paths", []),
        )

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "audit_id": self.audit_id,
            "event_types": self.event_types,
            "keys": self.keys,
            "exe": self.exe,
            "comm": self.comm,
            "syscall": self.syscall,
            "name": self.name,
            "paths": self.paths,
        }


@dataclass
class Alert:
    """
    A detection result emitted by the correlator for a single Transaction.
    Maps 1:1 to a Palantir ADS rule.
    """
    rule: str             # Rule ID, e.g. T1036.005-Masquerade or T1003.007-CredentialDump
    severity: str         # HIGH | CRITICAL
    description: str      # Human-readable summary including key evidence fields
    audit_id: str         # Links back to the source Transaction for forensic tracing

    SEVERITY_RANK = {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 0}

    @property
    def severity_rank(self) -> int:
        return self.SEVERITY_RANK.get(self.severity, -1)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "description": self.description,
            "audit_id": self.audit_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Alert":
        return cls(
            rule=d["rule"],
            severity=d["severity"],
            description=d["description"],
            audit_id=d["audit_id"],
        )
