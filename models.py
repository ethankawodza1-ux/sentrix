"""
SENTRIX — Core data models.
All inter-module communication uses these dataclasses.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, TYPE_CHECKING
from datetime import datetime

if TYPE_CHECKING:
    from .threat_intel import ThreatIntelReport
    from .mitre import ATTACKMapping


# ──────────────────────────────────────────────
#  Enumerations
# ──────────────────────────────────────────────

class ThreatLevel(Enum):
    """Normalised severity scale (1 = lowest, 5 = highest)."""
    INFORMATIONAL = 1
    LOW           = 2
    MEDIUM        = 3
    HIGH          = 4
    CRITICAL      = 5

    def label(self) -> str:
        colours = {
            "INFORMATIONAL": "\033[34m",   # blue
            "LOW":           "\033[32m",   # green
            "MEDIUM":        "\033[33m",   # yellow
            "HIGH":          "\033[91m",   # bright red
            "CRITICAL":      "\033[41m",   # red background
        }
        reset = "\033[0m"
        return f"{colours[self.name]}[{self.name}]{reset}"


class AttackType(Enum):
    RANSOMWARE          = "Ransomware"
    APT                 = "Advanced Persistent Threat"
    DDOS                = "Distributed Denial of Service"
    LATERAL_MOVEMENT    = "Lateral Movement"
    DATA_EXFILTRATION   = "Data Exfiltration"
    PRIVILEGE_ESCALATION= "Privilege Escalation"
    MALWARE             = "Malware Infection"
    PHISHING            = "Phishing / Credential Theft"
    ZERO_DAY            = "Zero-Day Exploit"
    INSIDER_THREAT      = "Insider Threat"


class AssetCriticality(Enum):
    """How important is the affected asset to operations?"""
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4


class ResponseDecision(Enum):
    CONTAIN_IMMEDIATELY    = "CONTAIN_IMMEDIATELY"
    PRESERVE_EVIDENCE_FIRST = "PRESERVE_EVIDENCE_FIRST"
    MONITOR_AND_ALERT       = "MONITOR_AND_ALERT"
    ESCALATE_TO_HUMAN       = "ESCALATE_TO_HUMAN"


# ──────────────────────────────────────────────
#  Detection & Assessment payloads
# ──────────────────────────────────────────────

@dataclass
class NetworkIndicator:
    """A single network-level indicator of compromise."""
    source_ip:   str
    dest_ip:     str
    port:        int
    protocol:    str
    bytes_sent:  int
    packets:     int
    anomaly_score: float   # 0.0–1.0

    def summary(self) -> str:
        return (f"{self.source_ip}:{self.port} → {self.dest_ip} "
                f"({self.protocol}) anomaly={self.anomaly_score:.2f}")


@dataclass
class ProcessIndicator:
    """Suspicious process / host activity."""
    pid:          int
    name:         str
    parent_name:  str
    command_line: str
    user:         str
    cpu_pct:      float
    mem_mb:       float
    anomaly_score: float   # 0.0–1.0


@dataclass
class FileIndicator:
    """Suspicious file-system activity."""
    path:           str
    action:         str    # created / modified / deleted / encrypted
    entropy:        float  # high entropy → encryption / packing
    is_executable:  bool
    anomaly_score:  float


@dataclass
class DetectionEvent:
    """Raw output from the Detector — everything observed about the attack."""
    event_id:            str
    timestamp:           datetime
    asset_id:            str
    asset_name:          str
    asset_criticality:   AssetCriticality
    attack_type:         AttackType
    network_indicators:  List[NetworkIndicator] = field(default_factory=list)
    process_indicators:  List[ProcessIndicator] = field(default_factory=list)
    file_indicators:     List[FileIndicator]    = field(default_factory=list)
    raw_log_snippet:     str = ""


@dataclass
class EvidenceItem:
    """A single piece of digital evidence captured before containment."""
    evidence_id:     str
    category:        str   # memory / network / process / file / log
    description:     str
    volatility_rank: int   # 1 (most volatile) … 5 (least volatile)
    captured:        bool  = False
    capture_method:  str   = ""
    size_bytes:      int   = 0
    timestamp:       Optional[datetime] = None


@dataclass
class ThreatAssessment:
    """Output of the Assessor — a scored, multi-dimensional risk picture."""
    event:                  DetectionEvent
    threat_level:           ThreatLevel
    threat_score:           float          # 0–100 composite
    severity_score:         float          # 0–100  (how dangerous)
    evidence_volatility:    float          # 0–100  (how quickly evidence evaporates)
    attacker_activity:      float          # 0–100  (how active / spreading)
    asset_criticality_score: float         # 0–100
    ioc_count:              int
    lateral_movement_risk:  bool
    data_loss_risk:         bool
    persistence_detected:   bool
    confidence:             float          # 0–1   model confidence
    evidence_items:         List[EvidenceItem] = field(default_factory=list)
    reasoning:              List[str]          = field(default_factory=list)
    # enrichment (set by orchestrator after assess())
    intel_report:           Optional["ThreatIntelReport"] = None
    mitre_mapping:          Optional["ATTACKMapping"]     = None


@dataclass
class ResponsePlan:
    """Final decision + actionable playbook produced by the Decision Engine."""
    assessment:          ThreatAssessment
    decision:            ResponseDecision
    priority_score:      float            # higher = more urgent
    decision_rationale:  List[str]        = field(default_factory=list)
    immediate_actions:   List[str]        = field(default_factory=list)
    evidence_actions:    List[str]        = field(default_factory=list)
    containment_actions: List[str]        = field(default_factory=list)
    forensic_actions:    List[str]        = field(default_factory=list)
    notification_targets: List[str]       = field(default_factory=list)
    estimated_response_time_seconds: int  = 0
