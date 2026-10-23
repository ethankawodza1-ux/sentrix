# SENTRIX — Cyber Threat Detection & Intelligent Response System

> **Detect → Assess → Enrich → Decide → Contain**
> An autonomous cybersecurity pipeline that intelligently weighs threat severity,
> evidence volatility, attacker activity, and asset criticality to determine whether
> to contain an attack immediately or preserve digital evidence first.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Key Features](#key-features)
4. [Modules](#modules)
5. [Scoring Engine](#scoring-engine)
6. [Decision Matrix](#decision-matrix)
7. [Threat Intelligence Feeds](#threat-intelligence-feeds)
8. [MITRE ATT\&CK Mapping](#mitre-attck-mapping)
9. [Installation](#installation)
10. [Usage](#usage)
11. [Sample Output](#sample-output)
12. [Extending SENTRIX](#extending-sentrix)
13. [Project Structure](#project-structure)

---

## Overview

SENTRIX is a Python-based cybersecurity response platform that simulates an
autonomous incident response pipeline. It processes a security event through
seven distinct stages — detection, evidence cataloguing, threat assessment,
threat intelligence enrichment, MITRE ATT&CK mapping, response decision, and
containment execution — and produces a complete, prioritised incident response
playbook.

The core innovation is the **intelligent decision engine**, which balances four
competing dimensions before choosing a response strategy:

| Dimension | Weight | What it captures |
|---|---|---|
| Threat Severity | 35% | How destructive is this attack? |
| Evidence Volatility | 25% | How quickly will forensic evidence evaporate? |
| Attacker Activity | 25% | Is the attacker actively spreading/encrypting right now? |
| Asset Criticality | 15% | How important is the targeted asset to operations? |

Scores from threat intelligence feeds (VirusTotal, AbuseIPDB, AlienVault OTX,
internal STIX/TAXII) and the MITRE ATT&CK technique library are applied as
additive boosts on top of the base composite score.

---

## Architecture

```
                        ┌─────────────────────────────────┐
                        │      SENTRIX Orchestrator        │
                        └─────────────┬───────────────────┘
                                      │
          ┌───────────────────────────▼──────────────────────────┐
          │                    Pipeline                          │
          │                                                      │
          │  1. ThreatDetector     ──► DetectionEvent            │
          │  2. EvidenceCollector  ──► [EvidenceItem, ...]       │
          │  3. ThreatAssessor     ──► ThreatAssessment          │
          │  4. ThreatIntelAggregator ──► ThreatIntelReport      │
          │     MITREMapper           ──► ATTACKMapping          │
          │     (score boosts applied to ThreatAssessment)       │
          │  5. DecisionEngine     ──► ResponsePlan              │
          │  6. ContainmentExecutor ──► [(action, ok, detail)]   │
          └──────────────────────────────────────────────────────┘
```

---

## Key Features

- **10 attack type scenarios** with realistic IOCs: Ransomware, APT, Lateral
  Movement, Data Exfiltration, Privilege Escalation, DDoS, Zero-Day, Malware,
  Insider Threat, Phishing.
- **4-dimensional weighted scoring** engine with dynamic indicator-driven
  adjustments (process entropy, SYSTEM privilege detection, high-packet flows).
- **RFC 3227 / NIST 800-86 evidence volatility ordering** — evidence is ranked
  and captured in the correct order: registers → memory → active connections →
  process images → disk.
- **4 threat intelligence feeds** (simulated): VirusTotal, AbuseIPDB,
  AlienVault OTX, Internal STIX/TAXII watchlist.
- **Full MITRE ATT&CK Enterprise v14 mapping** with technique IDs, tactics,
  mitigations, and detection data sources per attack type.
- **4 response decisions**: Contain Immediately, Preserve Evidence First,
  Monitor & Alert, Escalate to Human.
- **Attack-specific containment playbooks** with colour-coded CLI output.
- **Actionable forensic steps** including SHA-256 hashing, timeline creation,
  IOC hunting, and persistence sweep instructions.
- **Threat actor attribution** with nation-state and campaign context.

---

## Modules

| Module | File | Responsibility |
|---|---|---|
| Models | `sentrix/models.py` | All dataclasses and enumerations |
| Detector | `sentrix/detector.py` | Generates realistic IOC-rich DetectionEvents |
| Evidence | `sentrix/evidence.py` | Volatility-ranked evidence catalogues (RFC 3227) |
| Assessor | `sentrix/assessor.py` | 4-dimension scoring with indicator adjustments |
| Threat Intel | `sentrix/threat_intel.py` | Multi-feed IOC lookup and attribution |
| MITRE Mapper | `sentrix/mitre.py` | ATT&CK technique, tactic, and mitigation mapping |
| Decision | `sentrix/decision.py` | Response strategy selection + playbook generation |
| Containment | `sentrix/containment.py` | Ordered execution of response plan actions |
| Orchestrator | `sentrix/orchestrator.py` | Pipeline wiring and enrichment score application |
| CLI | `main.py` | Colour terminal output, reports, summary table |

---

## Scoring Engine

### Base scoring (per attack type)

```
threat_score = 0.35 × severity_score
             + 0.25 × evidence_volatility
             + 0.25 × attacker_activity
             + 0.15 × asset_criticality_score
```

### Dynamic adjustments

| Signal | Boost |
|---|---|
| High-entropy file (>7.5 bits) detected | +5 severity |
| Process running as SYSTEM/root | +4 severity |
| Executable dropped to %TEMP% / /tmp | +3 severity |
| Memory evidence identified | +8 volatility |
| High-anomaly active network connections | +5 volatility |
| Traffic to 3+ distinct destination IPs | +8 activity |
| Process CPU > 40% | +5 activity |
| High packet-count flow (>10K packets) | +6 activity |

### Enrichment boosts

| Source | Boost |
|---|---|
| High-confidence feed hit (≥80%) | +2.5 per hit (max +10) |
| Internal watchlist confirmation | +5.0 |
| MITRE high-impact tactic (Impact/Exfil/LateralMove/CredAccess) | +2.0 per tactic |

---

## Decision Matrix

| Condition | Decision |
|---|---|
| Confidence < 60% | `ESCALATE_TO_HUMAN` |
| CRITICAL threat + activity ≥ 85 | `CONTAIN_IMMEDIATELY` |
| Lateral movement confirmed + activity ≥ 80 | `CONTAIN_IMMEDIATELY` |
| Ransomware + severity ≥ 88 | `CONTAIN_IMMEDIATELY` |
| CRITICAL asset + HIGH/CRITICAL threat + activity ≥ 75 | `CONTAIN_IMMEDIATELY` |
| Volatility ≥ 80 + threat score ≥ 65 | `PRESERVE_EVIDENCE_FIRST` |
| APT/Zero-Day/Insider + volatility ≥ 70 | `PRESERVE_EVIDENCE_FIRST` |
| LOW or INFORMATIONAL threat level | `MONITOR_AND_ALERT` |
| Threat score < 50 | `MONITOR_AND_ALERT` |
| No single rule matched | `ESCALATE_TO_HUMAN` |

---

## Threat Intelligence Feeds

SENTRIX queries four simulated feeds per event:

| Feed | Type | Data |
|---|---|---|
| **VirusTotal** | Multi-AV / community | IP reputation, file hash analysis |
| **AbuseIPDB** | Community reporting | IP abuse confidence score (0–100) |
| **AlienVault OTX** | Open threat exchange | Pulse/campaign association |
| **Internal STIX/TAXII** | Enterprise private | Organisation watchlist hits |

Feed results apply a **severity boost** (up to +15 points) to the composite
score and provide threat actor attribution, campaign name, and nation-state
context.

---

## MITRE ATT&CK Mapping

Each attack type is mapped to the relevant Enterprise matrix v14 techniques:

| Attack Type | Techniques |
|---|---|
| Ransomware | T1566.001, T1059.001, T1490, T1486, T1489, T1041 |
| APT | T1195.002, T1055.001, T1053.005, T1071.001, T1027.002, T1078 |
| Lateral Movement | T1550.002, T1021.002, T1047, T1558.003, T1003.001 |
| Data Exfiltration | T1048.002, T1048.001, T1560.001, T1213, T1083 |
| Privilege Escalation | T1068, T1055, T1548.001, T1136.001 |
| DDoS | T1498.001, T1498.002, T1499.001 |
| Zero-Day | T1190, T1505.003, T1059.007, T1210 |
| Malware | T1547.001, T1036.004, T1071.001, T1082 |
| Insider Threat | T1052.001, T1213, T1078.002, T1074.001 |
| Phishing | T1566.002, T1539, T1056.003, T1176 |

Each technique includes mitigations (M-codes) and detection data sources
(DS-codes). A MITRE Navigator layer URL is generated per incident.

---

## Installation

```bash
# Clone or navigate to the sentrix directory
cd sentrix

# Python 3.9+ required — no external dependencies
python --version

# Run immediately
python main.py
```

SENTRIX has **zero external dependencies** — it uses only the Python standard
library. All threat intelligence data and ATT&CK mappings are embedded.

---

## Usage

```bash
# Random attack scenario
python main.py

# Specific attack type
python main.py ransomware
python main.py apt
python main.py lateral_movement
python main.py data_exfiltration
python main.py privilege_escalation
python main.py ddos
python main.py zero_day
python main.py malware
python main.py insider_threat
python main.py phishing

# Full summary table (all 10 scenarios)
python main.py all
```

### Programmatic API

```python
from sentrix.orchestrator import SentrixOrchestrator
from sentrix.models import AttackType

sentrix = SentrixOrchestrator(seed=42)

# Run a specific scenario
plan, execution_log = sentrix.respond(AttackType.RANSOMWARE)

# Access assessment data
a = plan.assessment
print(f"Threat Level  : {a.threat_level.name}")
print(f"Threat Score  : {a.threat_score:.1f}")
print(f"Decision      : {plan.decision.value}")
print(f"Threat Actor  : {a.intel_report.known_threat_actor}")
print(f"MITRE Tactics : {a.mitre_mapping.tactics}")
```

---

## Sample Output (summary table)

```
Attack Type                      Level        Score  Decision                      ETA
---------------------------------------------------------------------------------------
Ransomware                       CRITICAL     100.0  [!!] CONTAIN_IMMEDIATELY       60s
Advanced Persistent Threat       CRITICAL      92.5  [EV] PRESERVE_EVIDENCE_FIRST  300s
Distributed Denial of Service    MEDIUM        60.5  [??] ESCALATE_TO_HUMAN        600s
Lateral Movement                 HIGH          96.1  [!!] CONTAIN_IMMEDIATELY       60s
Data Exfiltration                HIGH         100.0  [!!] CONTAIN_IMMEDIATELY       60s
Privilege Escalation             HIGH          80.4  [!!] CONTAIN_IMMEDIATELY       60s
Malware Infection                MEDIUM        73.3  [EV] PRESERVE_EVIDENCE_FIRST  300s
Phishing / Credential Theft      LOW           64.0  [**] MONITOR_AND_ALERT        900s
Zero-Day Exploit                 CRITICAL      99.5  [!!] CONTAIN_IMMEDIATELY       60s
Insider Threat                   MEDIUM        63.5  [??] ESCALATE_TO_HUMAN        600s
```

---

## Extending SENTRIX

### Adding a real threat intelligence feed

```python
# sentrix/threat_intel.py — add a new feed class:
class MyCorporateFeed:
    name = "My Corporate TI"

    def lookup_ip(self, ip: str) -> Optional[IOCMatch]:
        response = requests.get(f"https://ti.corp.internal/api/ip/{ip}")
        if response.status_code == 200:
            data = response.json()
            return IOCMatch(
                ioc_type="ip", ioc_value=ip, provider=self.name,
                malicious_votes=data["malicious_count"],
                total_votes=data["total_reports"],
                confidence=data["confidence"],
                threat_names=data["threat_names"],
                tags=data["tags"],
            )
        return None

# Then add it to ThreatIntelAggregator.enrich()
```

### Connecting to a live EDR

```python
# Construct a DetectionEvent from your EDR event data:
from sentrix.models import DetectionEvent, AssetCriticality, AttackType
from sentrix.orchestrator import SentrixOrchestrator

event = DetectionEvent(
    event_id="EDR-12345",
    timestamp=datetime.now(),
    asset_id="WORKSTATION-007",
    asset_name="Finance Workstation 7",
    asset_criticality=AssetCriticality.HIGH,
    attack_type=AttackType.RANSOMWARE,
    network_indicators=[...],
    process_indicators=[...],
    file_indicators=[...],
)

sentrix = SentrixOrchestrator()
plan, log = sentrix.respond_to_event(event)
```

---

## Project Structure

```
sentrix/
├── main.py                   # CLI entry point & demo runner
├── README.md                 # This file
├── requirements.txt          # Dependencies (stdlib only)
└── sentrix/
    ├── __init__.py           # Package metadata
    ├── models.py             # All dataclasses and enumerations
    ├── detector.py           # Threat detection + IOC simulation
    ├── evidence.py           # RFC 3227 volatility-ranked evidence catalogues
    ├── assessor.py           # 4-dimension weighted scoring engine
    ├── threat_intel.py       # Multi-feed threat intelligence integration
    ├── mitre.py              # MITRE ATT&CK Enterprise v14 mapping
    ├── decision.py           # Response decision engine + playbook builder
    ├── containment.py        # Ordered containment execution
    └── orchestrator.py       # Full pipeline wiring
```

---

## License

MIT License — see LICENSE file for details.

---

*SENTRIX v1.0 — Built for intelligent, evidence-aware incident response.*
