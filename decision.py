"""
SENTRIX — Decision Engine
============================
Given a ThreatAssessment, determines the optimal response strategy
using a weighted scoring algorithm that balances four competing concerns:

  1. Threat severity    — how much immediate damage can the attack do?
  2. Evidence volatility — how fast will forensic evidence disappear?
  3. Attacker activity  — is the attacker actively spreading right now?
  4. Asset criticality  — what is the operational impact of the target?

Decision matrix (simplified)
─────────────────────────────
  CONTAIN_IMMEDIATELY       → attack so severe / fast that delay = unacceptable damage
  PRESERVE_EVIDENCE_FIRST   → evidence is highly volatile but threat can tolerate
                              a short evidence-capture window before containment
  MONITOR_AND_ALERT         → lower-severity; gather more data before acting
  ESCALATE_TO_HUMAN         → confidence too low or context too ambiguous for automation

The engine also generates a complete, prioritised response playbook.
"""
from __future__ import annotations
from typing import List

from .models import (
    AssetCriticality, AttackType, ResponseDecision,
    ResponsePlan, ThreatAssessment, ThreatLevel,
)


# ──────────────────────────────────────────────────────────────────────────────
#  Decision logic
# ──────────────────────────────────────────────────────────────────────────────

class DecisionEngine:
    """
    Analyses a ThreatAssessment and returns a ResponsePlan.
    """

    def decide(self, assessment: ThreatAssessment) -> ResponsePlan:
        decision, rationale = self._evaluate_decision(assessment)
        plan = self._build_plan(assessment, decision, rationale)
        return plan

    # ── Core decision logic ───────────────────────────────────────────────────

    def _evaluate_decision(
        self, a: ThreatAssessment
    ) -> tuple[ResponseDecision, List[str]]:

        rationale: List[str] = []

        # ── Hard escalation triggers ─────────────────────────────────────────
        if a.confidence < 0.60:
            rationale.append(
                f"Detection confidence is low ({a.confidence:.0%}) — "
                f"insufficient certainty for automated action."
            )
            return ResponseDecision.ESCALATE_TO_HUMAN, rationale

        # ── Immediate containment triggers ───────────────────────────────────
        # Any one of these alone is enough to contain first:

        if a.threat_level == ThreatLevel.CRITICAL and a.attacker_activity >= 85:
            rationale.append(
                f"CRITICAL threat + attacker activity {a.attacker_activity:.0f}/100 — "
                f"active spread in progress; every second increases blast radius."
            )
            return ResponseDecision.CONTAIN_IMMEDIATELY, rationale

        if a.lateral_movement_risk and a.attacker_activity >= 80:
            rationale.append(
                f"Confirmed lateral movement with activity={a.attacker_activity:.0f}/100 — "
                f"attacker is actively pivoting; containment stops the spread."
            )
            return ResponseDecision.CONTAIN_IMMEDIATELY, rationale

        if a.event.attack_type == AttackType.RANSOMWARE and a.severity_score >= 88:
            rationale.append(
                f"Ransomware with severity={a.severity_score:.0f} — "
                f"encryption is actively destroying data; must isolate NOW."
            )
            return ResponseDecision.CONTAIN_IMMEDIATELY, rationale

        if (a.event.asset_criticality == AssetCriticality.CRITICAL
                and a.threat_level in {ThreatLevel.CRITICAL, ThreatLevel.HIGH}
                and a.attacker_activity >= 75):
            rationale.append(
                f"CRITICAL asset under HIGH/CRITICAL threat with activity {a.attacker_activity:.0f}/100 — "
                f"operational impact too severe to delay containment."
            )
            return ResponseDecision.CONTAIN_IMMEDIATELY, rationale

        # ── Preserve evidence first triggers ─────────────────────────────────
        # Evidence is very volatile but the threat is not yet catastrophically fast:

        if a.evidence_volatility >= 80 and a.threat_score >= 65:
            rationale.append(
                f"Evidence volatility={a.evidence_volatility:.0f}/100 — forensic material "
                f"(RAM, active sessions) will evaporate within minutes."
            )
            rationale.append(
                f"Threat score {a.threat_score:.1f} is significant but attacker is not "
                f"spreading at catastrophic speed ({a.attacker_activity:.0f}/100)."
            )
            rationale.append(
                "Decision: capture volatile evidence first, then contain."
            )
            return ResponseDecision.PRESERVE_EVIDENCE_FIRST, rationale

        if (a.event.attack_type in {AttackType.APT, AttackType.ZERO_DAY, AttackType.INSIDER_THREAT}
                and a.evidence_volatility >= 70):
            rationale.append(
                f"{a.event.attack_type.value} attacks require forensic proof for "
                f"attribution and legal proceedings."
            )
            rationale.append(
                f"Evidence volatility={a.evidence_volatility:.0f}/100; "
                f"activity={a.attacker_activity:.0f}/100 — short evidence window safe."
            )
            return ResponseDecision.PRESERVE_EVIDENCE_FIRST, rationale

        # ── Monitor-and-alert (lower-confidence or low-impact) ───────────────
        if a.threat_level in {ThreatLevel.LOW, ThreatLevel.INFORMATIONAL}:
            rationale.append(
                f"Threat level {a.threat_level.name} — risk does not yet justify "
                f"disruptive containment; increase monitoring fidelity."
            )
            return ResponseDecision.MONITOR_AND_ALERT, rationale

        if a.threat_score < 50:
            rationale.append(
                f"Composite threat score {a.threat_score:.1f} < 50 — "
                f"alert SOC and continue monitoring for escalation."
            )
            return ResponseDecision.MONITOR_AND_ALERT, rationale

        # ── Default: escalate when pattern is ambiguous ───────────────────────
        rationale.append(
            "No single automated rule matched the threat profile precisely. "
            "Escalating to human analyst for final judgement."
        )
        return ResponseDecision.ESCALATE_TO_HUMAN, rationale

    # ── Playbook builder ──────────────────────────────────────────────────────

    def _build_plan(
        self,
        a: ThreatAssessment,
        decision: ResponseDecision,
        rationale: List[str],
    ) -> ResponsePlan:
        """Assemble a full, actionable playbook for the chosen decision."""

        ev   = a.event
        at   = ev.attack_type
        crit = ev.asset_criticality

        # ── Immediate actions (always done first) ─────────────────────────────
        immediate: List[str] = [
            f"[ALERT]   Notify SOC L1/L2 — {at.value} detected on {ev.asset_name}",
            f"[TICKET]  Open P{5 - a.threat_level.value + 1} incident ticket "
            f"(Severity: {a.threat_level.name})",
            f"[LOG]     Preserve SIEM event ID {ev.event_id} with hash for chain-of-custody",
        ]
        if crit == AssetCriticality.CRITICAL:
            immediate.append("[NOTIFY]  Page CISO and on-call IR lead immediately")

        # ── Evidence preservation actions ─────────────────────────────────────
        evidence_actions: List[str] = []
        for item in sorted(a.evidence_items, key=lambda x: x.volatility_rank):
            vol_label = "🔴" if item.volatility_rank <= 2 else ("🟡" if item.volatility_rank == 3 else "🟢")
            evidence_actions.append(
                f"{vol_label} [CAPTURE rank={item.volatility_rank}] "
                f"{item.description}  ← method: {item.capture_method}"
            )

        # ── Containment actions (vary by attack type) ──────────────────────────
        containment: List[str] = self._containment_playbook(ev, a)

        # ── Forensic / post-containment actions ───────────────────────────────
        forensic: List[str] = [
            "[FORENSIC] Hash all collected evidence files (SHA-256)",
            "[FORENSIC] Create forensic timeline from log artefacts",
            f"[FORENSIC] Run malware analysis on identified IOCs "
            f"({a.ioc_count} indicators)",
            "[FORENSIC] Check threat intel feeds for known attacker TTPs (MITRE ATT&CK)",
            "[FORENSIC] Identify patient-zero and initial infection vector",
        ]
        if a.lateral_movement_risk:
            forensic.append("[FORENSIC] Enumerate all hosts reached via lateral movement")
        if a.persistence_detected:
            forensic.append("[FORENSIC] Hunt for persistence mechanisms across the environment")

        # ── Notification targets ───────────────────────────────────────────────
        notifications: List[str] = ["SOC Analyst (L1/L2)", "Incident Response Team"]
        if crit == AssetCriticality.CRITICAL:
            notifications += ["CISO", "CTO", "Legal / Compliance"]
        if a.data_loss_risk:
            notifications.append("Data Protection Officer (DPO)")
        if at == AttackType.RANSOMWARE:
            notifications += ["CEO", "Cyber Insurance Provider"]
        if at == AttackType.INSIDER_THREAT:
            notifications += ["HR Director", "Legal Counsel"]

        # ── Estimated response time ────────────────────────────────────────────
        if decision == ResponseDecision.CONTAIN_IMMEDIATELY:
            response_seconds = 60
        elif decision == ResponseDecision.PRESERVE_EVIDENCE_FIRST:
            response_seconds = 300   # 5-min evidence window
        elif decision == ResponseDecision.MONITOR_AND_ALERT:
            response_seconds = 900   # 15-min watch
        else:
            response_seconds = 600   # human review

        # ── Priority score ─────────────────────────────────────────────────────
        priority = (
            a.threat_score * 0.5
          + a.attacker_activity * 0.3
          + a.asset_criticality_score * 0.2
        )

        return ResponsePlan(
            assessment               = a,
            decision                 = decision,
            priority_score           = round(priority, 1),
            decision_rationale       = rationale,
            immediate_actions        = immediate,
            evidence_actions         = evidence_actions,
            containment_actions      = containment,
            forensic_actions         = forensic,
            notification_targets     = notifications,
            estimated_response_time_seconds = response_seconds,
        )

    # ── Attack-specific containment playbooks ────────────────────────────────

    def _containment_playbook(
        self, ev, assessment: ThreatAssessment
    ) -> List[str]:
        at   = ev.attack_type
        host = ev.asset_name

        _common = [
            f"[ISOLATE]  Remove {host} from network (VLAN quarantine / firewall block)",
            f"[BLOCK]    Block all outbound traffic from {ev.asset_id} at perimeter",
            f"[CREDS]    Force password reset for all accounts active on {host}",
        ]

        _playbooks: dict[AttackType, List[str]] = {
            AttackType.RANSOMWARE: [
                *_common,
                "[STOP]    Kill encryption process tree (PID chain identified in IOCs)",
                "[VSS]     Attempt VSS shadow copy restoration if not yet deleted",
                "[SHARE]   Disable all SMB shares on host to prevent spread",
                "[DECRYPT] Engage decryption key recovery from memory dump if available",
                "[BACKUP]  Initiate restore from last known clean backup",
            ],
            AttackType.APT: [
                *_common,
                "[PURGE]   Terminate beacon process and remove implant files",
                "[PERSIST] Remove all identified persistence mechanisms",
                "[C2]      Sinkhole C2 domain(s) at DNS level",
                "[HUNT]    Trigger enterprise-wide IOC hunt for same beacon family",
            ],
            AttackType.LATERAL_MOVEMENT: [
                *_common,
                "[SMB]     Block SMB (445) between all non-DC hosts at L3",
                "[ACCT]    Disable compromised domain account(s) in AD",
                "[KERBEROS] Request Kerberos golden/silver ticket revocation",
                "[SCAN]    Run immediate vulnerability scan on all pivoted hosts",
            ],
            AttackType.DATA_EXFILTRATION: [
                *_common,
                "[EGRESS]  Block all outbound connections to identified external IPs",
                "[DNS]     Block DNS queries to attacker-controlled domain",
                "[DLP]     Lock down removable media and cloud storage on all endpoints",
                "[NOTIFY]  Assess regulatory notification obligations (GDPR / CCPA / HIPAA)",
            ],
            AttackType.PRIVILEGE_ESCALATION: [
                *_common,
                "[REVOKE]  Revoke elevated token for compromised process",
                "[PATCH]   Emergency patch for exploited CVE across all affected hosts",
                "[AUDIT]   Audit all sudo / admin rights granted in past 7 days",
            ],
            AttackType.DDOS: [
                "[SCRUB]   Route traffic through DDoS scrubbing centre",
                "[RATE]    Apply aggressive rate-limiting at edge routers",
                "[CDN]     Enable CDN-level protection / anycast routing",
                "[ISP]     Contact upstream ISP for BGP blackhole if volumetric",
                "[CREDS]   No credential reset required (availability attack)",
            ],
            AttackType.ZERO_DAY: [
                *_common,
                "[WAF]     Deploy virtual patch rule in WAF for exploit vector",
                "[SERVICE] Temporarily take vulnerable service offline",
                "[PATCH]   Expedite vendor notification and emergency patching",
                "[SHELL]   Remove webshell and backdoor files",
            ],
            AttackType.MALWARE: [
                *_common,
                "[AV]      Trigger full AV scan with updated signatures",
                "[PROCESS] Kill malware process tree",
                "[PERSIST] Remove registry run-key persistence",
                "[REIMAGE] Schedule host re-image from golden image",
            ],
            AttackType.INSIDER_THREAT: [
                "[HR]      Coordinate with HR — do NOT tip off suspect prematurely",
                "[ACCT]    Revoke VPN, remote access, and cloud credentials",
                "[DLP]     Preserve DLP logs with legal hold",
                "[USB]     Confiscate removable media if physical access possible",
                "[LEGAL]   Engage legal counsel before any further action",
            ],
            AttackType.PHISHING: [
                *_common,
                "[EMAIL]   Pull phishing email from all mailboxes (EWS / Graph API)",
                "[URL]     Block phishing URL at proxy / DNS filter",
                "[TOKEN]   Invalidate OAuth tokens for affected user(s)",
                "[TRAIN]   Schedule immediate security awareness reminder",
            ],
        }

        return _playbooks.get(at, _common)
