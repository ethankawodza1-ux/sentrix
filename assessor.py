"""
SENTRIX — Threat Assessment Engine
=====================================
Converts a raw DetectionEvent into a rich ThreatAssessment by scoring
four independent dimensions and combining them into a composite threat score.

Scoring dimensions (each 0 – 100)
──────────────────────────────────
  severity_score          How dangerous is the attack itself?
  evidence_volatility     How quickly will evidence evaporate?
  attacker_activity       How actively is the attacker moving / spreading?
  asset_criticality_score How important is the targeted asset?

Composite threat score
──────────────────────
  threat_score = 0.35 × severity
               + 0.25 × evidence_volatility
               + 0.25 × attacker_activity
               + 0.15 × asset_criticality
"""
from __future__ import annotations
from typing import List

from .models import (
    AttackType, AssetCriticality, DetectionEvent, EvidenceItem,
    ThreatAssessment, ThreatLevel,
)


# ──────────────────────────────────────────────────────────────────────────────
#  Static lookup tables (tuned by security research)
# ──────────────────────────────────────────────────────────────────────────────

# Base severity (0–100) by attack type
_BASE_SEVERITY: dict[AttackType, float] = {
    AttackType.RANSOMWARE:                                                     92.0,
    AttackType.APT:                                                            95.0,
    AttackType.ZERO_DAY:                                                       97.0,
    AttackType.DATA_EXFILTRATION:                                              85.0,
    AttackType.LATERAL_MOVEMENT:                                               78.0,
    AttackType.PRIVILEGE_ESCALATION:                                           72.0,
    AttackType.DDOS:                                                           65.0,
    AttackType.MALWARE:                                                        60.0,
    AttackType.INSIDER_THREAT:                                                 58.0,
    AttackType.PHISHING:                                                       50.0,
}

# How volatile is evidence for each attack type (0–100; higher = evaporates fast)
_BASE_EVIDENCE_VOLATILITY: dict[AttackType, float] = {
    AttackType.RANSOMWARE:           90.0,   # encryption keys vanish once process exits
    AttackType.APT:                  88.0,   # in-memory implants self-delete
    AttackType.ZERO_DAY:             92.0,   # heap memory cleared quickly
    AttackType.DATA_EXFILTRATION:    80.0,   # staged archives often deleted
    AttackType.LATERAL_MOVEMENT:     85.0,   # SMB sessions / LSASS memory
    AttackType.PRIVILEGE_ESCALATION: 88.0,   # exploit payload in heap
    AttackType.DDOS:                 40.0,   # logs persist; traffic easier to capture
    AttackType.MALWARE:              70.0,   # binary on disk but memory forensics fleeting
    AttackType.INSIDER_THREAT:       60.0,   # USB logs can be wiped
    AttackType.PHISHING:             65.0,   # session tokens in browser memory
}

# Base attacker activity (0–100; higher = more actively spreading)
_BASE_ATTACKER_ACTIVITY: dict[AttackType, float] = {
    AttackType.RANSOMWARE:           90.0,   # encrypting at full speed
    AttackType.APT:                  70.0,   # slow-and-low
    AttackType.ZERO_DAY:             85.0,   # initial access, rapid exploitation
    AttackType.DATA_EXFILTRATION:    75.0,   # active upload session
    AttackType.LATERAL_MOVEMENT:     88.0,   # hopping between hosts NOW
    AttackType.PRIVILEGE_ESCALATION: 80.0,   # actively elevating
    AttackType.DDOS:                 50.0,   # automated flood, no human interaction
    AttackType.MALWARE:              55.0,   # beaconing but not yet spreading
    AttackType.INSIDER_THREAT:       60.0,   # copying data right now
    AttackType.PHISHING:             45.0,   # initial stage, user-driven
}

# Asset criticality → numeric score
_CRITICALITY_SCORE: dict[AssetCriticality, float] = {
    AssetCriticality.LOW:      25.0,
    AssetCriticality.MEDIUM:   50.0,
    AssetCriticality.HIGH:     75.0,
    AssetCriticality.CRITICAL: 100.0,
}

# Composite score → ThreatLevel thresholds
_THREAT_LEVEL_THRESHOLDS = [
    (90, ThreatLevel.CRITICAL),
    (75, ThreatLevel.HIGH),
    (55, ThreatLevel.MEDIUM),
    (35, ThreatLevel.LOW),
    (0,  ThreatLevel.INFORMATIONAL),
]

# Dimension weights (must sum to 1.0)
_W_SEV  = 0.35
_W_EVOL = 0.25
_W_ACT  = 0.25
_W_CRIT = 0.15


def _score_to_threat_level(score: float) -> ThreatLevel:
    for threshold, level in _THREAT_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return ThreatLevel.INFORMATIONAL


def _clamp(val: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, val))


class ThreatAssessor:
    """
    Converts a DetectionEvent (+ collected evidence) into a ThreatAssessment.
    """

    def assess(
        self,
        event: DetectionEvent,
        evidence_items: List[EvidenceItem],
    ) -> ThreatAssessment:

        # ── 1. Base scores from lookup tables ────────────────────────────────
        severity    = _BASE_SEVERITY.get(event.attack_type, 50.0)
        volatility  = _BASE_EVIDENCE_VOLATILITY.get(event.attack_type, 50.0)
        activity    = _BASE_ATTACKER_ACTIVITY.get(event.attack_type, 50.0)
        crit_score  = _CRITICALITY_SCORE[event.asset_criticality]

        # ── 2. Dynamic adjustments from observed indicators ───────────────────
        severity, reasoning_sev  = self._adjust_severity(event, severity)
        volatility, reasoning_vol = self._adjust_volatility(event, evidence_items, volatility)
        activity, reasoning_act  = self._adjust_activity(event, activity)

        # ── 3. Composite threat score ─────────────────────────────────────────
        threat_score = _clamp(
            _W_SEV  * severity
          + _W_EVOL * volatility
          + _W_ACT  * activity
          + _W_CRIT * crit_score
        )

        # ── 4. Derived boolean flags ──────────────────────────────────────────
        lateral_risk   = (
            event.attack_type in {AttackType.LATERAL_MOVEMENT, AttackType.APT, AttackType.RANSOMWARE}
            or any(p.anomaly_score > 0.85 for p in event.process_indicators)
        )
        data_loss_risk = (
            event.attack_type in {AttackType.DATA_EXFILTRATION, AttackType.RANSOMWARE,
                                   AttackType.INSIDER_THREAT, AttackType.APT}
        )
        persistence    = (
            event.attack_type in {AttackType.APT, AttackType.MALWARE, AttackType.ZERO_DAY}
            or any(f.action in ("modified", "created") and "Run" in f.path
                   for f in event.file_indicators)
        )

        # ── 5. Confidence: mean of all anomaly scores ─────────────────────────
        all_scores = (
            [n.anomaly_score for n in event.network_indicators]
          + [p.anomaly_score for p in event.process_indicators]
          + [f.anomaly_score for f in event.file_indicators]
        )
        confidence = sum(all_scores) / len(all_scores) if all_scores else 0.5

        # ── 6. Collect all reasoning ──────────────────────────────────────────
        reasoning = reasoning_sev + reasoning_vol + reasoning_act
        reasoning.append(
            f"Asset '{event.asset_name}' carries criticality "
            f"{event.asset_criticality.name} (score={crit_score:.0f})."
        )
        reasoning.append(
            f"Composite threat score: {threat_score:.1f}  "
            f"[sev={severity:.1f} vol={volatility:.1f} "
            f"act={activity:.1f} crit={crit_score:.0f}]"
        )

        return ThreatAssessment(
            event                  = event,
            threat_level           = _score_to_threat_level(threat_score),
            threat_score           = threat_score,
            severity_score         = severity,
            evidence_volatility    = volatility,
            attacker_activity      = activity,
            asset_criticality_score= crit_score,
            ioc_count              = (len(event.network_indicators)
                                     + len(event.process_indicators)
                                     + len(event.file_indicators)),
            lateral_movement_risk  = lateral_risk,
            data_loss_risk         = data_loss_risk,
            persistence_detected   = persistence,
            confidence             = confidence,
            evidence_items         = evidence_items,
            reasoning              = reasoning,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _adjust_severity(
        self, event: DetectionEvent, base: float
    ) -> tuple[float, List[str]]:
        score  = base
        notes: List[str] = []

        # High-entropy files (packed/encrypted) increase severity
        hi_ent = [f for f in event.file_indicators if f.entropy > 7.5]
        if hi_ent:
            score += 5.0
            notes.append(
                f"High-entropy file(s) detected ({len(hi_ent)} item(s), "
                f"entropy > 7.5) — likely packed/encrypted payload. +5 severity."
            )

        # SYSTEM / root processes
        sys_procs = [p for p in event.process_indicators
                     if any(u in p.user.upper() for u in ("SYSTEM", "ROOT", "NT AUTHORITY"))]
        if sys_procs:
            score += 4.0
            notes.append(
                f"{len(sys_procs)} process(es) running as SYSTEM/root — "
                f"full privilege compromise. +4 severity."
            )

        # Executable files dropped to TEMP / /tmp
        tmp_execs = [f for f in event.file_indicators
                     if f.is_executable and ("temp" in f.path.lower() or "/tmp" in f.path.lower())]
        if tmp_execs:
            score += 3.0
            notes.append(
                f"Executable dropped to temp directory ({tmp_execs[0].path}). +3 severity."
            )

        notes.insert(0, f"Base severity for {event.attack_type.value}: {base:.1f}.")
        return _clamp(score), notes

    def _adjust_volatility(
        self,
        event: DetectionEvent,
        items: List[EvidenceItem],
        base: float,
    ) -> tuple[float, List[str]]:
        score  = base
        notes: List[str] = []

        # Memory evidence present → very volatile
        mem_items = [i for i in items if i.category == "memory"]
        if mem_items:
            score += 8.0
            notes.append(
                f"{len(mem_items)} memory evidence item(s) identified — "
                f"RAM content is extremely volatile. +8 volatility."
            )

        # Active network connections
        high_ano_net = [n for n in event.network_indicators if n.anomaly_score > 0.80]
        if high_ano_net:
            score += 5.0
            notes.append(
                f"{len(high_ano_net)} active high-anomaly network connection(s) — "
                f"session metadata will be lost on isolation. +5 volatility."
            )

        notes.insert(0, f"Base evidence volatility for {event.attack_type.value}: {base:.1f}.")
        return _clamp(score), notes

    def _adjust_activity(
        self, event: DetectionEvent, base: float
    ) -> tuple[float, List[str]]:
        score  = base
        notes: List[str] = []

        # Multiple target IPs suggest active lateral spread
        target_ips = {n.dest_ip for n in event.network_indicators}
        if len(target_ips) > 2:
            score += 8.0
            notes.append(
                f"Traffic to {len(target_ips)} distinct destination IPs — "
                f"active scanning / spreading. +8 activity."
            )

        # Very high CPU (ransomware encrypting, exploit running)
        hot_procs = [p for p in event.process_indicators if p.cpu_pct > 40.0]
        if hot_procs:
            score += 5.0
            notes.append(
                f"{len(hot_procs)} process(es) at > 40 % CPU — "
                f"active computation (encryption / exploitation). +5 activity."
            )

        # High packet count → active flood or exfil
        hi_pkt = [n for n in event.network_indicators if n.packets > 10_000]
        if hi_pkt:
            score += 6.0
            notes.append(
                f"High packet count on {len(hi_pkt)} flow(s) — "
                f"large-scale active transfer. +6 activity."
            )

        notes.insert(0, f"Base attacker activity for {event.attack_type.value}: {base:.1f}.")
        return _clamp(score), notes
