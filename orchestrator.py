"""
SENTRIX -- Main Orchestrator
=============================
Wires together all modules into a single pipeline:

  ThreatDetector -> EvidenceCollector -> ThreatAssessor
      -> ThreatIntelAggregator + MITREMapper (enrichment)
      -> DecisionEngine -> ContainmentExecutor

The Orchestrator is the only entry point external callers need.
"""
from __future__ import annotations
from typing import Optional

from .models      import AttackType, DetectionEvent, ResponsePlan
from .detector    import ThreatDetector
from .evidence    import EvidenceCollector
from .assessor    import ThreatAssessor
from .decision    import DecisionEngine
from .containment import ContainmentExecutor
from .threat_intel import ThreatIntelAggregator
from .mitre        import MITREMapper


class SentrixOrchestrator:
    """
    Full SENTRIX analysis pipeline.

    Parameters
    ----------
    seed : int, optional
        Fix the detector's random seed for reproducible demos.
    auto_execute : bool
        If True, automatically runs containment after deciding.
        Set to False when you only want the plan without execution.
    """

    def __init__(self, seed: Optional[int] = None, auto_execute: bool = True):
        self._detector   = ThreatDetector(seed=seed)
        self._collector  = EvidenceCollector()
        self._assessor   = ThreatAssessor()
        self._decision   = DecisionEngine()
        self._executor   = ContainmentExecutor()
        self._intel      = ThreatIntelAggregator()
        self._mitre      = MITREMapper()
        self.auto_execute = auto_execute

    # ── Public API ────────────────────────────────────────────────────────────

    def respond(
        self,
        attack_type: Optional[AttackType] = None,
    ) -> tuple[ResponsePlan, list]:
        """
        Run the full pipeline for one attack scenario.

        Parameters
        ----------
        attack_type : AttackType, optional
            Force a specific attack type; if None a random scenario is used.

        Returns
        -------
        plan : ResponsePlan
        execution_log : list of (action_text, success, detail) tuples
        """
        # 1. Detect
        event: DetectionEvent = self._detector.detect(attack_type)

        # 2. Collect evidence catalogue
        evidence = self._collector.collect(event)

        # 3. Assess (base scores)
        assessment = self._assessor.assess(event, evidence)

        # 4. Enrich with threat intel + MITRE ATT&CK
        intel_report = self._intel.enrich(event)
        mitre_mapping = self._mitre.map(event.attack_type)
        mitre_boost   = self._mitre.scoring_boost(mitre_mapping)

        # Apply boosts and attach to assessment
        assessment.threat_score   = min(100.0, assessment.threat_score
                                        + intel_report.intel_severity_boost
                                        + mitre_boost)
        assessment.severity_score = min(100.0, assessment.severity_score
                                        + intel_report.intel_severity_boost)
        assessment.intel_report   = intel_report
        assessment.mitre_mapping  = mitre_mapping

        if intel_report.enrichment_notes:
            assessment.reasoning += ["-- Threat Intelligence --"] + intel_report.enrichment_notes
        assessment.reasoning += [
            "-- MITRE ATT&CK --",
            f"Kill-chain: {mitre_mapping.kill_chain_stage}",
            f"Primary tactic: {mitre_mapping.primary_tactic}",
            f"Technique IDs: {', '.join(mitre_mapping.technique_ids)}",
            f"ATT&CK scoring boost: +{mitre_boost:.1f}",
        ]

        # 5. Decide
        plan = self._decision.decide(assessment)

        # 5. Execute (optional)
        execution_log = []
        if self.auto_execute:
            execution_log = self._executor.execute(plan)

        return plan, execution_log

    def respond_to_event(self, event: DetectionEvent) -> tuple[ResponsePlan, list]:
        """Accept an externally-constructed DetectionEvent (e.g. from a live EDR feed)."""
        evidence      = self._collector.collect(event)
        assessment    = self._assessor.assess(event, evidence)
        intel_report  = self._intel.enrich(event)
        mitre_mapping = self._mitre.map(event.attack_type)
        mitre_boost   = self._mitre.scoring_boost(mitre_mapping)
        assessment.threat_score   = min(100.0, assessment.threat_score + intel_report.intel_severity_boost + mitre_boost)
        assessment.severity_score = min(100.0, assessment.severity_score + intel_report.intel_severity_boost)
        assessment.intel_report   = intel_report
        assessment.mitre_mapping  = mitre_mapping
        plan          = self._decision.decide(assessment)
        execution_log = self._executor.execute(plan) if self.auto_execute else []
        return plan, execution_log
