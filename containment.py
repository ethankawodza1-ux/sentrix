"""
SENTRIX — Containment Executor
================================
Simulates executing containment actions on a compromised asset.
In production this module would call into orchestration APIs:
SOAR platforms, firewall SDKs, Active Directory, SIEM, etc.
"""
from __future__ import annotations
import time
from typing import List, Tuple

from .models import ResponsePlan, ResponseDecision


# Action execution result
ActionResult = Tuple[str, bool, str]   # (action_text, success, detail)


class ContainmentExecutor:
    """
    Walks through the ResponsePlan and simulates executing each step.
    Returns a list of (action, success, detail) tuples.
    """

    def execute(self, plan: ResponsePlan) -> List[ActionResult]:
        results: List[ActionResult] = []
        decision = plan.decision

        # Step 1 — always run immediate notification actions
        for action in plan.immediate_actions:
            results.append(self._run(action))

        if decision == ResponseDecision.CONTAIN_IMMEDIATELY:
            # Skip evidence capture — containment takes absolute priority
            for action in plan.containment_actions:
                results.append(self._run(action))
            # Evidence collected post-containment (whatever survives)
            for action in plan.evidence_actions:
                results.append(self._run(action, prefix="[POST-CONTAIN] "))

        elif decision == ResponseDecision.PRESERVE_EVIDENCE_FIRST:
            # Evidence capture window before containment
            for action in plan.evidence_actions:
                results.append(self._run(action))
            # Then execute full containment
            for action in plan.containment_actions:
                results.append(self._run(action))

        elif decision == ResponseDecision.MONITOR_AND_ALERT:
            # No active containment — increase sensor fidelity
            results.append(self._run("[MONITOR] Increase SIEM alert verbosity to DEBUG"))
            results.append(self._run("[MONITOR] Deploy honeytoken on affected asset"))
            results.append(self._run("[MONITOR] Enable full packet capture on asset SPAN port"))

        elif decision == ResponseDecision.ESCALATE_TO_HUMAN:
            results.append(self._run("[ESCALATE] Paging on-call IR analyst via PagerDuty"))
            results.append(self._run("[ESCALATE] Creating annotated incident report"))
            results.append(self._run("[ESCALATE] All automated actions PAUSED — awaiting human approval"))

        # Forensic actions always run at the end
        for action in plan.forensic_actions:
            results.append(self._run(action))

        return results

    @staticmethod
    def _run(action: str, prefix: str = "") -> ActionResult:
        """Simulate executing one action (always succeeds in the demo)."""
        display = f"{prefix}{action}".strip()
        # In production: call SOAR SDK, firewall API, AD connector, etc.
        time.sleep(0.01)   # simulate slight I/O latency
        return display, True, "OK"
