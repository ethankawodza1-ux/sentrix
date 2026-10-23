"""
SENTRIX -- Flask Web Application
==================================
Exposes the full pipeline via a REST JSON API consumed by the SPA frontend.

Routes
------
GET  /                          -> serve SPA (index.html)
POST /api/run                   -> run one scenario  { "attack_type": "ransomware" | "random" }
GET  /api/scenarios             -> run all 10 scenarios and return summary list
GET  /api/attack-types          -> list of valid attack type keys + labels
"""
from __future__ import annotations

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, render_template, request, abort

from sentrix.models import AttackType, ResponseDecision, ThreatLevel
from sentrix.orchestrator import SentrixOrchestrator

app = Flask(__name__)

# One shared orchestrator instance (no seed = real randomness each run)
_orchestrator = SentrixOrchestrator(auto_execute=True)

# ── Helper: snake_case key -> AttackType ─────────────────────────────────────
_ATTACK_MAP: dict[str, AttackType] = {
    "ransomware":           AttackType.RANSOMWARE,
    "apt":                  AttackType.APT,
    "lateral_movement":     AttackType.LATERAL_MOVEMENT,
    "data_exfiltration":    AttackType.DATA_EXFILTRATION,
    "privilege_escalation": AttackType.PRIVILEGE_ESCALATION,
    "ddos":                 AttackType.DDOS,
    "zero_day":             AttackType.ZERO_DAY,
    "malware":              AttackType.MALWARE,
    "insider_threat":       AttackType.INSIDER_THREAT,
    "phishing":             AttackType.PHISHING,
}

_LEVEL_COLOUR = {
    "CRITICAL":      "#ef4444",
    "HIGH":          "#f97316",
    "MEDIUM":        "#eab308",
    "LOW":           "#22c55e",
    "INFORMATIONAL": "#3b82f6",
}

_DECISION_COLOUR = {
    "CONTAIN_IMMEDIATELY":    "#ef4444",
    "PRESERVE_EVIDENCE_FIRST":"#eab308",
    "MONITOR_AND_ALERT":      "#3b82f6",
    "ESCALATE_TO_HUMAN":      "#8b5cf6",
}


def _serialise_plan(plan, execution_log) -> dict:
    """Convert ResponsePlan + execution_log into a JSON-safe dict."""
    a   = plan.assessment
    ev  = a.event
    ir  = a.intel_report
    mm  = a.mitre_mapping

    def _fmt_bytes(n):
        if n >= 1_073_741_824: return f"{n/1_073_741_824:.1f} GB"
        if n >= 1_048_576:     return f"{n/1_048_576:.1f} MB"
        if n >= 1_024:         return f"{n/1_024:.1f} KB"
        return f"{n} B"

    return {
        # ── event ──────────────────────────────────────────────────────────
        "event": {
            "event_id":          ev.event_id,
            "timestamp":         ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "asset_id":          ev.asset_id,
            "asset_name":        ev.asset_name,
            "asset_criticality": ev.asset_criticality.name,
            "attack_type":       ev.attack_type.value,
            "attack_key":        ev.attack_type.name.lower(),
            "raw_log":           ev.raw_log_snippet,
            "network_iocs": [
                {"src": n.source_ip, "dst": n.dest_ip, "port": n.port,
                 "proto": n.protocol, "bytes": n.bytes_sent,
                 "packets": n.packets, "score": round(n.anomaly_score, 3)}
                for n in ev.network_indicators
            ],
            "process_iocs": [
                {"pid": p.pid, "name": p.name, "parent": p.parent_name,
                 "cmd": p.command_line, "user": p.user,
                 "cpu": p.cpu_pct, "mem_mb": p.mem_mb, "score": round(p.anomaly_score, 3)}
                for p in ev.process_indicators
            ],
            "file_iocs": [
                {"path": f.path, "action": f.action, "entropy": round(f.entropy, 2),
                 "executable": f.is_executable, "score": round(f.anomaly_score, 3)}
                for f in ev.file_indicators
            ],
        },
        # ── assessment ─────────────────────────────────────────────────────
        "assessment": {
            "threat_level":          a.threat_level.name,
            "threat_level_value":    a.threat_level.value,
            "threat_level_colour":   _LEVEL_COLOUR.get(a.threat_level.name, "#94a3b8"),
            "threat_score":          round(a.threat_score, 1),
            "severity_score":        round(a.severity_score, 1),
            "evidence_volatility":   round(a.evidence_volatility, 1),
            "attacker_activity":     round(a.attacker_activity, 1),
            "asset_criticality_score": round(a.asset_criticality_score, 1),
            "ioc_count":             a.ioc_count,
            "lateral_movement_risk": a.lateral_movement_risk,
            "data_loss_risk":        a.data_loss_risk,
            "persistence_detected":  a.persistence_detected,
            "confidence":            round(a.confidence * 100),
            "reasoning":             a.reasoning,
        },
        # ── decision ───────────────────────────────────────────────────────
        "decision": {
            "value":          plan.decision.value,
            "colour":         _DECISION_COLOUR.get(plan.decision.value, "#94a3b8"),
            "priority_score": plan.priority_score,
            "response_secs":  plan.estimated_response_time_seconds,
            "rationale":      plan.decision_rationale,
            "notifications":  plan.notification_targets,
            "immediate":      plan.immediate_actions,
            "containment":    plan.containment_actions,
            "forensic":       plan.forensic_actions,
        },
        # ── evidence ───────────────────────────────────────────────────────
        "evidence": [
            {
                "id":       e.evidence_id,
                "category": e.category,
                "desc":     e.description,
                "rank":     e.volatility_rank,
                "method":   e.capture_method,
                "size":     _fmt_bytes(e.size_bytes),
                "size_raw": e.size_bytes,
            }
            for e in sorted(a.evidence_items, key=lambda x: x.volatility_rank)
        ],
        # ── threat intel ───────────────────────────────────────────────────
        "intel": {
            "actor":       ir.known_threat_actor   if ir else None,
            "campaign":    ir.campaign_name        if ir else None,
            "nation":      ir.threat_actor_nation  if ir else None,
            "matches":     ir.total_iocs_matched   if ir else 0,
            "confidence":  round((ir.intel_confidence or 0) * 100) if ir else 0,
            "boost":       ir.intel_severity_boost if ir else 0,
            "notes":       ir.enrichment_notes     if ir else [],
            "ioc_matches": [
                {"provider": m.provider, "ioc_type": m.ioc_type,
                 "ioc_value": m.ioc_value,
                 "malicious": m.malicious_votes, "total": m.total_votes,
                 "confidence": round(m.confidence * 100),
                 "threat_names": m.threat_names[:2], "tags": m.tags[:4]}
                for m in (ir.ioc_matches if ir else [])
            ] if ir else [],
        },
        # ── mitre ──────────────────────────────────────────────────────────
        "mitre": {
            "kill_chain":     mm.kill_chain_stage  if mm else "",
            "primary_tactic": mm.primary_tactic    if mm else "",
            "navigator_url":  mm.navigator_url     if mm else "",
            "techniques": [
                {"id": t.technique_id, "name": t.name, "tactic": t.tactic,
                 "tactic_id": t.tactic_id, "url": t.url,
                 "sub": t.is_subtechnique,
                 "mitigations": t.mitigations[:2],
                 "detections": t.detections[:2]}
                for t in (mm.techniques if mm else [])
            ],
        },
        # ── execution log ──────────────────────────────────────────────────
        "execution_log": [
            {"action": a_text, "ok": ok, "detail": detail}
            for a_text, ok, detail in execution_log
        ],
    }


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/attack-types")
def attack_types():
    return jsonify([
        {"key": k, "label": v.value}
        for k, v in _ATTACK_MAP.items()
    ])


@app.route("/api/run", methods=["POST"])
def run_scenario():
    data = request.get_json(silent=True) or {}
    key  = (data.get("attack_type") or "random").lower().strip()

    if key == "random":
        attack_type = None
    elif key in _ATTACK_MAP:
        attack_type = _ATTACK_MAP[key]
    else:
        abort(400, f"Unknown attack type: {key}")

    plan, log = _orchestrator.respond(attack_type)
    return jsonify(_serialise_plan(plan, log))


@app.route("/api/scenarios")
def all_scenarios():
    results = []
    for key, at in _ATTACK_MAP.items():
        plan, log = _orchestrator.respond(at)
        s = _serialise_plan(plan, log)
        results.append({
            "key":           key,
            "attack_type":   s["event"]["attack_type"],
            "asset_name":    s["event"]["asset_name"],
            "criticality":   s["event"]["asset_criticality"],
            "threat_level":  s["assessment"]["threat_level"],
            "threat_colour": s["assessment"]["threat_level_colour"],
            "threat_score":  s["assessment"]["threat_score"],
            "decision":      s["decision"]["value"],
            "dec_colour":    s["decision"]["colour"],
            "response_secs": s["decision"]["response_secs"],
            "actor":         s["intel"]["actor"],
            "ioc_count":     s["assessment"]["ioc_count"],
            "mitre_count":   len(s["mitre"]["techniques"]),
        })
    return jsonify(results)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
