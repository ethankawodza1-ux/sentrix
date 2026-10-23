"""
SENTRIX -- CLI Entry Point & Interactive Demo
=============================================
Run:
    python main.py                 -> random scenario
    python main.py ransomware      -> force ransomware scenario
    python main.py apt             -> force APT scenario
    python main.py all             -> run all 10 attack scenarios (summary table)

Available scenario names:
    ransomware  apt  lateral_movement  data_exfiltration  privilege_escalation
    ddos  zero_day  malware  insider_threat  phishing
"""
from __future__ import annotations
import sys
import os
import io
import textwrap
from datetime import datetime

# Force UTF-8 on Windows so box-drawing / emoji chars render correctly
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ── Make package importable when run directly from the sentrix/ directory ──
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sentrix.models import AttackType, ResponseDecision, ThreatLevel
from sentrix.orchestrator import SentrixOrchestrator


# ──────────────────────────────────────────────────────────────────────────────
#  Terminal colour helpers
# ──────────────────────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"
WHITE  = "\033[97m"
BG_RED = "\033[41m"
BG_DARK= "\033[100m"


def _c(text: str, *codes: str) -> str:
    return "".join(codes) + str(text) + RESET


# ──────────────────────────────────────────────────────────────────────────────
#  Rendering helpers
# ──────────────────────────────────────────────────────────────────────────────

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

_DECISION_COLOURS: dict[ResponseDecision, str] = {
    ResponseDecision.CONTAIN_IMMEDIATELY:    BG_RED  + BOLD,
    ResponseDecision.PRESERVE_EVIDENCE_FIRST: YELLOW + BOLD,
    ResponseDecision.MONITOR_AND_ALERT:      CYAN   + BOLD,
    ResponseDecision.ESCALATE_TO_HUMAN:      MAGENTA + BOLD,
}

_LEVEL_COLOURS: dict[ThreatLevel, str] = {
    ThreatLevel.CRITICAL:      BG_RED  + BOLD,
    ThreatLevel.HIGH:          RED     + BOLD,
    ThreatLevel.MEDIUM:        YELLOW  + BOLD,
    ThreatLevel.LOW:           GREEN,
    ThreatLevel.INFORMATIONAL: BLUE,
}

_DECISION_ICONS: dict[ResponseDecision, str] = {
    ResponseDecision.CONTAIN_IMMEDIATELY:    "[!!]",
    ResponseDecision.PRESERVE_EVIDENCE_FIRST: "[EV]",
    ResponseDecision.MONITOR_AND_ALERT:      "[**]",
    ResponseDecision.ESCALATE_TO_HUMAN:      "[??]",
}

BANNER = f"""
{_c('+' + '=' * 66 + '+', CYAN, BOLD)}
{_c('|', CYAN, BOLD)}  {_c('SENTRIX', WHITE, BOLD)} -- {_c('Cyber Threat Detection & Intelligent Response', DIM)}           {_c('|', CYAN, BOLD)}
{_c('|', CYAN, BOLD)}  {_c('v1.0  |  Detect -> Assess -> Decide -> Contain', DIM)}                   {_c('|', CYAN, BOLD)}
{_c('+' + '=' * 66 + '+', CYAN, BOLD)}
"""

def _hr(char: str = "-", width: int = 68, colour: str = DIM) -> str:
    return _c(char * width, colour)


def _bar(score: float, width: int = 30) -> str:
    """Render a simple ASCII progress bar for a 0-100 score."""
    filled = int(score / 100 * width)
    empty  = width - filled
    if score >= 80:
        colour = RED
    elif score >= 55:
        colour = YELLOW
    else:
        colour = GREEN
    return _c("#" * filled, colour) + _c("." * empty, DIM) + f" {score:5.1f}"


def _fmt_bytes(n: int) -> str:
    if n >= 1_073_741_824:
        return f"{n/1_073_741_824:.1f} GB"
    if n >= 1_048_576:
        return f"{n/1_048_576:.1f} MB"
    if n >= 1_024:
        return f"{n/1_024:.1f} KB"
    return f"{n} B"


def _section(title: str) -> None:
    print(f"\n{_c(f'  >> {title}', CYAN, BOLD)}")
    print(_hr())


def print_full_report(plan, execution_log) -> None:
    """Print the complete SENTRIX report for one incident."""
    a    = plan.assessment
    ev   = a.event
    dec  = plan.decision
    lvl  = a.threat_level

    print(BANNER)
    print(f"  {_c('Incident Report', BOLD, WHITE)}  ·  {_c(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), DIM)}")
    print(f"  Event ID : {_c(ev.event_id, CYAN)}")
    print()

    # ── Detection summary ──────────────────────────────────────────────────
    _section("DETECTION SUMMARY")
    print(f"  Attack Type   : {_c(ev.attack_type.value, BOLD, WHITE)}")
    print(f"  Asset         : {_c(ev.asset_name, WHITE)}")
    print(f"  Asset ID      : {ev.asset_id}")
    print(f"  Criticality   : {_c(ev.asset_criticality.name, BOLD)}")
    print(f"  Detected At   : {ev.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  IOC Count     : {a.ioc_count} indicator(s)")
    print()
    print(f"  {_c('Raw Log Snippet:', DIM)}")
    for line in ev.raw_log_snippet.split("\n"):
        print(f"    {_c(line, DIM)}")

    # ── Threat assessment scores ───────────────────────────────────────────
    _section("THREAT ASSESSMENT")
    lc = _LEVEL_COLOURS.get(lvl, WHITE)
    print(f"  Threat Level  : {_c(f'  {lvl.name}  ', lc)}")
    print(f"  Confidence    : {a.confidence:.0%}")
    print()
    print(f"  {'Dimension':<28} {'Score':>6}  Bar")
    print(f"  {_hr('-', 56, DIM)}")
    dims = [
        ("Threat Score (composite)", a.threat_score),
        ("Severity",                 a.severity_score),
        ("Evidence Volatility",      a.evidence_volatility),
        ("Attacker Activity",        a.attacker_activity),
        ("Asset Criticality",        a.asset_criticality_score),
    ]
    for label, score in dims:
        print(f"  {label:<28}  {_bar(score)}")
    print()
    print(f"  Lateral Movement Risk : {_c('YES', RED, BOLD) if a.lateral_movement_risk else _c('NO', GREEN)}")
    print(f"  Data Loss Risk        : {_c('YES', RED, BOLD) if a.data_loss_risk        else _c('NO', GREEN)}")
    print(f"  Persistence Detected  : {_c('YES', RED, BOLD) if a.persistence_detected  else _c('NO', GREEN)}")

    # ── Assessment reasoning ───────────────────────────────────────────────
    _section("ASSESSMENT REASONING")
    for note in a.reasoning:
        wrapped = textwrap.fill(note, width=64, subsequent_indent="      ")
        print(f"  * {wrapped}")

    # ── Decision ──────────────────────────────────────────────────────────
    _section("RESPONSE DECISION")
    dc = _DECISION_COLOURS.get(dec, WHITE)
    icon = _DECISION_ICONS.get(dec, "[ ]")
    print(f"  {icon}  Decision : {_c(f'  {dec.value}  ', dc)}")
    print(f"  Priority Score    : {_c(f'{plan.priority_score:.1f} / 100', BOLD)}")
    print(f"  Response Window   : {plan.estimated_response_time_seconds}s")
    print()
    print(f"  {_c('Rationale:', DIM)}")
    for r in plan.decision_rationale:
        wrapped = textwrap.fill(r, width=64, subsequent_indent="      ")
        print(f"  -> {wrapped}")

    # ── Notification targets ───────────────────────────────────────────────
    _section("NOTIFICATION TARGETS")
    for n in plan.notification_targets:
        print(f"  [MAIL]  {n}")

    # ── Evidence capture plan ──────────────────────────────────────────────
    _section("EVIDENCE CAPTURE PLAN  (by volatility rank)")
    total_mb = sum(i.size_bytes for i in a.evidence_items) / 1_048_576
    print(f"  {len(a.evidence_items)} item(s)  |  Total size: {total_mb:,.0f} MB")
    print()
    for item in sorted(a.evidence_items, key=lambda x: x.volatility_rank):
        vol_icon = "[HIGH-VOL]" if item.volatility_rank <= 2 else ("[MED-VOL]" if item.volatility_rank == 3 else "[LOW-VOL]")
        print(f"  {vol_icon} [{item.evidence_id}] Rank {item.volatility_rank}  {_c(item.category.upper(), BOLD)}")
        wrapped = textwrap.fill(item.description, width=60, subsequent_indent="         ")
        print(f"     {wrapped}")
        print(f"     Method : {_c(item.capture_method, DIM)}")
        print(f"     Size   : {_fmt_bytes(item.size_bytes)}")
        print()

    # ── Threat intelligence ────────────────────────────────────────────────
    intel = a.intel_report
    if intel:
        _section("THREAT INTELLIGENCE ENRICHMENT")
        if intel.known_threat_actor:
            print(f"  Threat Actor  : {_c(intel.known_threat_actor, RED, BOLD)}")
            print(f"  Campaign      : {_c(intel.campaign_name or 'Unknown', BOLD)}")
            print(f"  Nation-State  : {_c(intel.threat_actor_nation or 'Unknown', YELLOW)}")
        print(f"  Feed Matches  : {intel.total_iocs_matched} IOC(s) matched across feeds")
        print(f"  Intel Conf.   : {intel.intel_confidence:.0%}")
        print(f"  Severity Boost: +{intel.intel_severity_boost:.1f}")
        print()
        for note in intel.enrichment_notes:
            wrapped = textwrap.fill(note, width=64, subsequent_indent="      ")
            print(f"  * {wrapped}")
        if intel.ioc_matches:
            print()
            print(f"  {_c('Feed Hits:', DIM)}")
            seen_providers: set = set()
            for match in intel.ioc_matches:
                key = (match.provider, match.ioc_value)
                if key in seen_providers:
                    continue
                seen_providers.add(key)
                bar = _c("#" * int(match.confidence * 20), RED if match.confidence > 0.7 else YELLOW)
                bar += _c("." * (20 - int(match.confidence * 20)), DIM)
                print(f"  [{match.provider:<20}] {match.ioc_type}:{match.ioc_value:<20}"
                      f"  {bar}  {match.confidence:.0%}")

    # ── MITRE ATT&CK mapping ───────────────────────────────────────────────
    mitre = a.mitre_mapping
    if mitre:
        _section("MITRE ATT&CK MAPPING  (Enterprise v14)")
        print(f"  Kill-Chain Stage : {_c(mitre.kill_chain_stage, BOLD)}")
        print(f"  Primary Tactic   : {_c(mitre.primary_tactic, CYAN)}")
        print(f"  Techniques       : {len(mitre.techniques)}")
        print()
        print(f"  {'ID':<12} {'Tactic':<26} {'Technique':<40} {'Mitigations'}")
        print(f"  {_hr('-', 100, DIM)}")
        for tech in mitre.techniques:
            sub = "*" if tech.is_subtechnique else " "
            mit = tech.mitigations[0].split(" - ")[0] if tech.mitigations else "-"
            print(f"  {_c(tech.technique_id, CYAN)}{sub}  {tech.tactic:<26} {tech.name:<40} {_c(mit, DIM)}")
        print()
        print(f"  {_c('Navigator URL:', DIM)}")
        print(f"  {_c(mitre.navigator_url[:80], BLUE)}")

    # ── Containment playbook ───────────────────────────────────────────────
    _section("CONTAINMENT PLAYBOOK")
    for action in plan.containment_actions:
        tag = action.split("]")[0].replace("[", "").strip() if "]" in action else "ACT"
        rest = action.split("]", 1)[1].strip() if "]" in action else action
        tag_c = RED if tag in ("ISOLATE", "STOP", "BLOCK", "KILL") else (
                YELLOW if tag in ("CREDS", "REVOKE", "PURGE") else CYAN)
        print(f"  {_c(f'[{tag}]', tag_c, BOLD)} {rest}")

    # ── Execution log ──────────────────────────────────────────────────────
    if execution_log:
        _section("EXECUTION LOG")
        ok_count   = sum(1 for _, s, _ in execution_log if s)
        fail_count = sum(1 for _, s, _ in execution_log if not s)
        print(f"  {ok_count} action(s) succeeded  |  {fail_count} failed\n")
        for action_text, success, detail in execution_log:
            status = _c("[OK]", GREEN) if success else _c("[FAIL]", RED)
            short  = (action_text[:72] + "...") if len(action_text) > 75 else action_text
            print(f"  {status}  {_c(short, DIM)}")

    print(f"\n{_hr('=', 68, CYAN)}\n")


def print_summary_table(plans) -> None:
    """Print a one-line-per-scenario summary table."""
    print(BANNER)
    print(f"  {_c('SENTRIX -- All-Scenarios Summary', BOLD, WHITE)}\n")
    print(f"  {'Attack Type':<32} {'Level':<14} {'Score':>6}  {'Decision':<30}  {'ETA':>5}s")
    print(f"  {_hr('-', 90, DIM)}")
    for plan, _ in plans:
        a   = plan.assessment
        ev  = a.event
        dec = plan.decision
        lc  = _LEVEL_COLOURS.get(a.threat_level, WHITE)
        dc  = _DECISION_COLOURS.get(dec, WHITE)
        icon = _DECISION_ICONS.get(dec, "[ ]")
        level_str = _c(f"{a.threat_level.name:<12}", lc)
        dec_str   = _c(f"{dec.value[:28]:<28}", dc)
        print(f"  {ev.attack_type.value:<32} {level_str}  {a.threat_score:5.1f}  "
              f"{icon} {dec_str}  {plan.estimated_response_time_seconds:>5}")
    print()


# ──────────────────────────────────────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    arg = sys.argv[1].lower() if len(sys.argv) > 1 else "random"

    sentrix = SentrixOrchestrator(seed=42, auto_execute=True)

    if arg == "all":
        plans = []
        for at in AttackType:
            plan, log = sentrix.respond(at)
            plans.append((plan, log))
        print_summary_table(plans)
        return

    # Single scenario
    if arg == "random":
        attack_type = None
    elif arg in _ATTACK_MAP:
        attack_type = _ATTACK_MAP[arg]
    else:
        print(f"Unknown scenario '{arg}'. Available: random, all, " + ", ".join(_ATTACK_MAP))
        sys.exit(1)

    plan, log = sentrix.respond(attack_type)
    print_full_report(plan, log)


if __name__ == "__main__":
    main()
