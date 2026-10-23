"""
SENTRIX -- MITRE ATT&CK Mapping Module
========================================
Maps each detected attack scenario to the relevant MITRE ATT&CK
Tactics, Techniques, and Sub-techniques (Enterprise matrix v14).

Each AttackType resolves to:
  - A list of ATT&CK Technique objects (ID, name, tactic, description)
  - A kill-chain stage (recon -> initial-access -> ... -> impact)
  - A MITRE Navigator layer URL for browser viewing

Reference: https://attack.mitre.org/
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Dict

from .models import AttackType


# ─────────────────────────────────────────────────────────────────────────────
#  Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ATTACKTechnique:
    """A single MITRE ATT&CK technique or sub-technique."""
    technique_id:  str          # e.g. "T1486"
    name:          str          # e.g. "Data Encrypted for Impact"
    tactic:        str          # e.g. "Impact"
    tactic_id:     str          # e.g. "TA0040"
    description:   str
    url:           str
    is_subtechnique: bool       = False
    mitigations:   List[str]   = field(default_factory=list)
    detections:    List[str]   = field(default_factory=list)


@dataclass
class ATTACKMapping:
    """Full MITRE ATT&CK context for one attack scenario."""
    attack_type:    AttackType
    kill_chain_stage: str
    techniques:     List[ATTACKTechnique]
    primary_tactic: str
    navigator_url:  str         # pre-built Navigator layer link

    @property
    def technique_ids(self) -> List[str]:
        return [t.technique_id for t in self.techniques]

    @property
    def tactics(self) -> List[str]:
        return list(dict.fromkeys(t.tactic for t in self.techniques))

    def summary_lines(self) -> List[str]:
        lines = [
            f"Kill-Chain Stage : {self.kill_chain_stage}",
            f"Primary Tactic   : {self.primary_tactic}",
            f"Techniques       : {len(self.techniques)}",
        ]
        for t in self.techniques:
            lines.append(
                f"  [{t.technique_id}] {t.tactic:<22} {t.name}"
            )
        return lines


# ─────────────────────────────────────────────────────────────────────────────
#  Technique catalogue  (curated subset of ATT&CK Enterprise v14)
# ─────────────────────────────────────────────────────────────────────────────

def _t(tid, name, tactic, tactic_id, desc, mitigations=None, detections=None):
    return ATTACKTechnique(
        technique_id=tid, name=name, tactic=tactic, tactic_id=tactic_id,
        description=desc,
        url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        is_subtechnique="." in tid,
        mitigations=mitigations or [],
        detections=detections or [],
    )

# -- Ransomware ---------------------------------------------------------------
_RANSOMWARE_TECHNIQUES = [
    _t("T1566.001", "Spearphishing Attachment",    "Initial Access",  "TA0001",
       "Adversary sends a spear-phishing email with a malicious attachment to gain initial access.",
       ["M1049 - Antivirus/Antimalware", "M1031 - Network Intrusion Prevention"],
       ["DS0015 - Application Log", "DS0029 - Network Traffic"]),
    _t("T1059.001", "PowerShell",                  "Execution",       "TA0002",
       "Adversary uses PowerShell to execute malicious code.",
       ["M1045 - Code Signing", "M1042 - Disable or Remove Feature or Program"],
       ["DS0009 - Process", "DS0017 - Command"]),
    _t("T1490",     "Inhibit System Recovery",     "Impact",          "TA0040",
       "Adversary deletes Volume Shadow Copies to prevent file recovery.",
       ["M1053 - Data Backup"],
       ["DS0024 - Windows Registry", "DS0009 - Process"]),
    _t("T1486",     "Data Encrypted for Impact",   "Impact",          "TA0040",
       "Adversary encrypts data on target systems or on a large number of systems in a network.",
       ["M1053 - Data Backup"],
       ["DS0022 - File", "DS0009 - Process"]),
    _t("T1489",     "Service Stop",                "Impact",          "TA0040",
       "Adversary stops or disables services on a system to render those services unavailable.",
       ["M1030 - Network Segmentation", "M1022 - Restrict File and Directory Permissions"],
       ["DS0019 - Service", "DS0009 - Process"]),
    _t("T1041",     "Exfiltration Over C2 Channel","Exfiltration",    "TA0010",
       "Adversary steals data by exfiltrating it over an existing command and control channel.",
       ["M1031 - Network Intrusion Prevention", "M1057 - Data Loss Prevention"],
       ["DS0029 - Network Traffic"]),
]

# -- APT ----------------------------------------------------------------------
_APT_TECHNIQUES = [
    _t("T1195.002", "Compromise Software Supply Chain", "Initial Access", "TA0001",
       "Adversary manipulates software supply chain prior to distribution.",
       ["M1051 - Update Software", "M1016 - Vulnerability Scanning"],
       ["DS0022 - File"]),
    _t("T1055.001", "Dynamic-link Library Injection", "Defense Evasion", "TA0005",
       "Adversary injects malicious code into the address space of another process via DLL injection.",
       ["M1040 - Behavior Prevention on Endpoint"],
       ["DS0009 - Process", "DS0011 - Module"]),
    _t("T1053.005", "Scheduled Task",               "Persistence",     "TA0003",
       "Adversary abuses Windows Task Scheduler to execute malicious programs at system startup.",
       ["M1047 - Audit", "M1028 - Operating System Configuration"],
       ["DS0003 - Scheduled Job"]),
    _t("T1071.001", "Web Protocols (C2)",            "Command and Control","TA0011",
       "Adversary communicates with compromised systems using HTTP/HTTPS protocols.",
       ["M1031 - Network Intrusion Prevention"],
       ["DS0029 - Network Traffic"]),
    _t("T1027.002", "Software Packing",             "Defense Evasion", "TA0005",
       "Adversary performs software packing to conceal code.",
       ["M1049 - Antivirus/Antimalware"],
       ["DS0022 - File"]),
    _t("T1078",     "Valid Accounts",               "Defense Evasion", "TA0005",
       "Adversary obtains and abuses valid credentials.",
       ["M1036 - Account Use Policies", "M1032 - Multi-factor Authentication"],
       ["DS0002 - User Account"]),
]

# -- Lateral Movement ---------------------------------------------------------
_LATERAL_MOVEMENT_TECHNIQUES = [
    _t("T1550.002", "Pass the Hash",               "Lateral Movement","TA0008",
       "Adversary uses hashed credentials to authenticate and move laterally.",
       ["M1051 - Update Software", "M1052 - User Account Control"],
       ["DS0028 - Logon Session", "DS0002 - User Account"]),
    _t("T1021.002", "SMB/Windows Admin Shares",    "Lateral Movement","TA0008",
       "Adversary uses SMB to interact with remote shares or execute commands.",
       ["M1037 - Filter Network Traffic", "M1026 - Privileged Account Management"],
       ["DS0029 - Network Traffic"]),
    _t("T1047",     "Windows Management Instrumentation","Execution",  "TA0002",
       "Adversary abuses WMI to execute malicious commands on remote systems.",
       ["M1040 - Behavior Prevention on Endpoint", "M1026 - Privileged Account Management"],
       ["DS0009 - Process", "DS0005 - WMI"]),
    _t("T1558.003", "Kerberoasting",               "Credential Access","TA0006",
       "Adversary steals service tickets to crack offline for service account credentials.",
       ["M1041 - Encrypt Sensitive Information", "M1027 - Password Policies"],
       ["DS0026 - Active Directory"]),
    _t("T1003.001", "LSASS Memory",                "Credential Access","TA0006",
       "Adversary dumps LSASS memory to extract credentials.",
       ["M1043 - Credential Access Protection", "M1028 - Operating System Configuration"],
       ["DS0009 - Process", "DS0025 - Cloud Service"]),
]

# -- Data Exfiltration --------------------------------------------------------
_DATA_EXFIL_TECHNIQUES = [
    _t("T1048.002", "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", "Exfiltration", "TA0010",
       "Adversary steals data over HTTPS/TLS to avoid detection.",
       ["M1057 - Data Loss Prevention", "M1031 - Network Intrusion Prevention"],
       ["DS0029 - Network Traffic"]),
    _t("T1048.001", "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "Exfiltration", "TA0010",
       "Adversary uses DNS tunneling for covert data exfiltration.",
       ["M1021 - Restrict Web-Based Content"],
       ["DS0029 - Network Traffic"]),
    _t("T1560.001", "Archive via Utility",         "Collection",      "TA0009",
       "Adversary compresses and archives collected data prior to exfiltration.",
       ["M1047 - Audit"],
       ["DS0017 - Command", "DS0022 - File"]),
    _t("T1213",     "Data from Information Repositories","Collection", "TA0009",
       "Adversary attempts to collect sensitive data from information repositories.",
       ["M1047 - Audit", "M1018 - User Account Management"],
       ["DS0015 - Application Log"]),
    _t("T1083",     "File and Directory Discovery","Discovery",       "TA0007",
       "Adversary enumerates files and directories to find sensitive data.",
       ["M1028 - Operating System Configuration"],
       ["DS0022 - File", "DS0017 - Command"]),
]

# -- Privilege Escalation -----------------------------------------------------
_PRIVESC_TECHNIQUES = [
    _t("T1068",     "Exploitation for Privilege Escalation","Privilege Escalation","TA0004",
       "Adversary exploits software vulnerabilities to gain elevated privileges.",
       ["M1051 - Update Software", "M1048 - Application Isolation and Sandboxing"],
       ["DS0009 - Process"]),
    _t("T1055",     "Process Injection",           "Defense Evasion", "TA0005",
       "Adversary injects code into processes to evade defenses.",
       ["M1040 - Behavior Prevention on Endpoint"],
       ["DS0009 - Process"]),
    _t("T1548.001", "Setuid and Setgid",           "Privilege Escalation","TA0004",
       "Adversary abuses setuid/setgid bits to escalate privileges.",
       ["M1028 - Operating System Configuration"],
       ["DS0022 - File"]),
    _t("T1136.001", "Local Account",               "Persistence",     "TA0003",
       "Adversary creates a local account to maintain access.",
       ["M1032 - Multi-factor Authentication", "M1030 - Network Segmentation"],
       ["DS0002 - User Account"]),
]

# -- DDoS ---------------------------------------------------------------------
_DDOS_TECHNIQUES = [
    _t("T1498.001", "Direct Network Flood",        "Impact",          "TA0040",
       "Adversary performs a direct network flood to disrupt service availability.",
       ["M1037 - Filter Network Traffic"],
       ["DS0029 - Network Traffic"]),
    _t("T1498.002", "Reflection Amplification",    "Impact",          "TA0040",
       "Adversary uses amplification techniques (DNS/NTP) to amplify attack bandwidth.",
       ["M1037 - Filter Network Traffic"],
       ["DS0029 - Network Traffic"]),
    _t("T1499.001", "OS Exhaustion Flood",         "Impact",          "TA0040",
       "Adversary exhausts OS resources to cause a denial of service condition.",
       ["M1037 - Filter Network Traffic", "M1035 - Limit Access to Resource Over Network"],
       ["DS0029 - Network Traffic"]),
]

# -- Zero-Day -----------------------------------------------------------------
_ZERO_DAY_TECHNIQUES = [
    _t("T1190",     "Exploit Public-Facing Application","Initial Access","TA0001",
       "Adversary exploits a vulnerability in an internet-facing application.",
       ["M1048 - Application Isolation and Sandboxing", "M1051 - Update Software"],
       ["DS0015 - Application Log", "DS0029 - Network Traffic"]),
    _t("T1505.003", "Web Shell",                   "Persistence",     "TA0003",
       "Adversary installs a web shell to maintain persistent access.",
       ["M1042 - Disable or Remove Feature or Program"],
       ["DS0022 - File", "DS0015 - Application Log"]),
    _t("T1059.007", "JavaScript",                  "Execution",       "TA0002",
       "Adversary executes malicious JavaScript.",
       ["M1042 - Disable or Remove Feature or Program"],
       ["DS0009 - Process"]),
    _t("T1210",     "Exploitation of Remote Services","Lateral Movement","TA0008",
       "Adversary exploits remote services to gain access.",
       ["M1051 - Update Software", "M1050 - Exploit Protection"],
       ["DS0029 - Network Traffic"]),
]

# -- Malware ------------------------------------------------------------------
_MALWARE_TECHNIQUES = [
    _t("T1547.001", "Registry Run Keys / Startup Folder","Persistence","TA0003",
       "Adversary achieves persistence by adding a program to the registry run keys.",
       ["M1024 - Restrict Registry Permissions"],
       ["DS0024 - Windows Registry"]),
    _t("T1036.004", "Masquerading: Match Legitimate Name or Location","Defense Evasion","TA0005",
       "Adversary masquerades as a legitimate Windows process.",
       ["M1022 - Restrict File and Directory Permissions"],
       ["DS0009 - Process", "DS0022 - File"]),
    _t("T1071.001", "Web Protocols (C2)",          "Command and Control","TA0011",
       "Adversary communicates with compromised systems using HTTP/HTTPS.",
       ["M1031 - Network Intrusion Prevention"],
       ["DS0029 - Network Traffic"]),
    _t("T1082",     "System Information Discovery","Discovery",       "TA0007",
       "Adversary enumerates system information to fingerprint the target.",
       ["M1028 - Operating System Configuration"],
       ["DS0009 - Process"]),
]

# -- Insider Threat -----------------------------------------------------------
_INSIDER_TECHNIQUES = [
    _t("T1052.001", "Exfiltration over USB",       "Exfiltration",    "TA0010",
       "Adversary exfiltrates data over a USB connected physical medium.",
       ["M1034 - Limit Hardware Installation", "M1057 - Data Loss Prevention"],
       ["DS0022 - File"]),
    _t("T1213",     "Data from Information Repositories","Collection", "TA0009",
       "Adversary accesses and collects data from internal repositories.",
       ["M1018 - User Account Management"],
       ["DS0015 - Application Log"]),
    _t("T1078.002", "Domain Accounts",             "Defense Evasion", "TA0005",
       "Adversary abuses valid domain accounts to bypass defenses.",
       ["M1026 - Privileged Account Management", "M1032 - Multi-factor Authentication"],
       ["DS0002 - User Account"]),
    _t("T1074.001", "Local Data Staging",          "Collection",      "TA0009",
       "Adversary stages data to a local directory prior to exfiltration.",
       ["M1047 - Audit"],
       ["DS0022 - File"]),
]

# -- Phishing -----------------------------------------------------------------
_PHISHING_TECHNIQUES = [
    _t("T1566.002", "Spearphishing Link",          "Initial Access",  "TA0001",
       "Adversary sends a spear-phishing email with a malicious link.",
       ["M1017 - User Training", "M1021 - Restrict Web-Based Content"],
       ["DS0015 - Application Log", "DS0029 - Network Traffic"]),
    _t("T1539",     "Steal Web Session Cookie",    "Credential Access","TA0006",
       "Adversary steals web session cookies to bypass authentication.",
       ["M1032 - Multi-factor Authentication", "M1054 - Software Configuration"],
       ["DS0028 - Logon Session"]),
    _t("T1056.003", "Web Portal Capture",          "Collection",      "TA0009",
       "Adversary logs credentials submitted via a spoofed portal.",
       ["M1017 - User Training"],
       ["DS0028 - Logon Session"]),
    _t("T1176",     "Browser Extensions",          "Persistence",     "TA0003",
       "Adversary installs a malicious browser extension for persistent access.",
       ["M1047 - Audit"],
       ["DS0022 - File"]),
]


# ─────────────────────────────────────────────────────────────────────────────
#  Kill-chain stage mapping
# ─────────────────────────────────────────────────────────────────────────────

_KILL_CHAIN_STAGES: Dict[AttackType, str] = {
    AttackType.RANSOMWARE:           "Actions on Objectives (Encryption / Extortion)",
    AttackType.APT:                  "Persistence & Command-and-Control",
    AttackType.LATERAL_MOVEMENT:     "Lateral Movement & Credential Access",
    AttackType.DATA_EXFILTRATION:    "Collection & Exfiltration",
    AttackType.PRIVILEGE_ESCALATION: "Privilege Escalation & Defense Evasion",
    AttackType.DDOS:                 "Impact (Availability Disruption)",
    AttackType.ZERO_DAY:             "Initial Access & Exploitation",
    AttackType.MALWARE:              "Execution & Persistence",
    AttackType.INSIDER_THREAT:       "Collection & Exfiltration (Insider)",
    AttackType.PHISHING:             "Initial Access & Credential Access",
}

_PRIMARY_TACTICS: Dict[AttackType, str] = {
    AttackType.RANSOMWARE:           "TA0040 - Impact",
    AttackType.APT:                  "TA0003 - Persistence",
    AttackType.LATERAL_MOVEMENT:     "TA0008 - Lateral Movement",
    AttackType.DATA_EXFILTRATION:    "TA0010 - Exfiltration",
    AttackType.PRIVILEGE_ESCALATION: "TA0004 - Privilege Escalation",
    AttackType.DDOS:                 "TA0040 - Impact",
    AttackType.ZERO_DAY:             "TA0001 - Initial Access",
    AttackType.MALWARE:              "TA0003 - Persistence",
    AttackType.INSIDER_THREAT:       "TA0010 - Exfiltration",
    AttackType.PHISHING:             "TA0001 - Initial Access",
}

_TECHNIQUE_MAP: Dict[AttackType, List[ATTACKTechnique]] = {
    AttackType.RANSOMWARE:           _RANSOMWARE_TECHNIQUES,
    AttackType.APT:                  _APT_TECHNIQUES,
    AttackType.LATERAL_MOVEMENT:     _LATERAL_MOVEMENT_TECHNIQUES,
    AttackType.DATA_EXFILTRATION:    _DATA_EXFIL_TECHNIQUES,
    AttackType.PRIVILEGE_ESCALATION: _PRIVESC_TECHNIQUES,
    AttackType.DDOS:                 _DDOS_TECHNIQUES,
    AttackType.ZERO_DAY:             _ZERO_DAY_TECHNIQUES,
    AttackType.MALWARE:              _MALWARE_TECHNIQUES,
    AttackType.INSIDER_THREAT:       _INSIDER_TECHNIQUES,
    AttackType.PHISHING:             _PHISHING_TECHNIQUES,
}


# ─────────────────────────────────────────────────────────────────────────────
#  Public mapper
# ─────────────────────────────────────────────────────────────────────────────

class MITREMapper:
    """
    Maps an AttackType to its MITRE ATT&CK techniques.
    """

    def map(self, attack_type: AttackType) -> ATTACKMapping:
        techniques   = _TECHNIQUE_MAP.get(attack_type, [])
        kill_chain   = _KILL_CHAIN_STAGES.get(attack_type, "Unknown")
        primary_tact = _PRIMARY_TACTICS.get(attack_type, "Unknown")

        # Build a Navigator layer URL (loads technique layer on attack.mitre.org)
        tids = ",".join(t.technique_id for t in techniques)
        nav_url = (
            f"https://mitre-attack.github.io/attack-navigator/#"
            f"comment=SENTRIX+{attack_type.name}&techniques={tids}"
        )

        return ATTACKMapping(
            attack_type     = attack_type,
            kill_chain_stage= kill_chain,
            techniques      = techniques,
            primary_tactic  = primary_tact,
            navigator_url   = nav_url,
        )

    def scoring_boost(self, mapping: ATTACKMapping) -> float:
        """
        Returns an additional score boost (0–10) based on the number of
        high-impact ATT&CK tactics observed.

        Impact/Exfiltration tactics carry a higher weight than Discovery.
        """
        HIGH_IMPACT_TACTICS = {"TA0040", "TA0010", "TA0008", "TA0006"}
        count = sum(
            1 for t in mapping.techniques
            if t.tactic_id in HIGH_IMPACT_TACTICS
        )
        return min(10.0, count * 2.0)
