"""
SENTRIX — Digital Evidence Collection Module
==============================================
Identifies, ranks, and (simulates) capturing volatile evidence
before a containment action could destroy it.

Evidence is ranked from most-volatile (rank 1) to least-volatile (rank 5)
following the RFC 3227 / NIST 800-86 order of volatility:

  1 → CPU registers, routing tables, ARP cache, process table, kernel stats
  2 → Active network connections, login sessions, open files
  3 → Memory dumps (RAM)
  4 → Running process images on disk
  5 → Disk, file system, remote logs
"""
from __future__ import annotations
import uuid
from datetime import datetime
from typing import List

from .models import AttackType, DetectionEvent, EvidenceItem


# ──────────────────────────────────────────────────────────────────────────────
#  Evidence catalogue keyed by attack type
# ──────────────────────────────────────────────────────────────────────────────

_EVIDENCE_CATALOGUE: dict[AttackType, List[dict]] = {
    AttackType.RANSOMWARE: [
        {"category": "memory",  "desc": "Full RAM dump — encryption keys may still reside in memory",              "vol": 1, "method": "winpmem / avml",          "size": 8_589_934_592},
        {"category": "process", "desc": "Running process list with handles and open files",                        "vol": 2, "method": "Process Explorer snapshot", "size":       200_000},
        {"category": "network", "desc": "Active C2 network connections (pre-kill)",                                "vol": 2, "method": "netstat -anob capture",     "size":        10_000},
        {"category": "file",    "desc": "Copy of encrypted file samples + ransom note",                           "vol": 4, "method": "Forensic file copy",         "size":    5_000_000},
        {"category": "log",     "desc": "Windows Event Logs (Security, System, Application)",                     "vol": 5, "method": "wevtutil export",            "size":  200_000_000},
        {"category": "file",    "desc": "VSS shadow copy inventory (before vssadmin wipes them)",                 "vol": 1, "method": "vssadmin list shadows",      "size":        50_000},
    ],
    AttackType.APT: [
        {"category": "memory",  "desc": "Full memory dump — injected shellcode / in-memory implants",             "vol": 1, "method": "avml / LiME",               "size": 8_589_934_592},
        {"category": "network", "desc": "Active TLS sessions and C2 beaconing traffic (PCAP)",                    "vol": 2, "method": "tcpdump / Wireshark",        "size":  500_000_000},
        {"category": "process", "desc": "Process tree and loaded DLLs / modules",                                 "vol": 2, "method": "Volatility pstree + dlllist", "size":       300_000},
        {"category": "file",    "desc": "Persistence artefacts (scheduled tasks, registry run keys, WMI subs)",  "vol": 3, "method": "Registry / task export",     "size":     2_000_000},
        {"category": "log",     "desc": "PowerShell transcription logs, SIEM raw events",                        "vol": 5, "method": "Log export + hashing",        "size": 1_000_000_000},
        {"category": "file",    "desc": "Beacon DLL and any dropped implants",                                    "vol": 4, "method": "Forensic file copy + hash",   "size":    10_000_000},
    ],
    AttackType.LATERAL_MOVEMENT: [
        {"category": "network", "desc": "Current SMB sessions and authenticated users on remote hosts",           "vol": 1, "method": "net session / netsess",      "size":         5_000},
        {"category": "memory",  "desc": "LSASS memory — credential material (NTLM hashes, Kerberos tickets)",    "vol": 1, "method": "procdump -ma lsass",          "size":    50_000_000},
        {"category": "process", "desc": "Remote process creations via WMI / PsExec",                             "vol": 2, "method": "WMI event log query",          "size":       100_000},
        {"category": "log",     "desc": "Security event logs from all pivoted hosts (4624, 4648, 4688)",         "vol": 5, "method": "wevtutil remote export",       "size":  500_000_000},
        {"category": "file",    "desc": "Dropped lateral movement tools (psexec, wce, mimikatz)",                "vol": 4, "method": "Forensic copy + hash",         "size":    20_000_000},
    ],
    AttackType.DATA_EXFILTRATION: [
        {"category": "network", "desc": "Active upload session metadata (bytes/s, dest IP, TLS cert)",           "vol": 1, "method": "ss -tp / pcap sample",        "size":     1_000_000},
        {"category": "file",    "desc": "Staged archive (zip/tar) before deletion",                              "vol": 2, "method": "dd + sha256",                  "size":   500_000_000},
        {"category": "file",    "desc": "Source data files that were accessed / copied",                         "vol": 3, "method": "Forensic copy + MFT entry",    "size":   200_000_000},
        {"category": "log",     "desc": "DLP / proxy logs showing destination and transfer volume",              "vol": 5, "method": "Log export",                   "size":    50_000_000},
        {"category": "network", "desc": "Full PCAP of the exfiltration session",                                 "vol": 2, "method": "tcpdump ring-buffer",          "size": 2_000_000_000},
    ],
    AttackType.PRIVILEGE_ESCALATION: [
        {"category": "memory",  "desc": "Exploit shellcode in memory — evidence of CVE used",                    "vol": 1, "method": "LiME kernel module",           "size": 4_294_967_296},
        {"category": "process", "desc": "UID change event and parent-child process chain",                       "vol": 1, "method": "auditd + pstree snapshot",     "size":        20_000},
        {"category": "file",    "desc": "Exploit binary on disk",                                                "vol": 3, "method": "Forensic copy + sha256",       "size":     2_000_000},
        {"category": "log",     "desc": "auth.log / /var/log/secure entries showing uid transition",             "vol": 5, "method": "Log copy + hash",              "size":    10_000_000},
    ],
    AttackType.DDOS: [
        {"category": "network", "desc": "Real-time traffic sample (source IPs, packet rates, vectors)",         "vol": 1, "method": "tcpdump / netflow export",     "size":   100_000_000},
        {"category": "log",     "desc": "Web-server / load-balancer access logs (DDoS fingerprint)",            "vol": 5, "method": "Log export",                   "size":  500_000_000},
        {"category": "network", "desc": "Amplification reflector list (DNS/NTP source IPs)",                    "vol": 2, "method": "PCAP analysis",                "size":    50_000_000},
    ],
    AttackType.ZERO_DAY: [
        {"category": "memory",  "desc": "Full heap dump — exploit payload and ROP chain",                        "vol": 1, "method": "gcore / jmap",                 "size":   512_000_000},
        {"category": "network", "desc": "Malicious HTTP request that triggered the exploit",                     "vol": 1, "method": "Web-server access log + PCAP", "size":       500_000},
        {"category": "file",    "desc": "Dropped webshell and payload JAR",                                      "vol": 3, "method": "Forensic copy",                "size":    10_000_000},
        {"category": "log",     "desc": "Application server logs (full verbosity)",                             "vol": 5, "method": "Log export",                   "size":  200_000_000},
        {"category": "process", "desc": "Running Tomcat / JVM heap snapshot",                                   "vol": 2, "method": "jmap heapdump",                "size":   256_000_000},
    ],
    AttackType.MALWARE: [
        {"category": "memory",  "desc": "Process memory of malware PID",                                         "vol": 1, "method": "procdump / memdump",           "size":   256_000_000},
        {"category": "process", "desc": "Handles, loaded DLLs, and injected regions",                           "vol": 2, "method": "Process Hacker snapshot",      "size":        50_000},
        {"category": "file",    "desc": "Malware binary + any dropped payloads",                                 "vol": 3, "method": "Forensic copy + hash",         "size":     5_000_000},
        {"category": "log",     "desc": "Windows Defender / AV quarantine logs",                                "vol": 5, "method": "Log export",                   "size":    20_000_000},
    ],
    AttackType.INSIDER_THREAT: [
        {"category": "network", "desc": "USB device event log (VID/PID, mount time, device serial)",            "vol": 1, "method": "usbview / registry key dump",  "size":         5_000},
        {"category": "file",    "desc": "MFT entry for copied files (creation timestamp, size)",                 "vol": 2, "method": "$MFT forensic copy",           "size":   300_000_000},
        {"category": "log",     "desc": "DLP alert details and file access audit trail",                        "vol": 5, "method": "SIEM log export",               "size":    10_000_000},
        {"category": "file",    "desc": "Source files that were copied / exfiltrated",                          "vol": 3, "method": "Forensic copy + hash",         "size":   100_000_000},
    ],
    AttackType.PHISHING: [
        {"category": "memory",  "desc": "Browser process memory — cached credentials / session tokens",          "vol": 1, "method": "procdump chrome/edge PID",     "size":   512_000_000},
        {"category": "network", "desc": "Phishing URL and HTTP redirect chain",                                  "vol": 2, "method": "Browser history + PCAP",       "size":         5_000},
        {"category": "file",    "desc": "Malicious attachment / downloaded dropper",                             "vol": 3, "method": "Forensic copy + hash",         "size":     2_000_000},
        {"category": "log",     "desc": "Email server headers (received-from chain)",                           "vol": 5, "method": "EML header export",             "size":       500_000},
    ],
}


class EvidenceCollector:
    """
    Identifies the evidence items relevant to a detection event and
    (simulates) capturing them in priority order.
    """

    def collect(self, event: DetectionEvent) -> List[EvidenceItem]:
        """
        Return a list of EvidenceItem objects for the given event,
        ordered from most to least volatile.
        All items are marked as 'captured' with a realistic method.
        """
        catalogue = _EVIDENCE_CATALOGUE.get(event.attack_type, [])

        items: List[EvidenceItem] = []
        for entry in sorted(catalogue, key=lambda x: x["vol"]):
            item = EvidenceItem(
                evidence_id     = f"EV-{uuid.uuid4().hex[:6].upper()}",
                category        = entry["category"],
                description     = entry["desc"],
                volatility_rank = entry["vol"],
                captured        = True,          # simulate successful capture
                capture_method  = entry["method"],
                size_bytes      = entry["size"],
                timestamp       = datetime.now(),
            )
            items.append(item)

        return items

    @staticmethod
    def total_size_mb(items: List[EvidenceItem]) -> float:
        return sum(i.size_bytes for i in items) / 1_048_576
