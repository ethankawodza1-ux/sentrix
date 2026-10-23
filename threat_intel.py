"""
SENTRIX -- Threat Intelligence Feed Integration
================================================
Simulates querying multiple threat intelligence sources and enriching
a DetectionEvent with feed-derived context.

In production each provider class would call a real REST API
(VirusTotal v3, AbuseIPDB v2, Shodan, AlienVault OTX, etc.).
Here a rich curated dataset mimics the kinds of results those APIs return
so the system can run standalone without API keys.

ThreatIntelFeed  (base)
  |- VirusTotalFeed
  |- AbuseIPDBFeed
  |- AlienVaultOTXFeed
  |- ShodanFeed
  |- InternalTIFeed      <- enterprise private feed

ThreatIntelAggregator   <- queries all feeds, merges, deduplicates
"""
from __future__ import annotations
import hashlib
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from .models import AttackType, DetectionEvent


# ─────────────────────────────────────────────────────────────────────────────
#  Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IOCMatch:
    """A single hit from one threat intelligence provider."""
    ioc_type:        str          # ip / domain / hash / url
    ioc_value:       str
    provider:        str
    malicious_votes: int          # number of engines / reporters flagging as malicious
    total_votes:     int          # total engines / reporters consulted
    confidence:      float        # 0.0 – 1.0
    threat_names:    List[str]    = field(default_factory=list)
    tags:            List[str]    = field(default_factory=list)
    first_seen:      Optional[datetime] = None
    last_seen:       Optional[datetime] = None
    country:         str          = "Unknown"
    asn:             str          = ""
    raw:             Dict[str, Any] = field(default_factory=dict)

    @property
    def malicious_ratio(self) -> float:
        return self.malicious_votes / self.total_votes if self.total_votes else 0.0

    def summary(self) -> str:
        return (f"[{self.provider}] {self.ioc_type}:{self.ioc_value}  "
                f"{self.malicious_votes}/{self.total_votes} malicious  "
                f"conf={self.confidence:.0%}  names={self.threat_names[:2]}")


@dataclass
class ThreatIntelReport:
    """Aggregated intel for a single DetectionEvent."""
    event_id:        str
    timestamp:       datetime
    ioc_matches:     List[IOCMatch]   = field(default_factory=list)
    known_threat_actor: Optional[str] = None
    campaign_name:   Optional[str]    = None
    threat_actor_nation: Optional[str]= None
    intel_severity_boost: float       = 0.0   # extra points to add to threat_score
    intel_confidence: float           = 0.0   # 0–1 overall feed confidence
    enrichment_notes: List[str]       = field(default_factory=list)

    @property
    def total_iocs_matched(self) -> int:
        return len(self.ioc_matches)

    @property
    def highest_confidence_match(self) -> Optional[IOCMatch]:
        return max(self.ioc_matches, key=lambda m: m.confidence, default=None)


# ─────────────────────────────────────────────────────────────────────────────
#  Simulated provider databases
# ─────────────────────────────────────────────────────────────────────────────

# Known-malicious IPs (simulated VT / AIPDB data)
_KNOWN_MALICIOUS_IPS: Dict[str, Dict] = {
    "185.220.101.33": {
        "vt_malicious": 52, "vt_total": 87,
        "abuseipdb_confidence": 97,
        "tags": ["ransomware", "c2", "tor-exit"],
        "threat_names": ["LockBit 3.0", "BlackCat/ALPHV"],
        "country": "DE", "asn": "AS205100 F3 Netze e.V.",
        "actor": "LockBit Group", "campaign": "LockBit 3.0 Global Campaign",
        "nation": "Russia",
    },
    "45.142.212.100": {
        "vt_malicious": 38, "vt_total": 72,
        "abuseipdb_confidence": 89,
        "tags": ["apt", "c2", "cobalt-strike"],
        "threat_names": ["Cobalt Strike Beacon", "APT29"],
        "country": "RU", "asn": "AS8359 MTS PJSC",
        "actor": "APT29 (Cozy Bear)", "campaign": "SolarWinds Follow-on",
        "nation": "Russia",
    },
    "203.0.113.50": {
        "vt_malicious": 44, "vt_total": 80,
        "abuseipdb_confidence": 93,
        "tags": ["exfiltration", "data-theft"],
        "threat_names": ["FIN7 Exfil Server"],
        "country": "CN", "asn": "AS4134 CHINANET-BACKBONE",
        "actor": "FIN7", "campaign": "FIN7 Financial Sector Campaign",
        "nation": "China",
    },
    "91.108.4.100": {
        "vt_malicious": 21, "vt_total": 60,
        "abuseipdb_confidence": 74,
        "tags": ["malware", "c2", "botnet"],
        "threat_names": ["Emotet C2", "TrickBot"],
        "country": "UA", "asn": "AS3261 Volia",
        "actor": "TA542 (Emotet Operators)", "campaign": "Emotet Epoch 5",
        "nation": "Unknown",
    },
    "62.122.184.55": {
        "vt_malicious": 15, "vt_total": 55,
        "abuseipdb_confidence": 68,
        "tags": ["phishing", "credential-harvesting"],
        "threat_names": ["EvilProxy Phishing Kit"],
        "country": "NL", "asn": "AS49981 WorldStream B.V.",
        "actor": "Unknown Phishing Actor", "campaign": "MFA Bypass Phishing Wave",
        "nation": "Unknown",
    },
    "172.16.4.8": {   # internal — zero-day lateral
        "vt_malicious": 0, "vt_total": 0,
        "abuseipdb_confidence": 0,
        "tags": ["internal", "zero-day"],
        "threat_names": [],
        "country": "Internal", "asn": "",
        "actor": None, "campaign": None, "nation": None,
    },
}

# Known-malicious file hashes (SHA-256 simulated)
_KNOWN_MALICIOUS_HASHES: Dict[str, Dict] = {
    # Ransomware payload hash
    "crypt_payload.exe": {
        "sha256": "e3b0c44298fc1c149afb" + "f4c8996fb92427ae41e4649b934ca495991b7852b855",
        "vt_malicious": 61, "vt_total": 72,
        "threat_names": ["LockBit.Ransomware", "Ransom:Win32/LockBit.C"],
        "tags": ["ransomware", "file-encryptor", "shadow-delete"],
        "first_seen": datetime.now() - timedelta(days=45),
    },
    "beacon.dll": {
        "sha256": "a" * 64,
        "vt_malicious": 48, "vt_total": 68,
        "threat_names": ["CobaltStrike.Beacon.4", "Backdoor:Win64/CobaltStrike"],
        "tags": ["rat", "c2", "cobalt-strike", "apt"],
        "first_seen": datetime.now() - timedelta(days=120),
    },
    "svchost32.exe": {
        "sha256": "b" * 64,
        "vt_malicious": 33, "vt_total": 70,
        "threat_names": ["Emotet.Dropper", "Trojan:Win32/Emotet.M"],
        "tags": ["trojan", "dropper", "persistence"],
        "first_seen": datetime.now() - timedelta(days=22),
    },
    ".hidden_payload.jar": {
        "sha256": "c" * 64,
        "vt_malicious": 29, "vt_total": 52,
        "threat_names": ["Log4Shell.Exploit", "CVE-2021-44228.Payload"],
        "tags": ["zero-day", "exploit", "java"],
        "first_seen": datetime.now() - timedelta(days=180),
    },
}

# Actor / campaign attribution by attack type (used when IP not in known list)
_ACTOR_ATTRIBUTION: Dict[AttackType, Dict] = {
    AttackType.RANSOMWARE:        {"actor": "LockBit Group",        "campaign": "LockBit 3.0",            "nation": "Russia"},
    AttackType.APT:               {"actor": "APT29 (Cozy Bear)",    "campaign": "SolarWinds Follow-on",   "nation": "Russia"},
    AttackType.LATERAL_MOVEMENT:  {"actor": "APT41",                "campaign": "Double Dragon Intrusion","nation": "China"},
    AttackType.DATA_EXFILTRATION: {"actor": "FIN7",                 "campaign": "FIN7 FinSec Campaign",   "nation": "Russia"},
    AttackType.PRIVILEGE_ESCALATION: {"actor": "Unknown",           "campaign": "Unknown",                "nation": "Unknown"},
    AttackType.DDOS:              {"actor": "Killnet",              "campaign": "Pro-Russia DDoS Wave",   "nation": "Russia"},
    AttackType.ZERO_DAY:          {"actor": "Lazarus Group",        "campaign": "Operation DreamJob",     "nation": "North Korea"},
    AttackType.MALWARE:           {"actor": "TA542 (Emotet)",       "campaign": "Emotet Epoch 5",         "nation": "Unknown"},
    AttackType.INSIDER_THREAT:    {"actor": "Malicious Insider",    "campaign": "N/A",                    "nation": "Internal"},
    AttackType.PHISHING:          {"actor": "TA453 (Charming Kitten)","campaign": "Spear-Phishing Wave",  "nation": "Iran"},
}


# ─────────────────────────────────────────────────────────────────────────────
#  Individual feed simulators
# ─────────────────────────────────────────────────────────────────────────────

class _VirusTotalFeed:
    name = "VirusTotal"

    def lookup_ip(self, ip: str) -> Optional[IOCMatch]:
        data = _KNOWN_MALICIOUS_IPS.get(ip)
        if not data or data["vt_total"] == 0:
            return None
        conf = data["vt_malicious"] / data["vt_total"]
        return IOCMatch(
            ioc_type="ip", ioc_value=ip, provider=self.name,
            malicious_votes=data["vt_malicious"], total_votes=data["vt_total"],
            confidence=conf,
            threat_names=data["threat_names"], tags=data["tags"],
            first_seen=datetime.now() - timedelta(days=random.randint(30, 365)),
            last_seen=datetime.now() - timedelta(hours=random.randint(1, 72)),
            country=data["country"], asn=data["asn"],
        )

    def lookup_hash(self, filename: str) -> Optional[IOCMatch]:
        for key, data in _KNOWN_MALICIOUS_HASHES.items():
            if key in filename:
                return IOCMatch(
                    ioc_type="hash", ioc_value=data["sha256"][:16] + "...",
                    provider=self.name,
                    malicious_votes=data["vt_malicious"], total_votes=data["vt_total"],
                    confidence=data["vt_malicious"] / data["vt_total"],
                    threat_names=data["threat_names"], tags=data["tags"],
                    first_seen=data["first_seen"], last_seen=datetime.now(),
                )
        return None


class _AbuseIPDBFeed:
    name = "AbuseIPDB"

    def lookup_ip(self, ip: str) -> Optional[IOCMatch]:
        data = _KNOWN_MALICIOUS_IPS.get(ip)
        if not data or data["abuseipdb_confidence"] == 0:
            return None
        conf = data["abuseipdb_confidence"] / 100
        return IOCMatch(
            ioc_type="ip", ioc_value=ip, provider=self.name,
            malicious_votes=data["abuseipdb_confidence"],
            total_votes=100,
            confidence=conf,
            threat_names=data["threat_names"],
            tags=data["tags"],
            country=data["country"], asn=data["asn"],
        )


class _AlienVaultOTXFeed:
    name = "AlienVault OTX"

    _PULSES: Dict[str, Dict] = {
        "185.220.101.33": {"pulse": "LockBit Ransomware IOCs Q4-2026", "tags": ["ransomware", "ioc"]},
        "45.142.212.100": {"pulse": "APT29 Cobalt Strike Infrastructure", "tags": ["apt", "cobalt-strike"]},
        "203.0.113.50":   {"pulse": "FIN7 Exfil Infrastructure 2026", "tags": ["fin7", "exfil"]},
    }

    def lookup_ip(self, ip: str) -> Optional[IOCMatch]:
        pulse = self._PULSES.get(ip)
        if not pulse:
            return None
        return IOCMatch(
            ioc_type="ip", ioc_value=ip, provider=self.name,
            malicious_votes=1, total_votes=1, confidence=0.82,
            threat_names=[pulse["pulse"]], tags=pulse["tags"],
        )


class _InternalTIFeed:
    """Simulates an enterprise STIX/TAXII internal feed."""
    name = "Internal TI (STIX/TAXII)"

    _WATCHLIST = {
        "185.220.101.33", "45.142.212.100", "203.0.113.50",
        "91.108.4.100", "62.122.184.55",
    }

    def lookup_ip(self, ip: str) -> Optional[IOCMatch]:
        if ip not in self._WATCHLIST:
            return None
        return IOCMatch(
            ioc_type="ip", ioc_value=ip, provider=self.name,
            malicious_votes=1, total_votes=1, confidence=0.90,
            threat_names=["Enterprise Watchlist Hit"],
            tags=["internal-ti", "watchlist"],
        )


# ─────────────────────────────────────────────────────────────────────────────
#  Public aggregator
# ─────────────────────────────────────────────────────────────────────────────

class ThreatIntelAggregator:
    """
    Queries all configured feeds for every IOC in a DetectionEvent
    and produces a consolidated ThreatIntelReport.
    """

    def __init__(self):
        self._vt       = _VirusTotalFeed()
        self._aipdb    = _AbuseIPDBFeed()
        self._otx      = _AlienVaultOTXFeed()
        self._internal = _InternalTIFeed()

    def enrich(self, event: DetectionEvent) -> ThreatIntelReport:
        matches: List[IOCMatch] = []
        notes:   List[str]     = []

        # -- IP lookups -------------------------------------------------------
        seen_ips: set = set()
        for net_ioc in event.network_indicators:
            for ip in (net_ioc.source_ip, net_ioc.dest_ip):
                if ip in seen_ips or ip.startswith(("10.", "192.168.", "172.")):
                    continue
                seen_ips.add(ip)
                for feed_result in [
                    self._vt.lookup_ip(ip),
                    self._aipdb.lookup_ip(ip),
                    self._otx.lookup_ip(ip),
                    self._internal.lookup_ip(ip),
                ]:
                    if feed_result:
                        matches.append(feed_result)
                        notes.append(
                            f"IP {ip} flagged by {feed_result.provider}: "
                            f"{feed_result.malicious_votes}/{feed_result.total_votes} "
                            f"malicious ({feed_result.confidence:.0%} conf) — "
                            + ", ".join(feed_result.threat_names[:2])
                        )

        # -- File hash lookups ------------------------------------------------
        for file_ioc in event.file_indicators:
            hit = self._vt.lookup_hash(file_ioc.path)
            if hit:
                matches.append(hit)
                notes.append(
                    f"File '{file_ioc.path.split('/')[-1].split(chr(92))[-1]}' "
                    f"matches known malware: "
                    + ", ".join(hit.threat_names[:2])
                    + f" ({hit.malicious_votes}/{hit.total_votes} engines)"
                )

        # -- Attribution ------------------------------------------------------
        attr = _ACTOR_ATTRIBUTION.get(event.attack_type, {})
        actor    = attr.get("actor")
        campaign = attr.get("campaign")
        nation   = attr.get("nation")

        # Override with IP-specific attribution when available
        for ip in seen_ips:
            ip_data = _KNOWN_MALICIOUS_IPS.get(ip, {})
            if ip_data.get("actor"):
                actor    = ip_data["actor"]
                campaign = ip_data["campaign"]
                nation   = ip_data["nation"]
                break

        if actor and actor != "Unknown":
            notes.append(
                f"Attribution: {actor} | Campaign: {campaign} | "
                f"Nation-state: {nation}"
            )

        # -- Severity boost from feed hits ------------------------------------
        boost = 0.0
        high_conf_hits = [m for m in matches if m.confidence >= 0.80]
        if high_conf_hits:
            boost += min(10.0, len(high_conf_hits) * 2.5)
            notes.append(
                f"{len(high_conf_hits)} high-confidence feed hit(s) detected. "
                f"Severity boost: +{boost:.1f}"
            )

        # Internal watchlist is a premium signal
        if any(m.provider == _InternalTIFeed.name for m in matches):
            boost += 5.0
            notes.append("Internal watchlist hit confirmed. Additional +5 severity boost.")

        # -- Overall intel confidence -----------------------------------------
        if matches:
            intel_conf = sum(m.confidence for m in matches) / len(matches)
        else:
            intel_conf = 0.0
            notes.append("No known IOCs found in threat intelligence feeds.")

        return ThreatIntelReport(
            event_id             = event.event_id,
            timestamp            = datetime.now(),
            ioc_matches          = matches,
            known_threat_actor   = actor,
            campaign_name        = campaign,
            threat_actor_nation  = nation,
            intel_severity_boost = boost,
            intel_confidence     = intel_conf,
            enrichment_notes     = notes,
        )
