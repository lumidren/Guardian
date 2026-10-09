"""
Cross-Device Threat Intelligence Engine for GUARDIAN (Section 9.2).
Propagates detected Indicators of Compromise (IOCs) across all protected IoT devices on the local gateway.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional


@dataclass
class ThreatIndicator:
    ioc_type: str            # "IP_DESTINATION", "PORT_TARGET", "PROTOCOL_SIGNATURE"
    ioc_value: str           # e.g., "185.220.101.47", "4444"
    source_device_id: str
    attack_category: str
    threat_score: int
    detected_at: float = field(default_factory=time.time)
    reputation_score: float = 1.0  # 1.0 = malicious


class CrossDeviceThreatIntelligence:
    def __init__(self):
        self.known_bad_ips: Set[str] = set()
        self.known_bad_ports: Set[int] = set()
        self.active_indicators: List[ThreatIndicator] = []
        # device_id -> set of blocked remote endpoints
        self.device_firewall_rules: Dict[str, Set[str]] = {}

    def broadcast_attack(
        self,
        source_device_id: str,
        dest_ips: List[str],
        dest_ports: List[int],
        attack_category: str,
        threat_score: int
    ) -> List[ThreatIndicator]:
        """
        Ingest an attack from one device and generate fleet-wide indicators.
        """
        new_indicators = []
        for ip in dest_ips:
            if ip not in self.known_bad_ips and not ip.startswith("192.168.1.") and ip != "255.255.255.255":
                self.known_bad_ips.add(ip)
                indicator = ThreatIndicator(
                    ioc_type="IP_DESTINATION",
                    ioc_value=ip,
                    source_device_id=source_device_id,
                    attack_category=attack_category,
                    threat_score=threat_score
                )
                self.active_indicators.append(indicator)
                new_indicators.append(indicator)

        for port in dest_ports:
            if port in (23, 2323, 4444, 5555, 6667, 31337) and port not in self.known_bad_ports:
                self.known_bad_ports.add(port)
                indicator = ThreatIndicator(
                    ioc_type="PORT_TARGET",
                    ioc_value=str(port),
                    source_device_id=source_device_id,
                    attack_category=attack_category,
                    threat_score=threat_score
                )
                self.active_indicators.append(indicator)
                new_indicators.append(indicator)

        return new_indicators

    def is_known_threat_endpoint(self, ip: str) -> bool:
        """Check if an endpoint is already blacklisted by cross-device intelligence."""
        return ip in self.known_bad_ips

    def get_fleet_threat_summary(self) -> Dict[str, any]:
        return {
            "total_shared_indicators": len(self.active_indicators),
            "blacklisted_ips_count": len(self.known_bad_ips),
            "blacklisted_ips": list(self.known_bad_ips),
            "suspicious_ports": list(self.known_bad_ports),
            "recent_indicators": [
                {
                    "type": ind.ioc_type,
                    "value": ind.ioc_value,
                    "source": ind.source_device_id,
                    "attack": ind.attack_category,
                    "score": ind.threat_score
                }
                for ind in self.active_indicators[-10:]
            ]
        }
