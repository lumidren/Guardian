"""
Taxonomies, alert templates, and remediation actions for GUARDIAN Explainable AI.
Directly aligns with Section 3.3.2 and Table 8 in the GUARDIAN technical executive summary.
"""

from enum import Enum
from typing import Dict, List


class AttackClassification(str, Enum):
    DDOS_FLOODING = "DDoS Flooding"
    CNC_BEACONING = "Botnet C&C Communication"
    NETWORK_SCANNING = "Subnet Reconnaissance / Port Scan"
    DATA_EXFILTRATION = "Unauthorized Data Exfiltration"
    CRYPTOMINING = "Cryptomining Activity"
    ZERO_DAY_HYBRID = "Zero-Day Hybrid Attack"
    BENIGN_ANOMALY = "Unclassified Behavioral Deviation"


ATTACK_REMEDIATIONS: Dict[AttackClassification, List[str]] = {
    AttackClassification.DDOS_FLOODING: [
        "Isolate device immediately to protect local gateway bandwidth",
        "Inspect device firmware for Mirai or Bashlite botnet persistence",
        "Block outbound UDP/SYN bursts at router egress firewall",
        "Perform hardware factory reset and flash clean vendor firmware"
    ],
    AttackClassification.CNC_BEACONING: [
        "Keep device isolated from the external Internet",
        "Factory reset recommended to purge malware persistence",
        "Check manufacturer portal for urgent security firmware updates",
        "Add flagged C2 IP/domain to router blocklist"
    ],
    AttackClassification.NETWORK_SCANNING: [
        "Quarantine device into isolated guest VLAN immediately",
        "Prevent lateral movement to home computers or NAS storage",
        "Inspect open device ports and disable UPnP on local router",
        "Review router DHCP logs for unauthorized new MAC addresses"
    ],
    AttackClassification.DATA_EXFILTRATION: [
        "Sever camera/microphone device connection immediately",
        "Rotate local Wi-Fi passwords and device management credentials",
        "Verify camera RTSP/HTTP stream authentication settings",
        "Report destination endpoint to threat intelligence feeds"
    ],
    AttackClassification.CRYPTOMINING: [
        "Power cycle device and inspect running background processes",
        "Verify device CPU and thermal operating levels",
        "Update device default passwords (admin/root)",
        "Block known mining pool ports (3333, 4444, 14444) on gateway"
    ],
    AttackClassification.ZERO_DAY_HYBRID: [
        "Immediate graduated isolation active: Device fully blocked in <1 second",
        "Keep device disconnected from local network",
        "Contact device manufacturer regarding zero-day vulnerability",
        "Perform complete hardware factory reset before restoring network access"
    ],
    AttackClassification.BENIGN_ANOMALY: [
        "Monitor device behavior over next 24 hours",
        "If you performed a firmware update or reconfigured settings, click 'Approve & Retrain Baseline'",
        "No immediate blocking action required"
    ],
}
