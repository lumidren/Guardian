"""
Unified Graduated Response Enforcement Controller for GUARDIAN (Section 3.4).
Coordinates firewall rules across Linux iptables and virtual testbed tables.
"""

import time
from dataclasses import dataclass, field

from ..config import ThreatLevel, config
from ..ml.threat_scorer import ThreatAssessment
from .iptables_driver import LinuxIptablesDriver
from .overrides import UserOverrideManager
from .virtual_driver import VirtualFirewallDriver


@dataclass
class EnforcementState:
    device_id: str
    ip_address: str
    current_level: ThreatLevel
    threat_score: int
    enforcement_latency_ms: float
    last_enforced: float = field(default_factory=time.time)
    is_user_overridden: bool = False


class EnforcementController:
    def __init__(self, interface: str = config.GATEWAY_INTERFACE, local_subnet: str = config.LOCAL_SUBNET):
        self.iptables_driver = LinuxIptablesDriver(interface=interface, local_subnet=local_subnet)
        self.virtual_driver = VirtualFirewallDriver(local_subnet_prefix="192.168.1.")
        self.override_manager = UserOverrideManager()
        self.states: dict[str, EnforcementState] = {}

    def enforce(self, device_id: str, ip_address: str, assessment: ThreatAssessment) -> EnforcementState:
        """
        Enforce graduated response level for a device based on its threat score.
        Measures enforcement latency to ensure compliance with <0.3s requirement.
        """
        start = time.perf_counter()

        # Check for user manual override
        target_level = assessment.threat_level
        is_overridden = False

        if self.override_manager.is_overridden(device_id):
            override_str = self.override_manager.get_override_level(device_id)
            if override_str:
                target_level = ThreatLevel(override_str)
                is_overridden = True

        # Apply to virtual driver (always active for packet-level filtering simulation)
        self.virtual_driver.apply_policy(ip_address, target_level)

        # Apply to Linux iptables if present
        self.iptables_driver.apply_policy(ip_address, target_level)

        total_latency_ms = (time.perf_counter() - start) * 1000.0

        state = EnforcementState(
            device_id=device_id,
            ip_address=ip_address,
            current_level=target_level,
            threat_score=assessment.threat_score,
            enforcement_latency_ms=round(total_latency_ms, 2),
            last_enforced=time.time(),
            is_user_overridden=is_overridden
        )
        self.states[device_id] = state
        return state

    def get_state(self, device_id: str) -> EnforcementState | None:
        return self.states.get(device_id)
