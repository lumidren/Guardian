"""
High-performance virtual firewall driver for testbeds, simulators, and Windows environments.
Maintains stateful network filtering table with sub-millisecond policy execution.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Set
from ..config import ThreatLevel


@dataclass
class DeviceFilterState:
    ip_address: str
    threat_level: ThreatLevel = ThreatLevel.MONITOR
    bandwidth_limit_pct: float = 100.0
    wan_blocked: bool = False
    complete_drop: bool = False
    packets_dropped: int = 0
    packets_allowed: int = 0
    last_updated: float = field(default_factory=time.time)


class VirtualFirewallDriver:
    def __init__(self, local_subnet_prefix: str = "192.168.1."):
        self.local_subnet_prefix = local_subnet_prefix
        self.device_states: Dict[str, DeviceFilterState] = {}

    def apply_policy(self, ip_address: str, level: ThreatLevel) -> float:
        """
        Apply graduated policy in virtual firewall table.
        Returns execution latency in seconds (<0.001s).
        """
        start = time.perf_counter()
        state = self.device_states.get(ip_address)
        if not state:
            state = DeviceFilterState(ip_address=ip_address)
            self.device_states[ip_address] = state

        state.threat_level = level
        state.last_updated = time.time()

        if level == ThreatLevel.MONITOR:
            state.bandwidth_limit_pct = 100.0
            state.wan_blocked = False
            state.complete_drop = False
        elif level == ThreatLevel.RESTRICT:
            state.bandwidth_limit_pct = 50.0
            state.wan_blocked = True
            state.complete_drop = False
        elif level == ThreatLevel.QUARANTINE:
            state.bandwidth_limit_pct = 20.0
            state.wan_blocked = True
            state.complete_drop = False
        elif level == ThreatLevel.BLOCK:
            state.bandwidth_limit_pct = 0.0
            state.wan_blocked = True
            state.complete_drop = True

        latency = time.perf_counter() - start
        return latency

    def should_allow_packet(self, src_ip: str, dst_ip: str) -> bool:
        """Evaluate if an outbound packet is allowed under active policy."""
        state = self.device_states.get(src_ip)
        if not state or state.threat_level == ThreatLevel.MONITOR:
            if state:
                state.packets_allowed += 1
            return True

        if state.complete_drop:
            state.packets_dropped += 1
            return False

        if state.wan_blocked and not dst_ip.startswith(self.local_subnet_prefix):
            state.packets_dropped += 1
            return False

        state.packets_allowed += 1
        return True
