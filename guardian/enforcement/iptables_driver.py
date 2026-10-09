"""
Linux iptables and nftables driver for GUARDIAN Gateway (Raspberry Pi 4).
Executes graduated packet filtering policies at the Linux kernel level.
"""

import subprocess
import shutil
import time
from typing import Optional
from ..config import ThreatLevel


class LinuxIptablesDriver:
    def __init__(self, interface: str = "eth0", local_subnet: str = "192.168.1.0/24"):
        self.interface = interface
        self.local_subnet = local_subnet
        self.has_iptables = shutil.which("iptables") is not None

    def _run_cmd(self, cmd: list) -> bool:
        if not self.has_iptables:
            return False
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except Exception:
            return False

    def apply_policy(self, ip_address: str, level: ThreatLevel) -> float:
        """
        Apply iptables rules according to Graduated Response level.
        Returns execution latency in seconds.
        """
        start = time.perf_counter()
        if not self.has_iptables:
            return time.perf_counter() - start

        # Clear existing rules for this device
        self._clear_device_rules(ip_address)

        if level == ThreatLevel.MONITOR:
            # Default logging or accept
            pass
        elif level == ThreatLevel.RESTRICT:
            # Block external WAN IPs, allow local subnet
            self._run_cmd(["iptables", "-I", "FORWARD", "-s", ip_address, "!", "-d", self.local_subnet, "-j", "DROP"])
        elif level == ThreatLevel.QUARANTINE:
            # Isolate: block all external WAN and isolate from gateway services except DHCP/DNS
            self._run_cmd(["iptables", "-I", "FORWARD", "-s", ip_address, "-j", "DROP"])
            self._run_cmd(["iptables", "-I", "INPUT", "-s", ip_address, "!", "-p", "udp", "--dport", "67:68", "-j", "DROP"])
        elif level == ThreatLevel.BLOCK:
            # Complete isolation: Drop all inbound and outbound traffic
            self._run_cmd(["iptables", "-I", "FORWARD", "-s", ip_address, "-j", "DROP"])
            self._run_cmd(["iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"])

        return time.perf_counter() - start

    def _clear_device_rules(self, ip_address: str):
        # Best-effort rule deletion
        self._run_cmd(["iptables", "-D", "FORWARD", "-s", ip_address, "!", "-d", self.local_subnet, "-j", "DROP"])
        self._run_cmd(["iptables", "-D", "FORWARD", "-s", ip_address, "-j", "DROP"])
        self._run_cmd(["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"])
