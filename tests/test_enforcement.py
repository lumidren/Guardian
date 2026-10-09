"""
Unit tests for Graduated Response controller, virtual firewall, and user overrides.
"""

import pytest
from guardian.config import ThreatLevel
from guardian.ml.threat_scorer import ThreatAssessment
from guardian.enforcement.controller import EnforcementController
from guardian.enforcement.virtual_driver import VirtualFirewallDriver


def test_virtual_firewall_graduated_response():
    driver = VirtualFirewallDriver()
    ip = "192.168.1.108"

    # 1. MONITOR: allows all
    driver.apply_policy(ip, ThreatLevel.MONITOR)
    assert driver.should_allow_packet(ip, "192.168.1.1")
    assert driver.should_allow_packet(ip, "8.8.8.8")

    # 2. RESTRICT: blocks WAN, allows local
    driver.apply_policy(ip, ThreatLevel.RESTRICT)
    assert driver.should_allow_packet(ip, "192.168.1.1")
    assert not driver.should_allow_packet(ip, "8.8.8.8")

    # 3. BLOCK: drops all traffic
    driver.apply_policy(ip, ThreatLevel.BLOCK)
    assert not driver.should_allow_packet(ip, "192.168.1.1")
    assert not driver.should_allow_packet(ip, "8.8.8.8")


def test_enforcement_controller_latency():
    controller = EnforcementController()
    assessment = ThreatAssessment(
        threat_score=92,
        threat_level=ThreatLevel.BLOCK,
        confidence_level="High (90-100%)",
        confidence_score=0.92,
        ml_score=0.9,
        statistical_score=0.9,
        layer_contributions={}
    )

    state = controller.enforce("dev_test", "192.168.1.108", assessment)
    assert state.current_level == ThreatLevel.BLOCK
    assert state.enforcement_latency_ms < 300.0  # Must be <300ms (0.3s requirement)

    # Test user override
    controller.override_manager.request_override("dev_test", "MONITOR")
    state_overridden = controller.enforce("dev_test", "192.168.1.108", assessment)
    assert state_overridden.current_level == ThreatLevel.MONITOR
    assert state_overridden.is_user_overridden
