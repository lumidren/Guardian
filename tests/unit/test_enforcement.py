"""Unit tests for src/guardian/enforcement module."""

from guardian.config import ThreatLevel
from guardian.enforcement.controller import EnforcementController
from guardian.enforcement.overrides import UserOverrideManager
from guardian.enforcement.virtual_driver import VirtualFirewallDriver
from guardian.ml.threat_scorer import ThreatAssessment


def test_virtual_firewall_driver_tiers() -> None:
    driver = VirtualFirewallDriver()
    ip = "192.168.1.50"

    # MONITOR: all packets allowed
    driver.apply_policy(ip, ThreatLevel.MONITOR)
    assert driver.should_allow_packet(ip, "192.168.1.1") is True
    assert driver.should_allow_packet(ip, "198.51.100.1") is True

    # RESTRICT: uncataloged WAN dropped
    driver.apply_policy(ip, ThreatLevel.RESTRICT)
    assert driver.should_allow_packet(ip, "192.168.1.1") is True
    assert driver.should_allow_packet(ip, "198.51.100.1") is False

    # QUARANTINE: WAN blocked, LAN permitted
    driver.apply_policy(ip, ThreatLevel.QUARANTINE)
    assert driver.should_allow_packet(ip, "192.168.1.1") is True
    assert driver.should_allow_packet(ip, "8.8.8.8") is False

    # BLOCK: all blocked
    driver.apply_policy(ip, ThreatLevel.BLOCK)
    assert driver.should_allow_packet(ip, "192.168.1.1") is False


def test_user_override_manager() -> None:
    mgr = UserOverrideManager()
    mgr.request_override("dev_sensor_01", new_level="MONITOR", note="False positive test")
    assert mgr.is_overridden("dev_sensor_01") is True
    assert mgr.get_override_level("dev_sensor_01") == "MONITOR"

    mgr.clear_override("dev_sensor_01")
    assert mgr.is_overridden("dev_sensor_01") is False


def test_enforcement_controller_applies_and_overrides() -> None:
    ctrl = EnforcementController()
    assessment = ThreatAssessment(
        threat_score=85,
        threat_level=ThreatLevel.QUARANTINE,
        confidence_level="High",
        confidence_score=0.95,
        ml_score=0.9,
        statistical_score=0.8,
        layer_contributions={"Layer 1": 55.0},
    )
    state = ctrl.enforce("dev_iot_01", "192.168.1.75", assessment)
    assert state.current_level == ThreatLevel.QUARANTINE
    assert state.is_user_overridden is False

    # With user override
    ctrl.override_manager.request_override("dev_iot_01", new_level="MONITOR")
    state_ov = ctrl.enforce("dev_iot_01", "192.168.1.75", assessment)
    assert state_ov.current_level == ThreatLevel.MONITOR
    assert state_ov.is_user_overridden is True
