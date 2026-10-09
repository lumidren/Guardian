"""Unit tests for src/guardian/intelligence module."""

from guardian.intelligence.cross_device import CrossDeviceThreatIntelligence


def test_cross_device_intelligence_broadcast_and_quarantine() -> None:
    intel = CrossDeviceThreatIntelligence()
    indicators = intel.broadcast_attack(
        source_device_id="dev_cam_01",
        dest_ips=["198.51.100.22", "198.51.100.33"],
        dest_ports=[4444, 5555],
        attack_category="BOTNET_CNC",
        threat_score=85,
    )
    assert len(indicators) == 4
    assert "198.51.100.22" in intel.known_bad_ips
    assert 4444 in intel.known_bad_ports
    assert intel.is_known_threat_endpoint("198.51.100.22") is True
    assert intel.is_known_threat_endpoint("192.168.1.1") is False

    summary = intel.get_fleet_threat_summary()
    assert summary["blacklisted_ips_count"] == 2
    assert summary["total_shared_indicators"] == 4
