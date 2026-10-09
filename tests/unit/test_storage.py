"""
Unit tests for GUARDIAN storage and database manager.
"""

from pathlib import Path

from guardian.storage.database import DatabaseManager
from guardian.storage.models import Alert, SystemMetric


def test_database_initialization(tmp_path: Path) -> None:
    db_file = tmp_path / "test_guardian.db"
    _ = DatabaseManager(db_path=db_file)
    assert db_file.exists()


def test_upsert_device(tmp_path: Path) -> None:
    db_file = tmp_path / "test_guardian.db"
    db_mgr = DatabaseManager(db_path=db_file)

    device = db_mgr.upsert_device(
        device_id="AA:BB:CC:DD:EE:01",
        name="Smart Plug Living Room",
        device_type="Plug",
        ip_address="192.168.1.50",
        mac_address="AA:BB:CC:DD:EE:01",
        hardware="ESP8266",
        threat_level="MONITOR",
        current_threat_score=10,
        confidence_level="High (90-100%)",
    )
    assert device.id == "AA:BB:CC:DD:EE:01"
    assert device.name == "Smart Plug Living Room"
    assert device.current_threat_score == 10

    # Test update existing device
    updated_device = db_mgr.upsert_device(
        device_id="AA:BB:CC:DD:EE:01",
        name="Smart Plug Living Room Updated",
        device_type="Plug",
        ip_address="192.168.1.50",
        mac_address="AA:BB:CC:DD:EE:01",
        hardware="ESP8266",
        threat_level="RESTRICT",
        current_threat_score=45,
    )
    assert updated_device.name == "Smart Plug Living Room Updated"
    assert updated_device.threat_level == "RESTRICT"
    assert updated_device.current_threat_score == 45

    all_devices = db_mgr.get_all_devices()
    assert len(all_devices) == 1
    assert all_devices[0]["name"] == "Smart Plug Living Room Updated"


def test_record_alert_and_query(tmp_path: Path) -> None:
    db_file = tmp_path / "test_guardian.db"
    db_mgr = DatabaseManager(db_path=db_file)

    alert = db_mgr.record_alert(
        device_id="AA:BB:CC:DD:EE:02",
        device_name="IP Camera Front Door",
        threat_score=85,
        threat_level="QUARANTINE",
        confidence_level="High (95%)",
        likely_attack="SYN Flood",
        details_json='{"syn_rate": 1500, "entropy": 7.8}',
        plain_text_summary="High volume SYN flood detected from IP Camera",
    )
    assert isinstance(alert, Alert)
    assert alert.threat_score == 85
    assert alert.likely_attack == "SYN Flood"

    recent_alerts = db_mgr.get_recent_alerts(limit=10)
    assert len(recent_alerts) == 1
    assert recent_alerts[0]["device_id"] == "AA:BB:CC:DD:EE:02"
    assert "syn_rate" in recent_alerts[0]["details_json"]


def test_record_system_metrics(tmp_path: Path) -> None:
    db_file = tmp_path / "test_guardian.db"
    db_mgr = DatabaseManager(db_path=db_file)

    metric = db_mgr.record_system_metric(
        cpu_usage_pct=15.5,
        ram_usage_mb=120.4,
        detection_latency_ms=12.3,
        enforcement_latency_ms=0.8,
        active_devices_count=5,
    )
    assert isinstance(metric, SystemMetric)
    assert metric.cpu_usage_pct == 15.5

    recent_metrics = db_mgr.get_recent_metrics(limit=5)
    assert len(recent_metrics) == 1
    assert recent_metrics[0]["active_devices_count"] == 5
