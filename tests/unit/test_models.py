"""Unit tests for GUARDIAN core Pydantic v2 data models and abstract interfaces."""

import pytest
from pydantic import ValidationError

from guardian.common.models import (
    Alert,
    AlertStatus,
    Detection,
    Device,
    DeviceMode,
    DeviceStage,
    DeviceType,
    EnforcementBackend,
    FeatureAttribution,
    GeoProvider,
    LikelyAttack,
    PacketDirection,
    PacketRecord,
    PhysicalIdentityProvider,
    ResponseAction,
    ResponseLevel,
    WindowFeatures,
)


def test_packet_record_valid() -> None:
    """PacketRecord creates properly with valid attributes."""
    pkt = PacketRecord(
        ts=1700000000.123,
        src_ip="192.168.1.50",
        dst_ip="192.168.1.1",
        src_port=1883,
        dst_port=52341,
        proto="tcp",
        length=128,
        tcp_flags="PA",
        direction="out",
        app_proto="mqtt",
        mqtt_topic="sensor/temperature",
        payload_len=45,
        device_id="esp32_sensor_01",
    )
    assert pkt.ts == 1700000000.123
    assert pkt.direction == PacketDirection.OUT
    assert pkt.app_proto == "mqtt"
    assert pkt.payload_len == 45


def test_packet_record_invalid() -> None:
    """PacketRecord enforces validation on ports and negative lengths."""
    with pytest.raises(ValidationError):
        PacketRecord(
            ts=100.0,
            src_ip="192.168.1.50",
            dst_ip="192.168.1.1",
            src_port=70000,  # Invalid port > 65535
            dst_port=80,
            proto="tcp",
            length=100,
            tcp_flags=None,
            direction="out",
            app_proto="http",
            mqtt_topic=None,
            payload_len=0,
            device_id="dev1",
        )


def test_device_model() -> None:
    """Device model validates stages, modes, and device types."""
    dev = Device(
        device_id="esp32_sensor_01",
        name="DHT22 Sensor Living Room",
        type="esp32_sensor",
        ip="192.168.1.50",
        mac="AA:BB:CC:DD:EE:01",
        stage="observe",
        first_seen=1700000000.0,
        mode="observe",
    )
    assert dev.type == DeviceType.ESP32_SENSOR
    assert dev.stage == DeviceStage.OBSERVE
    assert dev.mode == DeviceMode.OBSERVE


def test_window_features_validation() -> None:
    """WindowFeatures stores feature vector and quality flags."""
    vec = [0.0] * 60
    vec[0] = 12.0  # pkts_out
    names = [f"f_{i}" for i in range(60)]
    wf = WindowFeatures(
        device_id="esp32_sensor_01",
        window_start=100.0,
        window_end=110.0,
        vector=vec,
        feature_names=names,
        n_packets=25,
        quality_flags=["sparse_window"],
    )
    assert len(wf.vector) == 60
    assert wf.n_packets == 25
    assert "sparse_window" in wf.quality_flags


def test_detection_model_bounds() -> None:
    """Detection model validates scores strictly between 0 and 100."""
    attr = FeatureAttribution(
        name="byte_rate",
        value=15000.0,
        expected=200.0,
        robust_z=14.2,
        direction="higher",
    )
    det = Detection(
        device_id="esp32_sensor_01",
        window_end=110.0,
        ml_score=85.5,
        stat_score=92.0,
        net_score=45.0,
        threat_score=88.2,
        confidence=0.95,
        level="quarantine",
        top_features=[attr],
        triggers=["volume_spike_3sigma"],
    )
    assert det.level == ResponseLevel.QUARANTINE
    assert det.top_features[0].name == "byte_rate"

    with pytest.raises(ValidationError):
        # Threat score must be <= 100
        Detection(
            device_id="esp32_sensor_01",
            window_end=110.0,
            ml_score=150.0,  # Invalid > 100
            stat_score=0.0,
            net_score=0.0,
            threat_score=150.0,
            confidence=0.5,
            level="normal",
            top_features=[],
            triggers=[],
        )


def test_alert_and_response_action() -> None:
    """Alert and ResponseAction models validate correctly."""
    alert = Alert(
        alert_id="alt_01",
        device_id="esp32_sensor_01",
        opened_at=1000.0,
        closed_at=None,
        peak_score=89.5,
        level="quarantine",
        explanation={"primary_anomaly": "byte_rate_burst"},
        explanation_text="Anomalous burst of 15KB/s on telemetry device",
        likely_attack=LikelyAttack(label="mirai_c2_burst", confidence=0.88),
        recommended_actions=["quarantine_device", "inspect_c2_ip"],
        status="open",
    )
    assert alert.status == AlertStatus.OPEN
    assert alert.likely_attack.label == "mirai_c2_burst"

    action = ResponseAction(
        action_id="act_01",
        device_id="esp32_sensor_01",
        level="quarantine",
        backend="dryrun",
        rules_applied=["drop_non_mqtt_outbound", "rate_limit_10pps"],
        applied_at=1001.0,
        expires_at=4601.0,
        reverted_at=None,
        reason="Triggered by high confidence C2 burst alert alt_01",
        overridden_by=None,
    )
    assert action.backend == "dryrun"
    assert action.expires_at == 4601.0


def test_interfaces_are_abstract() -> None:
    """EnforcementBackend, GeoProvider, PhysicalIdentityProvider cannot be instantiated directly."""
    with pytest.raises(TypeError):
        EnforcementBackend()  # type: ignore[abstract]

    with pytest.raises(TypeError):
        GeoProvider()  # type: ignore[abstract]

    stub = PhysicalIdentityProvider()
    assert stub.score("any_device") is None
