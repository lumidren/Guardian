"""Unit tests for unique identifier generation utilities."""

from guardian.common.ids import (
    generate_action_id,
    generate_alert_id,
    generate_device_id,
    generate_uuid,
)


def test_id_generation_formats() -> None:
    """Verify generated identifier formats and prefixes."""
    u = generate_uuid()
    assert len(u) == 32

    alt = generate_alert_id()
    assert alt.startswith("alt_")
    assert len(alt) == 16

    act = generate_action_id()
    assert act.startswith("act_")
    assert len(act) == 16

    dev = generate_device_id("ESP32 Sensor 1")
    assert dev.startswith("esp32_sensor_1_")
