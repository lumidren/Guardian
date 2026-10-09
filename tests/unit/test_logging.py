"""Unit tests for GUARDIAN structured logging system."""

import io
import json

from guardian.common.logging import get_logger, setup_logging


def test_structured_json_logging() -> None:
    """setup_logging in json mode renders structured JSON entries."""
    stream = io.StringIO()
    setup_logging(json_logs=True, log_level="INFO", stream=stream)

    logger = get_logger("guardian.test")
    bound = logger.bind(device_id="esp32_sensor_01", stage="ml")
    bound.info("Telemetry processed", pkts=42, score=12.5)

    output = stream.getvalue().strip()
    assert output != ""
    record = json.loads(output)
    assert record["event"] == "Telemetry processed"
    assert record["device_id"] == "esp32_sensor_01"
    assert record["stage"] == "ml"
    assert record["pkts"] == 42
    assert record["score"] == 12.5
    assert "timestamp" in record
    assert record["level"] == "info"


def test_console_logging() -> None:
    """setup_logging in console mode outputs readable text."""
    stream = io.StringIO()
    setup_logging(json_logs=False, log_level="DEBUG", stream=stream)

    logger = get_logger("guardian.console")
    logger.debug("Debug event message", test_key="val123")

    output = stream.getvalue()
    assert "Debug event message" in output
    assert "val123" in output
