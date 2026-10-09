"""Unit tests for GUARDIAN configuration system and validation."""

import os

import pytest
from pydantic import ValidationError

from guardian.common.config import GuardianConfig, load_config


def test_default_config_matches_spec() -> None:
    """Default configuration matches Appendix A values."""
    config = GuardianConfig()
    assert config.window.length_s == 10.0
    assert config.window.stride_s == 2.0
    assert config.stages.ml_min_samples == 20000
    assert config.detection.robust_z.threshold == 3.5
    assert config.detection.iforest.n_estimators == 200
    assert config.detection.fusion_weights.ml == 0.5
    assert config.detection.fusion_weights.stat == 0.3
    assert config.detection.fusion_weights.net == 0.2
    assert config.detection.hysteresis.k == 2
    assert config.detection.hysteresis.n == 3
    assert config.levels.quarantine_max == 85.0
    assert config.response.mode == "observe"
    assert config.response.backend == "dryrun"
    assert config.response.ttl_s.restrict == 900
    assert config.response.ttl_s.block is None
    assert config.database.wal_mode is True


def test_load_from_yaml_file() -> None:
    """Config loads accurately from config/guardian.yaml."""
    yaml_path = "config/guardian.yaml"
    if not os.path.exists(yaml_path):
        pytest.skip("config/guardian.yaml not found at expected path")

    cfg = load_config(yaml_path)
    assert cfg.window.length_s == 10.0
    assert cfg.stages.rules_hours == 24.0
    assert cfg.api.port == 8000


def test_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Environment variables with prefix GUARDIAN_ override file settings."""
    monkeypatch.setenv("GUARDIAN_API__PORT", "9999")
    monkeypatch.setenv("GUARDIAN_WINDOW__LENGTH_S", "20.0")

    cfg = load_config()
    assert cfg.api.port == 9999
    assert cfg.window.length_s == 20.0


def test_invalid_config_validation() -> None:
    """Invalid configuration values raise ValidationError."""
    with pytest.raises(ValidationError):
        # Window length cannot be non-positive
        GuardianConfig(window={"length_s": -5.0, "stride_s": 2.0})  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        # Fusion weights must sum approximately to 1.0
        GuardianConfig(
            detection={"fusion_weights": {"ml": 0.9, "stat": 0.5, "net": 0.5}}  # type: ignore[arg-type]
        )
