"""Authoritative configuration system for GUARDIAN (Appendix A).

Loads parameters from `config/guardian.yaml`, allows environment variable
overrides prefixed with `GUARDIAN_`, and enforces strict Pydantic v2 validation.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)


class WindowConfig(BaseModel):
    """Sliding time-window configuration."""

    length_s: float = Field(default=10.0, gt=0, description="Window duration in seconds")
    stride_s: float = Field(default=2.0, gt=0, description="Window advance step in seconds")


class StagesConfig(BaseModel):
    """Cold-start progressive profiling thresholds."""

    rules_hours: float = Field(default=24.0, ge=0, description="Rule-based heuristic period")
    statistical_hours: float = Field(default=24.0, ge=0, description="Statistical baseline period")
    ml_min_samples: int = Field(default=20000, gt=0, description="Minimum normal samples for ML")


class RobustZConfig(BaseModel):
    """Robust Z-Score detector parameters."""

    threshold: float = Field(default=3.5, gt=0, description="MAD standard deviation threshold")
    clip: float = Field(default=20.0, gt=0, description="Maximum clipped Z-score")
    top_k: int = Field(default=5, gt=0, description="Top anomalous features to report")


class IForestConfig(BaseModel):
    """Isolation Forest anomaly detector parameters."""

    n_estimators: int = Field(default=200, gt=0, description="Number of isolation trees")
    max_samples: str | int | float = Field(default="auto", description="Subsample size per tree")
    seed: int = Field(default=42, description="Random seed for reproducibility")
    holdout_fraction: float = Field(
        default=0.2, gt=0.0, lt=1.0, description="Validation calibration fraction"
    )


class FusionWeightsConfig(BaseModel):
    """Multi-layer anomaly score fusion weights (must sum to ~1.0)."""

    ml: float = Field(default=0.5, ge=0.0, le=1.0)
    stat: float = Field(default=0.3, ge=0.0, le=1.0)
    net: float = Field(default=0.2, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_sum(self) -> FusionWeightsConfig:
        total = self.ml + self.stat + self.net
        if abs(total - 1.0) > 1e-3:
            raise ValueError(f"Fusion weights must sum to 1.0 (got {total:.3f})")
        return self


class HysteresisConfig(BaseModel):
    """k-of-n sliding window confirmation and calm-down parameters."""

    k: int = Field(default=2, ge=1, description="Threshold violations required for alert")
    n: int = Field(default=3, ge=1, description="Window evaluation history length")
    calm_windows: int = Field(default=15, ge=1, description="Quiet windows required to de-escalate")


class DetectionConfig(BaseModel):
    """Detection pipeline configuration."""

    robust_z: RobustZConfig = Field(default_factory=RobustZConfig)
    iforest: IForestConfig = Field(default_factory=IForestConfig)
    fusion_weights: FusionWeightsConfig = Field(default_factory=FusionWeightsConfig)
    hysteresis: HysteresisConfig = Field(default_factory=HysteresisConfig)


class LevelsConfig(BaseModel):
    """Threat score cutoff boundaries for graduated response."""

    monitor_max: float = Field(default=30.0, ge=0.0, le=100.0)
    restrict_max: float = Field(default=60.0, ge=0.0, le=100.0)
    quarantine_max: float = Field(default=85.0, ge=0.0, le=100.0)


class TtlConfig(BaseModel):
    """Time-to-live in seconds for active containment levels."""

    restrict: int | None = Field(default=900, description="15 minutes containment")
    quarantine: int | None = Field(default=3600, description="1 hour containment")
    block: int | None = Field(default=None, description="Persistent manual block")


class ResponseConfig(BaseModel):
    """Enforcement engine mode and parameters."""

    mode: str = Field(default="observe", description="'observe' (dry-run) or 'enforce' (active)")
    backend: str = Field(default="dryrun", description="'dryrun', 'nftables', or 'sim'")
    ttl_s: TtlConfig = Field(default_factory=TtlConfig)
    protected_addresses: list[str] = Field(
        default_factory=list, description="Whitelisted IPs/subnets"
    )


class NetworkIdentityConfig(BaseModel):
    """Layer 2 communication baseline learning thresholds."""

    known_after_windows: int = Field(default=20, ge=1)
    known_after_hours: int = Field(default=2, ge=0)


class DriftConfig(BaseModel):
    """Concept drift detection and adaptation schedule."""

    check_every_h: int = Field(default=168, ge=1, description="Weekly scheduled drift check")
    auto_pct: float = Field(default=10.0, ge=0.0, le=100.0, description="Auto-retrain threshold")
    ask_pct: float = Field(default=30.0, ge=0.0, le=100.0, description="Human review threshold")


class SourceConfig(BaseModel):
    """Traffic intake source specification."""

    type: str = Field(default="simulator", description="'simulator', 'pcap', or 'live'")
    scenario: str = Field(default="scenarios/default.yaml", description="Scenario recipe path")
    speed: str = Field(default="fast", description="'fast' or 'realtime'")


class ApiConfig(BaseModel):
    """FastAPI service endpoints and runtime options."""

    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000, ge=1, le=65535)
    demo_mode: bool = Field(default=False)


class GeoConfig(BaseModel):
    """IP Geolocation and ASN lookup provider."""

    provider: str | None = Field(default=None)
    db_path: str | None = Field(default=None)


class DatabaseConfig(BaseModel):
    """SQLite engine settings."""

    url: str = Field(default="sqlite:///guardian.db", description="Database connection URL")
    echo: bool = Field(default=False, description="SQL statement logging")
    wal_mode: bool = Field(default=True, description="Enable Write-Ahead Logging (WAL)")


class GuardianConfig(BaseSettings):
    """Root configuration object for the GUARDIAN security platform."""

    model_config = SettingsConfigDict(
        extra="ignore",
        env_prefix="GUARDIAN_",
        env_nested_delimiter="__",
    )

    window: WindowConfig = Field(default_factory=WindowConfig)
    stages: StagesConfig = Field(default_factory=StagesConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    levels: LevelsConfig = Field(default_factory=LevelsConfig)
    response: ResponseConfig = Field(default_factory=ResponseConfig)
    network_identity: NetworkIdentityConfig = Field(default_factory=NetworkIdentityConfig)
    drift: DriftConfig = Field(default_factory=DriftConfig)
    source: SourceConfig = Field(default_factory=SourceConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    geo: GeoConfig = Field(default_factory=GeoConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        init_kwargs = getattr(init_settings, "init_kwargs", {}) or {}
        yaml_path = init_kwargs.get("_yaml_file")
        if not yaml_path:
            yaml_path = os.environ.get("GUARDIAN_CONFIG_FILE", "config/guardian.yaml")

        if yaml_path and os.path.exists(yaml_path):
            return (
                init_settings,
                env_settings,
                YamlConfigSettingsSource(settings_cls, yaml_file=yaml_path),
            )
        return (init_settings, env_settings)


def load_config(path: str | Path | None = None, **overrides: Any) -> GuardianConfig:
    """Load configuration from file or defaults with env variable overrides."""
    kwargs: dict[str, Any] = dict(overrides)
    if path is not None:
        kwargs["_yaml_file"] = str(path)
    return GuardianConfig(**kwargs)
