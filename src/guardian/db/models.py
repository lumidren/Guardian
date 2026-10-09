"""SQLAlchemy 2.0 ORM entities for GUARDIAN security platform.

Defines schemas for all 11 core tables specified in Section 7.4:
- devices
- windows
- profiles
- models
- detections
- alerts
- actions
- feedback
- drift_events
- destinations
- settings
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import Float, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base declarative class for all GUARDIAN persistence entities."""

    pass


class DeviceEntity(Base):
    """Monitored IoT device state and profile posture."""

    __tablename__ = "devices"

    device_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    mac: Mapped[str] = mapped_column(String(17), nullable=False)
    stage: Mapped[str] = mapped_column(String(32), default="observe", nullable=False)
    first_seen: Mapped[float] = mapped_column(Float, nullable=False)
    mode: Mapped[str] = mapped_column(String(32), default="observe", nullable=False)
    updated_at: Mapped[float] = mapped_column(Float, nullable=False)


class WindowEntity(Base):
    """Aggregated statistical feature vector over a sliding time window."""

    __tablename__ = "windows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    window_start: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    window_end: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    vector_json: Mapped[str] = mapped_column(Text, nullable=False)
    n_packets: Mapped[int] = mapped_column(Integer, nullable=False)
    quality_flags_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)

    __table_args__ = (Index("ix_windows_device_time", "device_id", "window_start", "window_end"),)

    def get_vector(self) -> list[float]:
        """Deserialize stored feature vector."""
        return json.loads(self.vector_json)  # type: ignore[no-any-return]

    def set_vector(self, vector: list[float]) -> None:
        """Serialize feature vector into JSON."""
        self.vector_json = json.dumps(vector)


class ProfileEntity(Base):
    """Versioned behavioral profile containing statistical baselines and priors."""

    __tablename__ = "profiles"

    device_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    profile_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[float] = mapped_column(Float, nullable=False)
    updated_at: Mapped[float] = mapped_column(Float, nullable=False)

    def get_profile(self) -> dict[str, Any]:
        """Return deserialized profile dictionary."""
        return json.loads(self.profile_json)  # type: ignore[no-any-return]

    def set_profile(self, data: dict[str, Any]) -> None:
        """Store serialized profile dictionary."""
        self.profile_json = json.dumps(data)


class ModelEntity(Base):
    """Trained machine learning model artifacts metadata and provenance."""

    __tablename__ = "models"

    model_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    model_type: Mapped[str] = mapped_column(String(32), default="iforest", nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    trained_at: Mapped[float] = mapped_column(Float, nullable=False)
    train_start_ts: Mapped[float] = mapped_column(Float, nullable=False)
    train_end_ts: Mapped[float] = mapped_column(Float, nullable=False)
    metrics_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)

    def get_metrics(self) -> dict[str, Any]:
        """Return model validation metrics."""
        return json.loads(self.metrics_json)  # type: ignore[no-any-return]


class DetectionEntity(Base):
    """Fine-grained multi-layer anomaly scoring per evaluated window."""

    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    window_end: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    ml_score: Mapped[float] = mapped_column(Float, nullable=False)
    stat_score: Mapped[float] = mapped_column(Float, nullable=False)
    net_score: Mapped[float] = mapped_column(Float, nullable=False)
    threat_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    level: Mapped[str] = mapped_column(String(32), nullable=False)
    top_features_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    triggers_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)

    __table_args__ = (Index("ix_detections_device_window", "device_id", "window_end"),)


class AlertEntity(Base):
    """High-confidence alert confirmed by the hysteresis engine."""

    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    opened_at: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    closed_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    peak_score: Mapped[float] = mapped_column(Float, nullable=False)
    level: Mapped[str] = mapped_column(String(32), nullable=False)
    explanation_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    explanation_text: Mapped[str] = mapped_column(Text, nullable=False)
    likely_attack_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    recommended_actions_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)


class ActionEntity(Base):
    """Enforcement and mitigation actions applied to network interfaces."""

    __tablename__ = "actions"

    action_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    level: Mapped[str] = mapped_column(String(32), nullable=False)
    backend: Mapped[str] = mapped_column(String(32), nullable=False)
    rules_applied_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    applied_at: Mapped[float] = mapped_column(Float, nullable=False)
    expires_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    reverted_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    overridden_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class FeedbackEntity(Base):
    """Operator analyst feedback and ground-truth validation records."""

    __tablename__ = "feedback"

    feedback_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    submitted_at: Mapped[float] = mapped_column(Float, nullable=False)


class DriftEventEntity(Base):
    """Statistical distribution drift evaluation records."""

    __tablename__ = "drift_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    detected_at: Mapped[float] = mapped_column(Float, nullable=False)
    drift_score: Mapped[float] = mapped_column(Float, nullable=False)
    p_value: Mapped[float] = mapped_column(Float, nullable=False)
    top_drifting_features_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending_review", nullable=False)


class DestinationEntity(Base):
    """Layer 2 communication partner destination tracking."""

    __tablename__ = "destinations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    first_seen: Mapped[float] = mapped_column(Float, nullable=False)
    last_seen: Mapped[float] = mapped_column(Float, nullable=False)
    count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)

    __table_args__ = (
        Index("ix_destinations_device_ip_port", "device_id", "dst_ip", "port", unique=True),
    )


class SettingEntity(Base):
    """Global configuration overrides and dynamic runtime flags."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value_json: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[float] = mapped_column(Float, nullable=False)

    def get_value(self) -> Any:
        """Return parsed JSON setting payload."""
        return json.loads(self.value_json)

    def set_value(self, val: Any) -> None:
        """Store serialized setting payload."""
        self.value_json = json.dumps(val)
