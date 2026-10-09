"""Database repository providing transactional CRUD operations for GUARDIAN."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session, sessionmaker

from guardian.db.models import (
    ActionEntity,
    AlertEntity,
    DestinationEntity,
    DetectionEntity,
    DeviceEntity,
    DriftEventEntity,
    FeedbackEntity,
    ModelEntity,
    ProfileEntity,
    SettingEntity,
    WindowEntity,
)


class GuardianRepository:
    """Encapsulates all persistence logic, transactional isolation, and query access."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # --- Device Operations ---

    def upsert_device(
        self,
        device_id: str,
        name: str,
        device_type: str,
        ip: str,
        mac: str,
        stage: str = "observe",
        first_seen: float = 0.0,
        mode: str = "observe",
    ) -> DeviceEntity:
        """Insert or update device posture."""
        with self._session_factory() as session:
            with session.begin():
                dev = session.get(DeviceEntity, device_id)
                if dev is None:
                    dev = DeviceEntity(
                        device_id=device_id,
                        name=name,
                        type=device_type,
                        ip=ip,
                        mac=mac,
                        stage=stage,
                        first_seen=first_seen,
                        mode=mode,
                        updated_at=first_seen,
                    )
                    session.add(dev)
                else:
                    dev.name = name
                    dev.type = device_type
                    dev.ip = ip
                    dev.mac = mac
                    dev.stage = stage
                    dev.mode = mode
                    dev.updated_at = first_seen
                session.flush()
                session.refresh(dev)
                return dev

    def get_device(self, device_id: str) -> DeviceEntity | None:
        """Fetch device entity by ID."""
        with self._session_factory() as session:
            return session.get(DeviceEntity, device_id)

    def list_devices(self) -> Sequence[DeviceEntity]:
        """Return all tracked devices."""
        with self._session_factory() as session:
            stmt = select(DeviceEntity).order_by(DeviceEntity.first_seen.asc())
            return session.scalars(stmt).all()

    def update_device_posture(
        self,
        device_id: str,
        stage: str | None = None,
        mode: str | None = None,
        updated_at: float = 0.0,
    ) -> None:
        """Update lifecycle stage or policy enforcement mode."""
        with self._session_factory() as session:
            with session.begin():
                dev = session.get(DeviceEntity, device_id)
                if dev is not None:
                    if stage is not None:
                        dev.stage = stage
                    if mode is not None:
                        dev.mode = mode
                    dev.updated_at = updated_at

    # --- Feature Windows ---

    def insert_window(
        self,
        device_id: str,
        window_start: float,
        window_end: float,
        vector: list[float],
        n_packets: int,
        quality_flags: list[str] | None = None,
    ) -> WindowEntity:
        """Persist aggregated feature window."""
        with self._session_factory() as session:
            with session.begin():
                window = WindowEntity(
                    device_id=device_id,
                    window_start=window_start,
                    window_end=window_end,
                    vector_json=json.dumps(vector),
                    n_packets=n_packets,
                    quality_flags_json=json.dumps(quality_flags or []),
                )
                session.add(window)
                session.flush()
                session.refresh(window)
                return window

    def get_windows(
        self,
        device_id: str,
        start_ts: float | None = None,
        end_ts: float | None = None,
        limit: int = 1000,
    ) -> Sequence[WindowEntity]:
        """Query time-range bounded feature windows for a device."""
        with self._session_factory() as session:
            stmt = select(WindowEntity).where(WindowEntity.device_id == device_id)
            if start_ts is not None:
                stmt = stmt.where(WindowEntity.window_start >= start_ts)
            if end_ts is not None:
                stmt = stmt.where(WindowEntity.window_end <= end_ts)
            stmt = stmt.order_by(WindowEntity.window_start.asc()).limit(limit)
            return session.scalars(stmt).all()

    # --- Behavioral Profiles ---

    def upsert_profile(
        self,
        device_id: str,
        profile_data: dict[str, Any],
        version: int = 1,
        updated_at: float = 0.0,
    ) -> ProfileEntity:
        """Insert or replace device statistical baseline profile."""
        with self._session_factory() as session:
            with session.begin():
                profile = session.get(ProfileEntity, device_id)
                if profile is None:
                    profile = ProfileEntity(
                        device_id=device_id,
                        version=version,
                        profile_json=json.dumps(profile_data),
                        created_at=updated_at,
                        updated_at=updated_at,
                    )
                    session.add(profile)
                else:
                    profile.version = version
                    profile.profile_json = json.dumps(profile_data)
                    profile.updated_at = updated_at
                session.flush()
                session.refresh(profile)
                return profile

    def get_profile(self, device_id: str) -> ProfileEntity | None:
        """Fetch current active profile for device."""
        with self._session_factory() as session:
            return session.get(ProfileEntity, device_id)

    # --- Trained Models ---

    def record_model(
        self,
        model_id: str,
        device_id: str,
        model_type: str,
        path: str,
        sha256: str,
        trained_at: float,
        train_start_ts: float,
        train_end_ts: float,
        metrics: dict[str, Any],
    ) -> ModelEntity:
        """Register newly trained machine learning model."""
        with self._session_factory() as session:
            with session.begin():
                model = ModelEntity(
                    model_id=model_id,
                    device_id=device_id,
                    model_type=model_type,
                    path=path,
                    sha256=sha256,
                    trained_at=trained_at,
                    train_start_ts=train_start_ts,
                    train_end_ts=train_end_ts,
                    metrics_json=json.dumps(metrics),
                )
                session.add(model)
                session.flush()
                session.refresh(model)
                return model

    def get_active_model(self, device_id: str, model_type: str = "iforest") -> ModelEntity | None:
        """Fetch latest trained model for a device."""
        with self._session_factory() as session:
            stmt = (
                select(ModelEntity)
                .where(ModelEntity.device_id == device_id, ModelEntity.model_type == model_type)
                .order_by(desc(ModelEntity.trained_at))
                .limit(1)
            )
            return session.scalars(stmt).first()

    # --- Detections ---

    def insert_detection(
        self,
        device_id: str,
        window_end: float,
        ml_score: float,
        stat_score: float,
        net_score: float,
        threat_score: float,
        confidence: float,
        level: str,
        top_features: list[dict[str, Any]] | None = None,
        triggers: list[str] | None = None,
    ) -> DetectionEntity:
        """Insert detection evaluation result for a window."""
        with self._session_factory() as session:
            with session.begin():
                det = DetectionEntity(
                    device_id=device_id,
                    window_end=window_end,
                    ml_score=ml_score,
                    stat_score=stat_score,
                    net_score=net_score,
                    threat_score=threat_score,
                    confidence=confidence,
                    level=level,
                    top_features_json=json.dumps(top_features or []),
                    triggers_json=json.dumps(triggers or []),
                )
                session.add(det)
                session.flush()
                session.refresh(det)
                return det

    def get_recent_detections(self, device_id: str, limit: int = 100) -> Sequence[DetectionEntity]:
        """Query recent anomaly detection records for a device."""
        with self._session_factory() as session:
            stmt = (
                select(DetectionEntity)
                .where(DetectionEntity.device_id == device_id)
                .order_by(desc(DetectionEntity.window_end))
                .limit(limit)
            )
            return session.scalars(stmt).all()

    # --- Alerts ---

    def create_alert(
        self,
        alert_id: str,
        device_id: str,
        opened_at: float,
        peak_score: float,
        level: str,
        explanation: dict[str, Any],
        explanation_text: str,
        likely_attack: dict[str, Any],
        recommended_actions: list[str],
    ) -> AlertEntity:
        """Create confirmed threat alert."""
        with self._session_factory() as session:
            with session.begin():
                alert = AlertEntity(
                    alert_id=alert_id,
                    device_id=device_id,
                    opened_at=opened_at,
                    peak_score=peak_score,
                    level=level,
                    explanation_json=json.dumps(explanation),
                    explanation_text=explanation_text,
                    likely_attack_json=json.dumps(likely_attack),
                    recommended_actions_json=json.dumps(recommended_actions),
                    status="open",
                )
                session.add(alert)
                session.flush()
                session.refresh(alert)
                return alert

    def get_alert(self, alert_id: str) -> AlertEntity | None:
        """Retrieve alert by ID."""
        with self._session_factory() as session:
            return session.get(AlertEntity, alert_id)

    def update_alert_status(
        self, alert_id: str, status: str, closed_at: float | None = None
    ) -> None:
        """Update alert state (open, acknowledged, resolved, false_positive)."""
        with self._session_factory() as session:
            with session.begin():
                alert = session.get(AlertEntity, alert_id)
                if alert is not None:
                    alert.status = status
                    if closed_at is not None:
                        alert.closed_at = closed_at

    def list_open_alerts(self) -> Sequence[AlertEntity]:
        """Retrieve all currently active unclosed alerts."""
        with self._session_factory() as session:
            stmt = (
                select(AlertEntity)
                .where(AlertEntity.status == "open")
                .order_by(desc(AlertEntity.opened_at))
            )
            return session.scalars(stmt).all()

    # --- Response Actions ---

    def record_action(
        self,
        action_id: str,
        device_id: str,
        level: str,
        backend: str,
        rules_applied: list[str],
        applied_at: float,
        expires_at: float | None = None,
        reason: str = "",
    ) -> ActionEntity:
        """Record dispatched graduated containment action."""
        with self._session_factory() as session:
            with session.begin():
                action = ActionEntity(
                    action_id=action_id,
                    device_id=device_id,
                    level=level,
                    backend=backend,
                    rules_applied_json=json.dumps(rules_applied),
                    applied_at=applied_at,
                    expires_at=expires_at,
                    reason=reason,
                )
                session.add(action)
                session.flush()
                session.refresh(action)
                return action

    def get_action(self, action_id: str) -> ActionEntity | None:
        """Retrieve response action by ID."""
        with self._session_factory() as session:
            return session.get(ActionEntity, action_id)

    def revert_action(
        self, action_id: str, reverted_at: float, overridden_by: str | None = None
    ) -> None:
        """Mark action as reverted or overridden."""
        with self._session_factory() as session:
            with session.begin():
                action = session.get(ActionEntity, action_id)
                if action is not None:
                    action.reverted_at = reverted_at
                    action.overridden_by = overridden_by

    # --- Analyst Feedback ---

    def record_feedback(
        self,
        feedback_id: str,
        alert_id: str,
        device_id: str,
        verdict: str,
        notes: str | None = None,
        submitted_at: float = 0.0,
    ) -> FeedbackEntity:
        """Record analyst label for continual adaptation."""
        with self._session_factory() as session:
            with session.begin():
                feedback = FeedbackEntity(
                    feedback_id=feedback_id,
                    alert_id=alert_id,
                    device_id=device_id,
                    verdict=verdict,
                    notes=notes,
                    submitted_at=submitted_at,
                )
                session.add(feedback)
                session.flush()
                session.refresh(feedback)
                return feedback

    def get_alert_feedback(self, alert_id: str) -> Sequence[FeedbackEntity]:
        """Retrieve feedback associated with an alert."""
        with self._session_factory() as session:
            stmt = select(FeedbackEntity).where(FeedbackEntity.alert_id == alert_id)
            return session.scalars(stmt).all()

    # --- Drift Events ---

    def record_drift_event(
        self,
        device_id: str,
        detected_at: float,
        drift_score: float,
        p_value: float,
        top_drifting_features: list[str],
        status: str = "pending_review",
    ) -> DriftEventEntity:
        """Record distribution drift assessment event."""
        with self._session_factory() as session:
            with session.begin():
                drift = DriftEventEntity(
                    device_id=device_id,
                    detected_at=detected_at,
                    drift_score=drift_score,
                    p_value=p_value,
                    top_drifting_features_json=json.dumps(top_drifting_features),
                    status=status,
                )
                session.add(drift)
                session.flush()
                session.refresh(drift)
                return drift

    # --- Destinations (Layer 2 Identity) ---

    def record_destination(
        self,
        device_id: str,
        dst_ip: str,
        port: int,
        seen_at: float,
        initial_status: str = "pending",
    ) -> DestinationEntity:
        """Record or update destination endpoint contact."""
        with self._session_factory() as session:
            with session.begin():
                stmt = select(DestinationEntity).where(
                    DestinationEntity.device_id == device_id,
                    DestinationEntity.dst_ip == dst_ip,
                    DestinationEntity.port == port,
                )
                dest = session.scalars(stmt).first()
                if dest is None:
                    dest = DestinationEntity(
                        device_id=device_id,
                        dst_ip=dst_ip,
                        port=port,
                        first_seen=seen_at,
                        last_seen=seen_at,
                        count=1,
                        status=initial_status,
                    )
                    session.add(dest)
                else:
                    dest.last_seen = seen_at
                    dest.count += 1
                session.flush()
                session.refresh(dest)
                return dest

    def get_destinations(self, device_id: str) -> Sequence[DestinationEntity]:
        """Fetch known destinations for a device."""
        with self._session_factory() as session:
            stmt = select(DestinationEntity).where(DestinationEntity.device_id == device_id)
            return session.scalars(stmt).all()

    # --- Dynamic Settings ---

    def set_setting(self, key: str, value: Any, updated_at: float = 0.0) -> None:
        """Set dynamic setting value."""
        with self._session_factory() as session:
            with session.begin():
                setting = session.get(SettingEntity, key)
                if setting is None:
                    setting = SettingEntity(
                        key=key,
                        value_json=json.dumps(value),
                        updated_at=updated_at,
                    )
                    session.add(setting)
                else:
                    setting.value_json = json.dumps(value)
                    setting.updated_at = updated_at

    def get_setting(self, key: str) -> Any | None:
        """Retrieve dynamic setting value."""
        with self._session_factory() as session:
            setting = session.get(SettingEntity, key)
            if setting is not None:
                return setting.get_value()
            return None
