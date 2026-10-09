"""Unit tests for GUARDIAN database models, engine, and repository CRUD operations."""

import pytest
from sqlalchemy import text

from guardian.db.engine import get_db_engine, get_session_factory
from guardian.db.models import (
    Base,
)
from guardian.db.repository import GuardianRepository


@pytest.fixture
def repo(tmp_path: pytest.TempPathFactory) -> GuardianRepository:
    """Fixture providing an isolated SQLite database repository with WAL mode."""
    db_file = tmp_path / "test_guardian.db"
    db_url = f"sqlite:///{db_file}"
    engine = get_db_engine(db_url=db_url, wal_mode=True)
    Base.metadata.create_all(bind=engine)
    session_factory = get_session_factory(engine)
    return GuardianRepository(session_factory)


def test_sqlite_pragmas(tmp_path: pytest.TempPathFactory) -> None:
    """Verify SQLite connection applies WAL journal mode and foreign keys."""
    db_file = tmp_path / "pragma_test.db"
    db_url = f"sqlite:///{db_file}"
    engine = get_db_engine(db_url=db_url, wal_mode=True)

    with engine.connect() as conn:
        journal_mode = conn.execute(text("PRAGMA journal_mode;")).scalar()
        assert str(journal_mode).lower() == "wal"

        foreign_keys = conn.execute(text("PRAGMA foreign_keys;")).scalar()
        assert foreign_keys == 1


def test_device_crud(repo: GuardianRepository) -> None:
    """Test device registration, retrieval, and status updates."""
    repo.upsert_device(
        device_id="esp32_sensor_01",
        name="Living Room Sensor",
        device_type="esp32_sensor",
        ip="192.168.1.50",
        mac="AA:BB:CC:DD:EE:01",
        stage="observe",
        first_seen=1000.0,
        mode="observe",
    )

    dev = repo.get_device("esp32_sensor_01")
    assert dev is not None
    assert dev.name == "Living Room Sensor"
    assert dev.stage == "observe"

    # Update stage and mode
    repo.update_device_posture("esp32_sensor_01", stage="ml", mode="enforce")
    updated = repo.get_device("esp32_sensor_01")
    assert updated is not None
    assert updated.stage == "ml"
    assert updated.mode == "enforce"


def test_window_and_detection_crud(repo: GuardianRepository) -> None:
    """Test inserting feature windows and detection records."""
    repo.insert_window(
        device_id="esp32_sensor_01",
        window_start=100.0,
        window_end=110.0,
        vector=[1.0] * 60,
        n_packets=30,
        quality_flags=["sparse_window"],
    )

    windows = repo.get_windows(device_id="esp32_sensor_01", start_ts=90.0, end_ts=120.0)
    assert len(windows) == 1
    assert len(windows[0].get_vector()) == 60
    assert windows[0].n_packets == 30

    repo.insert_detection(
        device_id="esp32_sensor_01",
        window_end=110.0,
        ml_score=85.0,
        stat_score=90.0,
        net_score=40.0,
        threat_score=82.5,
        confidence=0.9,
        level="quarantine",
        top_features=[{"name": "byte_rate", "value": 5000.0}],
        triggers=["volume_burst"],
    )

    detections = repo.get_recent_detections(device_id="esp32_sensor_01", limit=10)
    assert len(detections) == 1
    assert detections[0].threat_score == 82.5
    assert detections[0].level == "quarantine"


def test_alert_action_feedback_lifecycle(repo: GuardianRepository) -> None:
    """Test alert creation, response action execution, and user feedback."""
    repo.create_alert(
        alert_id="alt_001",
        device_id="esp32_sensor_01",
        opened_at=1000.0,
        peak_score=92.0,
        level="quarantine",
        explanation={"anomaly": "outbound_flood"},
        explanation_text="Outbound flood detected",
        likely_attack={"label": "mirai_ddos", "confidence": 0.89},
        recommended_actions=["quarantine_device"],
    )

    alert = repo.get_alert("alt_001")
    assert alert is not None
    assert alert.status == "open"
    assert alert.peak_score == 92.0

    repo.record_action(
        action_id="act_001",
        device_id="esp32_sensor_01",
        level="quarantine",
        backend="dryrun",
        rules_applied=["isolate_ports"],
        applied_at=1001.0,
        expires_at=4601.0,
        reason="Mitigating alt_001",
    )

    action = repo.get_action("act_001")
    assert action is not None
    assert action.backend == "dryrun"
    assert action.reverted_at is None

    repo.revert_action("act_001", reverted_at=1050.0, overridden_by="admin")
    reverted = repo.get_action("act_001")
    assert reverted is not None
    assert reverted.reverted_at == 1050.0
    assert reverted.overridden_by == "admin"

    repo.record_feedback(
        feedback_id="fb_001",
        alert_id="alt_001",
        device_id="esp32_sensor_01",
        verdict="false_positive",
        notes="Firmware update burst",
        submitted_at=1100.0,
    )
    feedback_entries = repo.get_alert_feedback("alt_001")
    assert len(feedback_entries) == 1
    assert feedback_entries[0].verdict == "false_positive"


def test_destinations_and_settings(repo: GuardianRepository) -> None:
    """Test network identity destination tracking and platform settings."""
    repo.record_destination(
        device_id="esp32_sensor_01",
        dst_ip="192.168.1.1",
        port=1883,
        seen_at=100.0,
        initial_status="known",
    )
    dests = repo.get_destinations("esp32_sensor_01")
    assert len(dests) == 1
    assert dests[0].count == 1
    assert dests[0].status == "known"

    # Increment destination seen
    repo.record_destination(
        device_id="esp32_sensor_01",
        dst_ip="192.168.1.1",
        port=1883,
        seen_at=105.0,
    )
    dests_updated = repo.get_destinations("esp32_sensor_01")
    assert dests_updated[0].count == 2
    assert dests_updated[0].last_seen == 105.0

    # Settings
    repo.set_setting("system.version", {"version": "1.0.0"}, updated_at=100.0)
    val = repo.get_setting("system.version")
    assert val == {"version": "1.0.0"}
    assert repo.get_setting("non_existent_key") is None


def test_profiles_models_and_drift(repo: GuardianRepository) -> None:
    """Test profiles, model registration, drift events, and device listing."""
    # List devices
    devs = repo.list_devices()
    assert len(devs) >= 0

    # Profile upsert and get
    repo.upsert_profile(
        device_id="esp32_sensor_01",
        profile_data={"mean_pkts": 12.0, "priors": {"periodicity": 10.0}},
        version=1,
        updated_at=100.0,
    )
    prof = repo.get_profile("esp32_sensor_01")
    assert prof is not None
    assert prof.get_profile()["mean_pkts"] == 12.0

    # Update profile
    repo.upsert_profile(
        device_id="esp32_sensor_01",
        profile_data={"mean_pkts": 15.0},
        version=2,
        updated_at=200.0,
    )
    prof_v2 = repo.get_profile("esp32_sensor_01")
    assert prof_v2 is not None
    assert prof_v2.version == 2
    assert prof_v2.get_profile()["mean_pkts"] == 15.0

    # Model registry
    repo.record_model(
        model_id="mod_001",
        device_id="esp32_sensor_01",
        model_type="iforest",
        path="models/esp32_01.joblib",
        sha256="abc123sha",
        trained_at=500.0,
        train_start_ts=0.0,
        train_end_ts=450.0,
        metrics={"f1": 0.94},
    )
    active_mod = repo.get_active_model("esp32_sensor_01", model_type="iforest")
    assert active_mod is not None
    assert active_mod.sha256 == "abc123sha"
    assert active_mod.get_metrics()["f1"] == 0.94

    # Drift events
    drift = repo.record_drift_event(
        device_id="esp32_sensor_01",
        detected_at=600.0,
        drift_score=0.35,
        p_value=0.01,
        top_drifting_features=["pkt_rate", "dst_entropy"],
        status="pending_review",
    )
    assert drift.drift_score == 0.35
    assert drift.status == "pending_review"

    # Open alerts
    open_alerts = repo.list_open_alerts()
    assert isinstance(open_alerts, list)
