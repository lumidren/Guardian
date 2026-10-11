"""Unit tests for auto-learned zero-config policies (Phase 4 Section D, Tasks 55-76)."""

from __future__ import annotations

from guardian.policy import PolicyRule, RuleKind, RuleScope, RuleSource


def test_policy_rule_data_model_and_expiry() -> None:
    """Task 55: Verify PolicyRule data model fields (rule, scope, source, expiry)."""
    rule = PolicyRule(
        rule_id="r_001",
        kind=RuleKind.DESTINATION_ALLOWLIST,
        scope=RuleScope.DEVICE,
        target_id="dev_01_temp",
        source=RuleSource.BASELINE_LEARNED,
        parameters={"allowed_ips": ["192.168.1.1"]},
        created_at=1000.0,
        expires_at=2000.0,
    )
    assert rule.is_expired(now=1500.0) is False
    assert rule.is_expired(now=2000.0) is True
    d = rule.to_dict()
    assert d["kind"] == "destination_allowlist"
    assert d["scope"] == "device"
    assert d["source"] == "baseline_learned"


def test_db_tables_for_rules_and_decisions() -> None:
    """Task 56: Verify SQLite DB tables for policy_rules and policy_decisions persist and filter expired rules."""
    from guardian.policy import DecisionMode, PolicySQLiteStore

    store = PolicySQLiteStore(":memory:")
    r_active = PolicyRule(
        rule_id="r_active",
        kind=RuleKind.DESTINATION_ALLOWLIST,
        scope=RuleScope.DEVICE,
        target_id="dev_01_temp",
        source=RuleSource.BASELINE_LEARNED,
        parameters={"allowed_ips": ["192.168.1.1"]},
        created_at=100.0,
        expires_at=500.0,
    )
    r_expired = PolicyRule(
        rule_id="r_expired",
        kind=RuleKind.ACTIVE_HOURS,
        scope=RuleScope.DEVICE,
        target_id="dev_01_temp",
        source=RuleSource.BASELINE_LEARNED,
        parameters={"hours": [6, 22]},
        created_at=100.0,
        expires_at=200.0,
    )
    store.upsert_rule(r_active)
    store.upsert_rule(r_expired)
    active = store.get_active_rules(target_id="dev_01_temp", now=300.0)
    assert [r.rule_id for r in active] == ["r_active"]

    store.record_decision(
        decision_id="dec_1",
        device_id="dev_01_temp",
        rule_kind=RuleKind.STREAMING_CAPABILITY,
        subject_key="stream:rtsp",
        mode=DecisionMode.ALWAYS,
        created_at=300.0,
    )
    decisions = store.get_decisions("dev_01_temp")
    assert len(decisions) == 1
    assert decisions[0]["mode"] == "always"


def test_learn_destination_allowlist_from_baseline() -> None:
    """Task 57: Verify learn_destination_allowlist extracts unique benign destinations."""
    from guardian.policy.learner import (
        BaselineWindowObservation,
        learn_destination_allowlist,
    )

    obs = [
        BaselineWindowObservation(device_id="dev_01", timestamp=10.0, dst_ips=("192.168.1.1", "54.210.10.45")),
        BaselineWindowObservation(device_id="dev_01", timestamp=20.0, dst_ips=("192.168.1.1",)),
    ]
    rule = learn_destination_allowlist("dev_01", obs, created_at=100.0)
    assert rule.kind == RuleKind.DESTINATION_ALLOWLIST
    assert rule.parameters["allowed_ips"] == ["192.168.1.1", "54.210.10.45"]
    assert rule.parameters["window_count"] == 2


def test_learn_port_and_protocol_allowlist() -> None:
    """Task 58: Verify learn_port_and_protocol_allowlist extracts benign ports and transport/app protocols."""
    from guardian.policy.learner import (
        BaselineWindowObservation,
        learn_port_and_protocol_allowlist,
    )

    obs = [
        BaselineWindowObservation(device_id="dev_01", timestamp=10.0, dst_ports=(1883, 53), protocols=("MQTT", "DNS")),
        BaselineWindowObservation(device_id="dev_01", timestamp=20.0, dst_ports=(1883, 123), protocols=("MQTT", "NTP")),
    ]
    rule = learn_port_and_protocol_allowlist("dev_01", obs, created_at=100.0)
    assert rule.kind == RuleKind.PORT_PROTOCOL_ALLOWLIST
    assert rule.parameters["allowed_ports"] == [53, 123, 1883]
    assert rule.parameters["allowed_protocols"] == ["DNS", "MQTT", "NTP"]


def test_learn_active_hours() -> None:
    """Task 59: Verify learn_active_hours extracts circadian active hours from baseline traffic."""
    from guardian.policy.learner import BaselineWindowObservation, learn_active_hours

    obs = [
        BaselineWindowObservation(device_id="dev_cam", timestamp=8 * 3600.0, upload_bytes=500),
        BaselineWindowObservation(device_id="dev_cam", timestamp=14 * 3600.0, upload_bytes=600),
        BaselineWindowObservation(device_id="dev_cam", timestamp=2 * 3600.0, upload_bytes=10),  # below threshold
    ]
    rule = learn_active_hours("dev_cam", obs, min_bytes_threshold=64, created_at=100.0)
    assert rule.kind == RuleKind.ACTIVE_HOURS
    assert rule.parameters["active_hours_utc"] == [8, 14]


def test_learn_daily_upload_budget() -> None:
    """Task 60: Verify learn_daily_upload_budget computes peak daily upload x margin."""
    from guardian.policy.learner import (
        BaselineWindowObservation,
        learn_daily_upload_budget,
    )

    obs = [
        BaselineWindowObservation(device_id="dev_01", timestamp=100.0, upload_bytes=4000),
        BaselineWindowObservation(device_id="dev_01", timestamp=200.0, upload_bytes=6000),  # day 0 total = 10000
        BaselineWindowObservation(device_id="dev_01", timestamp=90000.0, upload_bytes=8000),  # day 1 total = 8000
    ]
    rule = learn_daily_upload_budget("dev_01", obs, margin=2.5, created_at=100.0)
    assert rule.kind == RuleKind.DAILY_UPLOAD_BUDGET
    assert rule.parameters["peak_daily_upload_bytes"] == 10000
    assert rule.parameters["daily_upload_budget_bytes"] == 25000


def test_learn_daily_download_budget() -> None:
    """Task 61: Verify learn_daily_download_budget computes peak daily download x margin."""
    from guardian.policy.learner import (
        BaselineWindowObservation,
        learn_daily_download_budget,
    )

    obs = [
        BaselineWindowObservation(device_id="dev_01", timestamp=100.0, download_bytes=12000),
        BaselineWindowObservation(device_id="dev_01", timestamp=200.0, download_bytes=8000),  # day 0 total = 20000
        BaselineWindowObservation(device_id="dev_01", timestamp=90000.0, download_bytes=5000),
    ]
    rule = learn_daily_download_budget("dev_01", obs, margin=3.0, created_at=100.0)
    assert rule.kind == RuleKind.DAILY_DOWNLOAD_BUDGET
    assert rule.parameters["peak_daily_download_bytes"] == 20000
    assert rule.parameters["daily_download_budget_bytes"] == 60000
