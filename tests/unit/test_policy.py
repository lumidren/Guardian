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
