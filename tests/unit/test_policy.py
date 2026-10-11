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


def test_learn_whether_device_ever_streams() -> None:
    """Task 62: Verify learn_streaming_capability distinguishes non-streaming sensors from streaming cameras."""
    from guardian.policy.learner import (
        BaselineWindowObservation,
        learn_streaming_capability,
    )

    sensor_obs = [
        BaselineWindowObservation(device_id="dev_sensor", timestamp=10.0, upload_bytes=400),
        BaselineWindowObservation(device_id="dev_sensor", timestamp=20.0, upload_bytes=550),
    ]
    cam_obs = [
        BaselineWindowObservation(device_id="dev_cam", timestamp=10.0, upload_bytes=25000),
        BaselineWindowObservation(device_id="dev_cam", timestamp=20.0, upload_bytes=32000),
    ]
    r_sensor = learn_streaming_capability("dev_sensor", sensor_obs, created_at=100.0)
    r_cam = learn_streaming_capability("dev_cam", cam_obs, created_at=100.0)
    assert r_sensor.parameters["ever_streams"] is False
    assert r_cam.parameters["ever_streams"] is True


def test_device_type_guess_from_traffic() -> None:
    """Task 63: Verify guess_device_type_from_traffic classifies sensor, camera, plug, and compute archetypes."""
    from guardian.policy.learner import (
        BaselineWindowObservation,
        guess_device_type_from_traffic,
    )

    assert guess_device_type_from_traffic([
        BaselineWindowObservation(device_id="d1", timestamp=10.0, dst_ips=("192.168.1.1",), dst_ports=(1883,), protocols=("MQTT",), upload_bytes=300)
    ]) == "Environmental Sensor"
    assert guess_device_type_from_traffic([
        BaselineWindowObservation(device_id="d2", timestamp=10.0, dst_ips=("192.168.1.50",), dst_ports=(554,), protocols=("MQTT",), upload_bytes=22000)
    ]) == "Smart Camera"
    assert guess_device_type_from_traffic([
        BaselineWindowObservation(device_id="d3", timestamp=10.0, dst_ips=("192.168.1.1", "54.210.10.45"), dst_ports=(1883,), protocols=("MQTT",), upload_bytes=450)
    ]) == "Smart Plug"
    assert guess_device_type_from_traffic([
        BaselineWindowObservation(device_id="d4", timestamp=10.0, dst_ips=("192.168.1.1",), dst_ports=(80,), protocols=("HTTP",), upload_bytes=1200)
    ]) == "Edge Compute"


def test_device_type_default_templates_yaml() -> None:
    """Task 64: Verify config/device_type_templates.yaml loads all device archetypes and instantiates 6 rules."""
    from guardian.policy.templates import (
        build_template_rules_for_device_type,
        load_device_type_templates,
    )

    templates = load_device_type_templates()
    assert "Environmental Sensor" in templates
    assert "Smart Camera" in templates
    rules = build_template_rules_for_device_type("dev_01", "Environmental Sensor", created_at=100.0)
    assert len(rules) == 6
    assert all(r.source == RuleSource.DEFAULT_TEMPLATE for r in rules)
    assert all(r.scope == RuleScope.DEVICE_TYPE for r in rules)


def test_use_templates_before_baseline_is_ready() -> None:
    """Task 65: Verify templates are used before min_baseline_windows and replaced by learned rules once ready."""
    from guardian.policy.learner import BaselineWindowObservation
    from guardian.policy.templates import resolve_effective_device_rules

    early_obs = [
        BaselineWindowObservation(device_id="dev_01", timestamp=10.0 * i, dst_ips=("192.168.1.1",), dst_ports=(1883,), protocols=("MQTT",), upload_bytes=200)
        for i in range(5)
    ]
    early_rules = resolve_effective_device_rules("dev_01", early_obs, min_baseline_windows=10, created_at=100.0)
    assert all(r.source == RuleSource.DEFAULT_TEMPLATE for r in early_rules)

    ready_obs = [
        BaselineWindowObservation(device_id="dev_01", timestamp=10.0 * i, dst_ips=("192.168.1.1",), dst_ports=(1883,), protocols=("MQTT",), upload_bytes=200)
        for i in range(12)
    ]
    ready_rules = resolve_effective_device_rules("dev_01", ready_obs, min_baseline_windows=10, created_at=100.0)
    assert all(r.source == RuleSource.BASELINE_LEARNED for r in ready_rules)


def test_policy_rule_evaluator() -> None:
    """Task 66: Verify PolicyRuleEvaluator checks destination, port/protocol, hours, budgets, and streaming."""
    from guardian.policy.evaluator import PolicyRuleEvaluator
    from guardian.policy.learner import BaselineWindowObservation
    from guardian.policy.templates import build_template_rules_for_device_type

    rules = build_template_rules_for_device_type("dev_01", "Environmental Sensor", created_at=100.0)
    evaluator = PolicyRuleEvaluator()

    benign_obs = BaselineWindowObservation(
        device_id="dev_01",
        timestamp=12 * 3600.0,
        dst_ips=("192.168.1.1",),
        dst_ports=(1883,),
        protocols=("MQTT",),
        upload_bytes=300,
        download_bytes=200,
    )
    res_ok = evaluator.evaluate_window(benign_obs, rules)
    assert all(r["passed"] for r in res_ok)

    bad_obs = BaselineWindowObservation(
        device_id="dev_01",
        timestamp=12 * 3600.0,
        dst_ips=("198.51.100.99",),
        dst_ports=(23,),
        protocols=("TELNET",),
        upload_bytes=300,
        download_bytes=200,
    )
    res_bad = evaluator.evaluate_window(bad_obs, rules)
    failed_kinds = {r["kind"] for r in res_bad if not r["passed"]}
    assert RuleKind.DESTINATION_ALLOWLIST in failed_kinds
    assert RuleKind.PORT_PROTOCOL_ALLOWLIST in failed_kinds


def test_rule_violation_events() -> None:
    """Task 67: Verify extract_violation_events converts failed rule checks into RuleViolationEvent objects."""
    from guardian.policy.evaluator import PolicyRuleEvaluator
    from guardian.policy.learner import BaselineWindowObservation
    from guardian.policy.templates import build_template_rules_for_device_type

    rules = build_template_rules_for_device_type("dev_01", "Environmental Sensor", created_at=100.0)
    evaluator = PolicyRuleEvaluator()
    bad_obs = BaselineWindowObservation(
        device_id="dev_01",
        timestamp=12 * 3600.0,
        dst_ips=("198.51.100.99",),
        dst_ports=(23,),
        protocols=("TELNET",),
        upload_bytes=300,
    )
    eval_res = evaluator.evaluate_window(bad_obs, rules)
    events = evaluator.extract_violation_events(bad_obs, eval_res)
    assert len(events) == 2
    assert all(e.severity > 0.0 and e.device_id == "dev_01" for e in events)


def test_feed_violations_into_threat_score() -> None:
    """Task 68: Verify policy violations boost fused threat score up to [0, 100]."""
    from guardian.policy.evaluator import (
        RuleViolationEvent,
        fuse_violations_into_threat_score,
    )

    ev = RuleViolationEvent(
        event_id="ev_1",
        device_id="dev_01",
        timestamp=100.0,
        rule_id="r_1",
        kind=RuleKind.DESTINATION_ALLOWLIST,
        source=RuleSource.BASELINE_LEARNED,
        severity=25.0,
        reason="unauthorized dst",
    )
    assert fuse_violations_into_threat_score(30.0, [ev]) == 55.0
    assert fuse_violations_into_threat_score(90.0, [ev]) == 100.0


def test_budget_breach_triggers_restrict() -> None:
    """Task 69: Verify daily upload/download budget breach triggers RESTRICT response action."""
    from guardian.policy.evaluator import (
        RuleViolationEvent,
        determine_policy_response_action,
    )

    budget_ev = RuleViolationEvent(
        event_id="ev_b1",
        device_id="dev_01",
        timestamp=100.0,
        rule_id="r_b1",
        kind=RuleKind.DAILY_UPLOAD_BUDGET,
        source=RuleSource.BASELINE_LEARNED,
        severity=35.0,
        reason="upload budget exceeded",
    )
    assert determine_policy_response_action([budget_ev]) == "RESTRICT"
    assert determine_policy_response_action([]) == "MONITOR"
