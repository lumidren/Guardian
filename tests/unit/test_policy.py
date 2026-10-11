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


def test_first_time_streaming_triggers_a_prompt() -> None:
    """Task 70: Verify first-time streaming violation generates a UserPromptRequest (once/always/block)."""
    from guardian.policy.evaluator import (
        RuleViolationEvent,
        build_first_time_streaming_prompt,
        determine_policy_response_action,
    )

    stream_ev = RuleViolationEvent(
        event_id="ev_s1",
        device_id="dev_vacuum",
        timestamp=500.0,
        rule_id="r_s1",
        kind=RuleKind.STREAMING_CAPABILITY,
        source=RuleSource.BASELINE_LEARNED,
        severity=40.0,
        reason="First-time streaming upload (28000 B >= 15000 B)",
    )
    assert determine_policy_response_action([stream_ev]) == "PROMPT"
    prompt = build_first_time_streaming_prompt(stream_ev, dst_ip="198.51.100.42")
    assert prompt is not None
    assert prompt.options == ("once", "always", "block")
    assert prompt.subject_key == "stream:198.51.100.42"


def test_remember_decisions_once_always_block() -> None:
    """Task 71: Verify PolicyDecisionManager persists and resolves ONCE (TTL), ALWAYS, and BLOCK decisions."""
    from guardian.policy import DecisionMode, PolicySQLiteStore
    from guardian.policy.evaluator import PolicyDecisionManager, UserPromptRequest

    store = PolicySQLiteStore(":memory:")
    mgr = PolicyDecisionManager(store, once_ttl_seconds=300.0)
    prompt = UserPromptRequest(
        prompt_id="p_1",
        device_id="dev_01",
        timestamp=1000.0,
        rule_kind=RuleKind.STREAMING_CAPABILITY,
        subject_key="stream:198.51.100.42",
        message="Allow streaming?",
    )
    mgr.apply_user_decision(prompt, DecisionMode.ONCE, now=1000.0)
    assert mgr.resolve_decision("dev_01", RuleKind.STREAMING_CAPABILITY, "stream:198.51.100.42", now=1100.0) == "ALLOW"
    assert mgr.resolve_decision("dev_01", RuleKind.STREAMING_CAPABILITY, "stream:198.51.100.42", now=1400.0) is None

    mgr.apply_user_decision(prompt, DecisionMode.BLOCK, now=1405.0)
    assert mgr.resolve_decision("dev_01", RuleKind.STREAMING_CAPABILITY, "stream:198.51.100.42", now=99999.0) == "BLOCK"

    mgr.apply_user_decision(prompt, DecisionMode.ALWAYS, now=1500.0)
    assert mgr.resolve_decision("dev_01", RuleKind.STREAMING_CAPABILITY, "stream:198.51.100.42", now=99999.0) == "ALLOW"


def test_prompt_rate_limit_per_device_per_week() -> None:
    """Task 72: Verify PromptRateLimiter caps interactive prompts per device per 7-day rolling window."""
    from guardian.policy.evaluator import PromptRateLimiter

    limiter = PromptRateLimiter(max_prompts_per_device_week=2)
    assert limiter.record_prompt("dev_01", now=100.0) is True
    assert limiter.record_prompt("dev_01", now=200.0) is True
    assert limiter.record_prompt("dev_01", now=300.0) is False
    assert limiter.prompts_in_last_week("dev_01", now=300.0) == 2
    # After 7 days + 200s, the first two prompts expire
    assert limiter.record_prompt("dev_01", now=7 * 86400.0 + 250.0) is True


def test_keurig_style_volume_runaway_scenario() -> None:
    """Task 73: Verify Keurig-style runaway daily upload to a whitelisted cloud endpoint triggers RESTRICT."""
    from guardian.policy.evaluator import (
        PolicyRuleEvaluator,
        determine_policy_response_action,
        fuse_violations_into_threat_score,
    )
    from guardian.policy.learner import BaselineWindowObservation
    from guardian.policy.templates import resolve_effective_device_rules

    baseline = [
        BaselineWindowObservation(
            device_id="dev_coffee_maker",
            timestamp=float(d * 86400 + i * 600),
            dst_ips=("54.210.10.45",),
            dst_ports=(443,),
            protocols=("HTTPS",),
            upload_bytes=5000,  # 10 windows/day = 50,000 B/day peak
            download_bytes=2000,
        )
        for d in range(3)
        for i in range(10)
    ]
    rules = resolve_effective_device_rules("dev_coffee_maker", baseline, min_baseline_windows=20, created_at=100.0)
    evaluator = PolicyRuleEvaluator()

    # Runaway loop to the same whitelisted cloud IP and HTTPS port, breaching the 125,000 B daily upload budget
    runaway_window = BaselineWindowObservation(
        device_id="dev_coffee_maker",
        timestamp=4 * 86400.0 + 3600.0,
        dst_ips=("54.210.10.45",),
        dst_ports=(443,),
        protocols=("HTTPS",),
        upload_bytes=8000,
        download_bytes=1000,
    )
    checks = evaluator.evaluate_window(
        runaway_window,
        rules,
        cumulative_daily_upload_bytes=450000,
    )
    violations = evaluator.extract_violation_events(runaway_window, checks)
    assert any(v.kind == RuleKind.DAILY_UPLOAD_BUDGET for v in violations)
    assert determine_policy_response_action(violations) == "RESTRICT"
    assert fuse_violations_into_threat_score(20.0, violations) >= 55.0


def test_dji_style_first_time_streaming_scenario() -> None:
    """Task 74: Verify DJI Romo-style first-time camera/audio streaming over whitelisted MQTT broker triggers a user prompt."""
    from guardian.policy.evaluator import (
        PolicyRuleEvaluator,
        build_first_time_streaming_prompt,
        determine_policy_response_action,
    )
    from guardian.policy.learner import BaselineWindowObservation
    from guardian.policy.templates import resolve_effective_device_rules

    baseline = [
        BaselineWindowObservation(
            device_id="dev_romo_vacuum",
            timestamp=float(i * 600),
            dst_ips=("54.210.10.45",),
            dst_ports=(1883,),
            protocols=("MQTT",),
            upload_bytes=1200,  # Normal lightweight status/map telemetry (30 KB/day -> 75 KB daily budget); never streams video
            download_bytes=300,
        )
        for i in range(25)
    ]
    rules = resolve_effective_device_rules("dev_romo_vacuum", baseline, min_baseline_windows=20, created_at=100.0)
    evaluator = PolicyRuleEvaluator()

    # Unauthorized remote camera/audio stream over the same whitelisted cloud broker IP and port (first 10s burst = 25 KB >= 15 KB streaming threshold)
    stream_window = BaselineWindowObservation(
        device_id="dev_romo_vacuum",
        timestamp=20000.0,
        dst_ips=("54.210.10.45",),
        dst_ports=(1883,),
        protocols=("MQTT",),
        upload_bytes=25000,
        download_bytes=500,
    )
    checks = evaluator.evaluate_window(stream_window, rules)
    violations = evaluator.extract_violation_events(stream_window, checks)
    stream_viols = [v for v in violations if v.kind == RuleKind.STREAMING_CAPABILITY]
    assert len(stream_viols) == 1
    assert determine_policy_response_action(violations) == "PROMPT"
    prompt = build_first_time_streaming_prompt(stream_viols[0], dst_ip="54.210.10.45")
    assert prompt is not None
    assert "dev_romo_vacuum" in prompt.message


def test_flagged_windows_never_become_learned_rules() -> None:
    """Task 75: Verify flagged anomalous windows (is_flagged=True) are strictly excluded from all learned rules."""
    from guardian.policy.learner import (
        BaselineWindowObservation,
        learn_active_hours,
        learn_daily_download_budget,
        learn_daily_upload_budget,
        learn_destination_allowlist,
        learn_port_and_protocol_allowlist,
        learn_streaming_capability,
    )

    obs = [
        BaselineWindowObservation(
            device_id="dev_01",
            timestamp=10 * 3600.0,
            dst_ips=("192.168.1.1",),
            dst_ports=(1883,),
            protocols=("MQTT",),
            upload_bytes=500,
            download_bytes=400,
            is_flagged=False,
        ),
        BaselineWindowObservation(
            device_id="dev_01",
            timestamp=3 * 3600.0,
            dst_ips=("198.51.100.66",),
            dst_ports=(23, 4444),
            protocols=("TELNET",),
            upload_bytes=900000,
            download_bytes=800000,
            is_flagged=True,
        ),
        BaselineWindowObservation(
            device_id="dev_01",
            timestamp=3 * 3600.0 + 10.0,
            dst_ips=("198.51.100.66",),
            dst_ports=(23, 4444),
            protocols=("TELNET",),
            upload_bytes=900000,
            download_bytes=800000,
            is_flagged=True,
        ),
    ]
    r_dst = learn_destination_allowlist("dev_01", obs, created_at=100.0)
    r_port = learn_port_and_protocol_allowlist("dev_01", obs, created_at=100.0)
    r_hrs = learn_active_hours("dev_01", obs, created_at=100.0)
    r_up = learn_daily_upload_budget("dev_01", obs, margin=2.0, created_at=100.0)
    r_down = learn_daily_download_budget("dev_01", obs, margin=2.0, created_at=100.0)
    r_stream = learn_streaming_capability("dev_01", obs, created_at=100.0)

    assert "198.51.100.66" not in r_dst.parameters["allowed_ips"]
    assert 23 not in r_port.parameters["allowed_ports"] and 4444 not in r_port.parameters["allowed_ports"]
    assert "TELNET" not in r_port.parameters["allowed_protocols"]
    assert 3 not in r_hrs.parameters["active_hours_utc"]
    assert r_up.parameters["peak_daily_upload_bytes"] == 500
    assert r_down.parameters["peak_daily_download_bytes"] == 400
    assert r_stream.parameters["ever_streams"] is False
