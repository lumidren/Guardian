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
