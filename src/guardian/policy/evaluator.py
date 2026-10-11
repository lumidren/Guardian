"""
Policy rule evaluator, violation events, threat score integration, and user decision manager
for GUARDIAN (Phase 4 Section D, Tasks 66-76).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .learner import BaselineWindowObservation
from .models import PolicyRule, RuleKind, RuleSource


@dataclass(frozen=True)
class RuleViolationEvent:
    """Task 67: Structured policy rule violation event emitted by `PolicyRuleEvaluator`."""

    event_id: str
    device_id: str
    timestamp: float
    rule_id: str
    kind: RuleKind
    source: RuleSource
    severity: float
    reason: str


class PolicyRuleEvaluator:
    """Task 66: Evaluates a window observation against a set of active `PolicyRule` constraints."""

    def evaluate_window(
        self,
        obs: BaselineWindowObservation,
        rules: Sequence[PolicyRule],
        cumulative_daily_upload_bytes: int | None = None,
        cumulative_daily_download_bytes: int | None = None,
        streaming_threshold_bytes: int = 15000,
    ) -> list[dict[str, Any]]:
        """
        Evaluate `obs` against all non-expired `rules` for `obs.device_id`.
        Returns a list of rule check dicts (`passed: bool`, `rule_id`, `kind`, `reason`).
        """
        results: list[dict[str, Any]] = []
        up_total = obs.upload_bytes if cumulative_daily_upload_bytes is None else cumulative_daily_upload_bytes
        down_total = obs.download_bytes if cumulative_daily_download_bytes is None else cumulative_daily_download_bytes

        for rule in rules:
            if rule.is_expired(obs.timestamp):
                continue
            passed = True
            reason = "ok"

            if rule.kind == RuleKind.DESTINATION_ALLOWLIST:
                allowed_ips = set(rule.parameters.get("allowed_ips", []))
                unauthorized = sorted(set(obs.dst_ips) - allowed_ips)
                if unauthorized:
                    passed = False
                    reason = f"Unauthorized destination IPs: {unauthorized}"

            elif rule.kind == RuleKind.PORT_PROTOCOL_ALLOWLIST:
                allowed_ports = {int(p) for p in rule.parameters.get("allowed_ports", [])}
                allowed_protos = {str(p).upper() for p in rule.parameters.get("allowed_protocols", [])}
                bad_ports = sorted({int(p) for p in obs.dst_ports if p > 0} - allowed_ports)
                bad_protos = sorted({str(p).upper() for p in obs.protocols if p} - allowed_protos)
                if bad_ports or bad_protos:
                    passed = False
                    reason = f"Unauthorized ports={bad_ports} or protocols={bad_protos}"

            elif rule.kind == RuleKind.ACTIVE_HOURS:
                allowed_hours = {int(h) for h in rule.parameters.get("active_hours_utc", range(24))}
                hr = datetime.fromtimestamp(obs.timestamp, tz=UTC).hour
                if (obs.upload_bytes + obs.download_bytes) >= 64 and hr not in allowed_hours:
                    passed = False
                    reason = f"Traffic during inactive UTC hour {hr}"

            elif rule.kind == RuleKind.DAILY_UPLOAD_BUDGET:
                budget = int(rule.parameters.get("daily_upload_budget_bytes", 0))
                if budget > 0 and up_total > budget:
                    passed = False
                    reason = f"Daily upload {up_total} B exceeds budget {budget} B"

            elif rule.kind == RuleKind.DAILY_DOWNLOAD_BUDGET:
                budget = int(rule.parameters.get("daily_download_budget_bytes", 0))
                if budget > 0 and down_total > budget:
                    passed = False
                    reason = f"Daily download {down_total} B exceeds budget {budget} B"

            elif rule.kind == RuleKind.STREAMING_CAPABILITY:
                ever_streams = bool(rule.parameters.get("ever_streams", False))
                thresh = int(rule.parameters.get("streaming_window_bytes_threshold", streaming_threshold_bytes))
                if not ever_streams and obs.upload_bytes >= thresh:
                    passed = False
                    reason = f"First-time streaming upload ({obs.upload_bytes} B >= {thresh} B) on non-streaming device"

            results.append(
                {
                    "rule_id": rule.rule_id,
                    "kind": rule.kind,
                    "source": rule.source,
                    "passed": passed,
                    "reason": reason,
                }
            )
        return results

    def extract_violation_events(
        self,
        obs: BaselineWindowObservation,
        evaluation_results: Sequence[dict[str, Any]],
    ) -> list[RuleViolationEvent]:
        """Task 67: Convert failed rule evaluation results into structured `RuleViolationEvent` objects."""
        severity_by_kind: dict[RuleKind, float] = {
            RuleKind.DESTINATION_ALLOWLIST: 25.0,
            RuleKind.PORT_PROTOCOL_ALLOWLIST: 20.0,
            RuleKind.ACTIVE_HOURS: 15.0,
            RuleKind.DAILY_UPLOAD_BUDGET: 35.0,
            RuleKind.DAILY_DOWNLOAD_BUDGET: 30.0,
            RuleKind.STREAMING_CAPABILITY: 40.0,
        }
        events: list[RuleViolationEvent] = []
        for idx, res in enumerate(evaluation_results):
            if res.get("passed", True):
                continue
            kind = RuleKind(str(res["kind"]))
            src = RuleSource(str(res["source"]))
            events.append(
                RuleViolationEvent(
                    event_id=f"viol_{obs.device_id}_{int(obs.timestamp)}_{idx}",
                    device_id=obs.device_id,
                    timestamp=obs.timestamp,
                    rule_id=str(res["rule_id"]),
                    kind=kind,
                    source=src,
                    severity=severity_by_kind.get(kind, 20.0),
                    reason=str(res["reason"]),
                )
            )
        return events
