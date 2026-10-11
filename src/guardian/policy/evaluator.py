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


def fuse_violations_into_threat_score(
    base_threat_score: float,
    violations: Sequence[RuleViolationEvent],
    max_score: float = 100.0,
) -> float:
    """
    Task 68: Feed policy rule violation events into the fused threat score [0, 100].
    Learned/user-decided rule violations receive full weight (1.0x); cold-start template
    violations receive 0.75x weight.
    """
    bonus = 0.0
    for v in violations:
        weight = 0.75 if v.source == RuleSource.DEFAULT_TEMPLATE else 1.0
        bonus += v.severity * weight
    return float(min(max_score, max(0.0, base_threat_score + bonus)))


def determine_policy_response_action(violations: Sequence[RuleViolationEvent]) -> str:
    """
    Task 69: Determine automatic containment/response tier from policy violations.
    Daily upload or download budget breaches automatically trigger `RESTRICT` (rate-limiting/throttling).
    """
    if not violations:
        return "MONITOR"
    kinds = {v.kind for v in violations}
    if RuleKind.DAILY_UPLOAD_BUDGET in kinds or RuleKind.DAILY_DOWNLOAD_BUDGET in kinds:
        return "RESTRICT"
    if RuleKind.STREAMING_CAPABILITY in kinds:
        return "PROMPT"
    return "ALERT"


@dataclass(frozen=True)
class UserPromptRequest:
    """Task 70: User-facing confirmation prompt triggered by first-time streaming or sensitive policy violation."""

    prompt_id: str
    device_id: str
    timestamp: float
    rule_kind: RuleKind
    subject_key: str
    message: str
    options: tuple[str, ...] = ("once", "always", "block")


def build_first_time_streaming_prompt(
    violation: RuleViolationEvent,
    dst_ip: str = "external",
) -> UserPromptRequest | None:
    """
    Task 70: Generate a user decision prompt (`once`, `always`, `block`) when a device
    that has never streamed media initiates a high-throughput streaming upload.
    """
    if violation.kind != RuleKind.STREAMING_CAPABILITY:
        return None
    return UserPromptRequest(
        prompt_id=f"prompt_{violation.device_id}_{int(violation.timestamp)}",
        device_id=violation.device_id,
        timestamp=violation.timestamp,
        rule_kind=RuleKind.STREAMING_CAPABILITY,
        subject_key=f"stream:{dst_ip}",
        message=(
            f"Device {violation.device_id} initiated first-time high-throughput streaming "
            f"to {dst_ip}: {violation.reason}. Allow once, always allow, or block?"
        ),
    )


class PolicyDecisionManager:
    """
    Task 71: Remembers user prompt decisions (`once` / `always` / `block`) and resolves
    whether subsequent events for `(device_id, rule_kind, subject_key)` are pre-authorized or blocked.
    """

    def __init__(self, store: Any, once_ttl_seconds: float = 300.0) -> None:
        self.store = store
        self.once_ttl_seconds = once_ttl_seconds

    def apply_user_decision(
        self,
        prompt: UserPromptRequest,
        mode: Any,
        now: float | None = None,
    ) -> None:
        from .models import DecisionMode, RuleScope

        dec_mode = DecisionMode(str(mode))
        ts = prompt.timestamp if now is None else now
        expires_at = (ts + self.once_ttl_seconds) if dec_mode == DecisionMode.ONCE else None
        self.store.record_decision(
            decision_id=f"dec_{prompt.prompt_id}",
            device_id=prompt.device_id,
            rule_kind=prompt.rule_kind,
            subject_key=prompt.subject_key,
            mode=dec_mode,
            created_at=ts,
            expires_at=expires_at,
        )
        if dec_mode == DecisionMode.ALWAYS and prompt.rule_kind == RuleKind.STREAMING_CAPABILITY:
            self.store.upsert_rule(
                PolicyRule(
                    rule_id=f"user_stream_allow_{prompt.device_id}",
                    kind=RuleKind.STREAMING_CAPABILITY,
                    scope=RuleScope.DEVICE,
                    target_id=prompt.device_id,
                    source=RuleSource.USER_DECISION,
                    parameters={"ever_streams": True, "subject_key": prompt.subject_key},
                    created_at=ts,
                )
            )

    def resolve_decision(
        self,
        device_id: str,
        rule_kind: RuleKind,
        subject_key: str,
        now: float,
    ) -> str | None:
        """Return 'ALLOW' (for active ONCE or ALWAYS), 'BLOCK' (for BLOCK), or None if undecided."""
        rows = self.store.get_decisions(device_id)
        matched = [
            r for r in rows
            if r["rule_kind"] == str(rule_kind) and r["subject_key"] == subject_key
        ]
        if not matched:
            return None
        latest = matched[-1]
        exp = latest.get("expires_at")
        if exp is not None and now >= float(exp):
            return None
        mode_str = str(latest["mode"])
        if mode_str in ("once", "always"):
            return "ALLOW"
        if mode_str == "block":
            return "BLOCK"
        return None


class PromptRateLimiter:
    """
    Task 72: Enforces a rolling 7-day rate limit on interactive user prompts per device
    (default `max_prompts_per_device_week = 3`) to prevent alert fatigue.
    """

    WEEK_SECONDS = 7 * 86400.0

    def __init__(self, max_prompts_per_device_week: int = 3) -> None:
        self.max_prompts_per_device_week = max_prompts_per_device_week
        self._history: dict[str, list[float]] = {}

    def can_prompt(self, device_id: str, now: float) -> bool:
        cutoff = now - self.WEEK_SECONDS
        recent = [ts for ts in self._history.get(device_id, []) if ts > cutoff]
        self._history[device_id] = recent
        return len(recent) < self.max_prompts_per_device_week

    def record_prompt(self, device_id: str, now: float) -> bool:
        """Record a prompt if under the weekly limit; returns False if rate-limited."""
        if not self.can_prompt(device_id, now):
            return False
        self._history.setdefault(device_id, []).append(now)
        return True

    def prompts_in_last_week(self, device_id: str, now: float) -> int:
        cutoff = now - self.WEEK_SECONDS
        return sum(1 for ts in self._history.get(device_id, []) if ts > cutoff)
