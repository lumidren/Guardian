"""
Zero-config baseline policy learner for GUARDIAN (Tasks 57-63, 75).
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, field

from .models import PolicyRule, RuleKind, RuleScope, RuleSource


@dataclass(frozen=True)
class BaselineWindowObservation:
    """Observation of a single 10s window used for zero-config policy learning."""

    device_id: str
    timestamp: float
    dst_ips: tuple[str, ...] = field(default_factory=tuple)
    dst_ports: tuple[int, ...] = field(default_factory=tuple)
    protocols: tuple[str, ...] = field(default_factory=tuple)
    upload_bytes: int = 0
    download_bytes: int = 0
    is_flagged: bool = False


def _unflagged(observations: Sequence[BaselineWindowObservation]) -> list[BaselineWindowObservation]:
    """Filter out any window flagged as anomalous so attacks never poison learned rules."""
    return [obs for obs in observations if not obs.is_flagged]


def learn_destination_allowlist(
    device_id: str,
    observations: Sequence[BaselineWindowObservation],
    created_at: float | None = None,
) -> PolicyRule:
    """
    Task 57: Learn the destination IP allowlist from unflagged baseline observations.
    """
    clean = _unflagged(observations)
    allowed_ips = sorted({ip for obs in clean for ip in obs.dst_ips if ip})
    return PolicyRule(
        rule_id=f"rule_dst_allow_{device_id}",
        kind=RuleKind.DESTINATION_ALLOWLIST,
        scope=RuleScope.DEVICE,
        target_id=device_id,
        source=RuleSource.BASELINE_LEARNED,
        parameters={"allowed_ips": allowed_ips, "window_count": len(clean)},
        created_at=time.time() if created_at is None else created_at,
    )


def learn_port_and_protocol_allowlist(
    device_id: str,
    observations: Sequence[BaselineWindowObservation],
    created_at: float | None = None,
) -> PolicyRule:
    """
    Task 58: Learn the destination port and protocol allowlist from unflagged baseline observations.
    """
    clean = _unflagged(observations)
    allowed_ports = sorted({int(p) for obs in clean for p in obs.dst_ports if p > 0})
    allowed_protocols = sorted({proto.upper() for obs in clean for proto in obs.protocols if proto})
    return PolicyRule(
        rule_id=f"rule_port_proto_{device_id}",
        kind=RuleKind.PORT_PROTOCOL_ALLOWLIST,
        scope=RuleScope.DEVICE,
        target_id=device_id,
        source=RuleSource.BASELINE_LEARNED,
        parameters={
            "allowed_ports": allowed_ports,
            "allowed_protocols": allowed_protocols,
            "window_count": len(clean),
        },
        created_at=time.time() if created_at is None else created_at,
    )


def learn_active_hours(
    device_id: str,
    observations: Sequence[BaselineWindowObservation],
    min_bytes_threshold: int = 64,
    created_at: float | None = None,
) -> PolicyRule:
    """
    Task 59: Learn active circadian hours (0..23 UTC) from unflagged baseline observations.
    """
    from datetime import UTC, datetime

    clean = _unflagged(observations)
    active_hours = sorted(
        {
            datetime.fromtimestamp(obs.timestamp, tz=UTC).hour
            for obs in clean
            if (obs.upload_bytes + obs.download_bytes) >= min_bytes_threshold
        }
    )
    if not active_hours:
        active_hours = list(range(24))
    return PolicyRule(
        rule_id=f"rule_active_hours_{device_id}",
        kind=RuleKind.ACTIVE_HOURS,
        scope=RuleScope.DEVICE,
        target_id=device_id,
        source=RuleSource.BASELINE_LEARNED,
        parameters={
            "active_hours_utc": active_hours,
            "min_hour": min(active_hours),
            "max_hour": max(active_hours),
        },
        created_at=time.time() if created_at is None else created_at,
    )


def learn_daily_upload_budget(
    device_id: str,
    observations: Sequence[BaselineWindowObservation],
    margin: float = 2.5,
    created_at: float | None = None,
) -> PolicyRule:
    """
    Task 60: Learn daily upload byte budget as (peak observed daily upload bytes x safety margin)
    across unflagged baseline days.
    """
    clean = _unflagged(observations)
    by_day: dict[int, int] = {}
    for obs in clean:
        day_idx = int(obs.timestamp // 86400.0)
        by_day[day_idx] = by_day.get(day_idx, 0) + max(0, int(obs.upload_bytes))
    peak_daily = max(by_day.values()) if by_day else 1024
    budget_bytes = max(1024, int(round(peak_daily * margin)))
    return PolicyRule(
        rule_id=f"rule_upload_budget_{device_id}",
        kind=RuleKind.DAILY_UPLOAD_BUDGET,
        scope=RuleScope.DEVICE,
        target_id=device_id,
        source=RuleSource.BASELINE_LEARNED,
        parameters={
            "peak_daily_upload_bytes": peak_daily,
            "margin": margin,
            "daily_upload_budget_bytes": budget_bytes,
            "days_observed": len(by_day),
        },
        created_at=time.time() if created_at is None else created_at,
    )
