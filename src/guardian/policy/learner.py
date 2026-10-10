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
