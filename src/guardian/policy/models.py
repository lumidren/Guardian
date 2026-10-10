"""
Auto-Learned Zero-Config Policy Data Models for GUARDIAN (Phase 4 Section D, Tasks 55-76).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RuleScope(StrEnum):
    """Scope at which a policy rule applies."""

    DEVICE = "device"
    DEVICE_TYPE = "device_type"
    GLOBAL = "global"


class RuleSource(StrEnum):
    """Provenance of a policy rule."""

    BASELINE_LEARNED = "baseline_learned"
    DEFAULT_TEMPLATE = "default_template"
    USER_DECISION = "user_decision"


class RuleKind(StrEnum):
    """Category of behavioral policy constraint."""

    DESTINATION_ALLOWLIST = "destination_allowlist"
    PORT_PROTOCOL_ALLOWLIST = "port_protocol_allowlist"
    ACTIVE_HOURS = "active_hours"
    DAILY_UPLOAD_BUDGET = "daily_upload_budget"
    DAILY_DOWNLOAD_BUDGET = "daily_download_budget"
    STREAMING_CAPABILITY = "streaming_capability"


class DecisionMode(StrEnum):
    """User prompt decision persistence mode."""

    ONCE = "once"
    ALWAYS = "always"
    BLOCK = "block"


@dataclass(frozen=True)
class PolicyRule:
    """
    Task 55: Immutable policy rule data model specifying rule kind, target scope,
    provenance source, constraint parameters, creation timestamp, and optional expiry.
    """

    rule_id: str
    kind: RuleKind
    scope: RuleScope
    target_id: str
    source: RuleSource
    parameters: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    expires_at: float | None = None

    def is_expired(self, now: float | None = None) -> bool:
        """Return True if the rule has an expiry timestamp and `now >= expires_at`."""
        if self.expires_at is None:
            return False
        current = time.time() if now is None else now
        return current >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "kind": str(self.kind),
            "scope": str(self.scope),
            "target_id": self.target_id,
            "source": str(self.source),
            "parameters": dict(self.parameters),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }
