"""
Device-type default policy templates loader for cold-start protection (Tasks 64-65).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .models import PolicyRule, RuleKind, RuleScope, RuleSource

DEFAULT_TEMPLATE_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent / "config" / "device_type_templates.yaml"
)


def load_device_type_templates(template_path: Path | str | None = None) -> dict[str, dict[str, Any]]:
    """
    Task 64: Load per-device-type default policy templates from `config/device_type_templates.yaml`.
    """
    path = Path(template_path) if template_path is not None else DEFAULT_TEMPLATE_PATH
    text = path.read_text(encoding="utf-8")
    raw = json.loads(text)
    device_types = raw.get("device_types", {})
    return dict(device_types)


def build_template_rules_for_device_type(
    device_id: str,
    device_type: str,
    template_path: Path | str | None = None,
    created_at: float | None = None,
) -> list[PolicyRule]:
    """
    Task 64: Instantiate the 6 default `PolicyRule` objects (`RuleSource.DEFAULT_TEMPLATE`)
    for a given device and inferred/declared `device_type`.
    """
    templates = load_device_type_templates(template_path)
    tpl = templates.get(device_type) or templates["Environmental Sensor"]
    ts = time.time() if created_at is None else created_at

    return [
        PolicyRule(
            rule_id=f"tpl_dst_allow_{device_id}",
            kind=RuleKind.DESTINATION_ALLOWLIST,
            scope=RuleScope.DEVICE_TYPE,
            target_id=device_id,
            source=RuleSource.DEFAULT_TEMPLATE,
            parameters={"allowed_ips": list(tpl["allowed_ips"]), "device_type": device_type},
            created_at=ts,
        ),
        PolicyRule(
            rule_id=f"tpl_port_proto_{device_id}",
            kind=RuleKind.PORT_PROTOCOL_ALLOWLIST,
            scope=RuleScope.DEVICE_TYPE,
            target_id=device_id,
            source=RuleSource.DEFAULT_TEMPLATE,
            parameters={
                "allowed_ports": list(tpl["allowed_ports"]),
                "allowed_protocols": list(tpl["allowed_protocols"]),
                "device_type": device_type,
            },
            created_at=ts,
        ),
        PolicyRule(
            rule_id=f"tpl_active_hours_{device_id}",
            kind=RuleKind.ACTIVE_HOURS,
            scope=RuleScope.DEVICE_TYPE,
            target_id=device_id,
            source=RuleSource.DEFAULT_TEMPLATE,
            parameters={"active_hours_utc": list(tpl["active_hours_utc"]), "device_type": device_type},
            created_at=ts,
        ),
        PolicyRule(
            rule_id=f"tpl_upload_budget_{device_id}",
            kind=RuleKind.DAILY_UPLOAD_BUDGET,
            scope=RuleScope.DEVICE_TYPE,
            target_id=device_id,
            source=RuleSource.DEFAULT_TEMPLATE,
            parameters={
                "daily_upload_budget_bytes": int(tpl["daily_upload_budget_bytes"]),
                "device_type": device_type,
            },
            created_at=ts,
        ),
        PolicyRule(
            rule_id=f"tpl_download_budget_{device_id}",
            kind=RuleKind.DAILY_DOWNLOAD_BUDGET,
            scope=RuleScope.DEVICE_TYPE,
            target_id=device_id,
            source=RuleSource.DEFAULT_TEMPLATE,
            parameters={
                "daily_download_budget_bytes": int(tpl["daily_download_budget_bytes"]),
                "device_type": device_type,
            },
            created_at=ts,
        ),
        PolicyRule(
            rule_id=f"tpl_streaming_cap_{device_id}",
            kind=RuleKind.STREAMING_CAPABILITY,
            scope=RuleScope.DEVICE_TYPE,
            target_id=device_id,
            source=RuleSource.DEFAULT_TEMPLATE,
            parameters={"ever_streams": bool(tpl["ever_streams"]), "device_type": device_type},
            created_at=ts,
        ),
    ]


def resolve_effective_device_rules(
    device_id: str,
    observations: list[Any],
    min_baseline_windows: int = 50,
    created_at: float | None = None,
) -> list[PolicyRule]:
    """
    Task 65: Return device-type default template rules while the device's baseline
    has fewer than `min_baseline_windows` unflagged windows; once ready, return
    the learned per-device baseline rules.
    """
    from .learner import (
        guess_device_type_from_traffic,
        learn_active_hours,
        learn_daily_download_budget,
        learn_daily_upload_budget,
        learn_destination_allowlist,
        learn_port_and_protocol_allowlist,
        learn_streaming_capability,
    )

    unflagged = [o for o in observations if not o.is_flagged]
    if len(unflagged) < min_baseline_windows:
        guessed_type = guess_device_type_from_traffic(unflagged)
        return build_template_rules_for_device_type(
            device_id=device_id,
            device_type=guessed_type,
            created_at=created_at,
        )

    return [
        learn_destination_allowlist(device_id, unflagged, created_at=created_at),
        learn_port_and_protocol_allowlist(device_id, unflagged, created_at=created_at),
        learn_active_hours(device_id, unflagged, created_at=created_at),
        learn_daily_upload_budget(device_id, unflagged, created_at=created_at),
        learn_daily_download_budget(device_id, unflagged, created_at=created_at),
        learn_streaming_capability(device_id, unflagged, created_at=created_at),
    ]
