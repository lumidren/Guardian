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
