"""Unique identifier generation utilities for GUARDIAN."""

import uuid


def generate_uuid() -> str:
    """Generate a standard UUID4 hex string."""
    return uuid.uuid4().hex


def generate_alert_id() -> str:
    """Generate a prefixed alert identifier."""
    return f"alt_{uuid.uuid4().hex[:12]}"


def generate_action_id() -> str:
    """Generate a prefixed response action identifier."""
    return f"act_{uuid.uuid4().hex[:12]}"


def generate_device_id(name: str) -> str:
    """Generate a sanitized device identifier."""
    sanitized = "".join(c if c.isalnum() else "_" for c in name.lower())
    return f"{sanitized}_{uuid.uuid4().hex[:6]}"
