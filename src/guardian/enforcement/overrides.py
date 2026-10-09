"""
User override and feedback learning loop for GUARDIAN (Section 6.6).
Allows one-click unblock and updates device baseline to prevent repeat false positives.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class OverrideEvent:
    device_id: str
    previous_level: str
    requested_level: str
    timestamp: float
    user_note: str


class UserOverrideManager:
    def __init__(self) -> None:
        self.override_history: list[OverrideEvent] = []
        self.active_overrides: dict[str, str] = {}
        self._on_override_callbacks: list[Callable[[str, str], None]] = []

    def register_callback(self, cb: Callable[[str, str], None]) -> None:
        """Callback triggered when an override occurs to update baseline."""
        self._on_override_callbacks.append(cb)

    def request_override(self, device_id: str, new_level: str = "MONITOR", note: str = "User verified safe"):
        """Execute manual user override."""
        event = OverrideEvent(
            device_id=device_id,
            previous_level=self.active_overrides.get(device_id, "BLOCK"),
            requested_level=new_level,
            timestamp=time.time(),
            user_note=note
        )
        self.override_history.append(event)
        self.active_overrides[device_id] = new_level

        for cb in self._on_override_callbacks:
            try:
                cb(device_id, new_level)
            except Exception:
                pass

    def is_overridden(self, device_id: str) -> bool:
        return device_id in self.active_overrides

    def get_override_level(self, device_id: str) -> str | None:
        return self.active_overrides.get(device_id)

    def clear_override(self, device_id: str):
        self.active_overrides.pop(device_id, None)
