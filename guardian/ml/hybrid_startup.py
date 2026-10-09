"""
Hybrid Startup Mode for Cold-Start Protection in GUARDIAN (Section 6.1).
Ensures IoT devices are never left unprotected during the initial baseline observation period.
"""

import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from ..config import SystemPhase, config


@dataclass
class StartupState:
    device_id: str
    connected_at: float
    elapsed_hours: float
    current_phase: SystemPhase
    protection_quality: str  # Basic -> Moderate -> Optimal
    samples_collected: int


class HybridStartupManager:
    def __init__(
        self,
        cold_start_hours: float = config.COLD_START_HOURS,
        statistical_hours: float = config.STATISTICAL_HOURS
    ):
        self.cold_start_hours = cold_start_hours
        self.statistical_hours = statistical_hours
        # device_id -> float (connected_at timestamp)
        self.device_start_times: Dict[str, float] = {}
        # device_id -> sample count
        self.sample_counts: Dict[str, int] = {}

    def register_device(self, device_id: str, connected_at: Optional[float] = None):
        """Register a new device joining the IoT network."""
        if device_id not in self.device_start_times:
            self.device_start_times[device_id] = connected_at or time.time()
            self.sample_counts[device_id] = 0

    def increment_samples(self, device_id: str, count: int = 1):
        """Record newly captured traffic samples."""
        self.sample_counts[device_id] = self.sample_counts.get(device_id, 0) + count

    def get_phase(self, device_id: str, current_time: Optional[float] = None) -> StartupState:
        """
        Evaluate current phase and protection tier for the given device.
        """
        now = current_time or time.time()
        start_time = self.device_start_times.get(device_id, now)
        elapsed_seconds = max(0.0, now - start_time)
        elapsed_hours = elapsed_seconds / 3600.0
        samples = self.sample_counts.get(device_id, 0)

        # Allow accelerating phase if sufficient samples gathered in lab testbed
        if elapsed_hours < self.cold_start_hours and samples < 500:
            phase = SystemPhase.COLD_START_OBSERVATION
            quality = "Basic (Whitelist + Rate Limiting)"
        elif elapsed_hours < self.statistical_hours and samples < 2000:
            phase = SystemPhase.STATISTICAL_BASELINE
            quality = "Moderate (Z-Score Statistical Thresholds)"
        else:
            phase = SystemPhase.ACTIVE_PROTECTION
            quality = "Optimal (Multi-Layer Isolation Forest ML + XAI)"

        return StartupState(
            device_id=device_id,
            connected_at=start_time,
            elapsed_hours=elapsed_hours,
            current_phase=phase,
            protection_quality=quality,
            samples_collected=samples
        )
