"""
Calibration and Operating Point Selection Module for GUARDIAN Evaluation.

Chooses the unified operating point threshold on the Day 8 calibration split,
then freezes it for the entire test duration. Resolves audit finding F6 by
guaranteeing that the exact same threshold produces both detection and false alarm metrics.
"""

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np


class FrozenOperatingPointError(Exception):
    """Raised when an attempt is made to mutate a frozen operating point."""


@dataclass
class OperatingPoint:
    """
    Unified operating point thresholds frozen after Day 8 calibration.
    """

    alert_threshold: float
    restrict_threshold: float = 31.0
    quarantine_threshold: float = 61.0
    block_threshold: float = 86.0
    target_calibration_fpr: float = 0.05
    frozen: bool = False

    def is_alert(self, score: float) -> bool:
        """Single canonical evaluation: True if score meets or exceeds alert threshold."""
        return float(score) >= self.alert_threshold

    def update_threshold(self, new_threshold: float) -> None:
        """Attempt to update threshold; fails if frozen."""
        if self.frozen:
            raise FrozenOperatingPointError(
                "Operating point is frozen from Day 8 calibration and cannot be altered during testing."
            )
        self.alert_threshold = float(new_threshold)

    @classmethod
    def default_production(cls) -> "OperatingPoint":
        """Default production thresholds aligned with spec (30/60/85)."""
        return cls(
            alert_threshold=30.0,
            restrict_threshold=31.0,
            quarantine_threshold=61.0,
            block_threshold=86.0,
            target_calibration_fpr=0.05,
            frozen=True,
        )


class Calibrator:
    """
    Selects empirical score threshold on clean calibration split.
    """

    def __init__(self, target_fpr: float = 0.05) -> None:
        if not 0.0 < target_fpr < 1.0:
            raise ValueError(f"Target FPR must be strictly between 0 and 1, got {target_fpr}")
        self.target_fpr = target_fpr

    def calibrate_from_scores(
        self,
        calibration_scores: Sequence[float],
        restrict_offset: float = 1.0,
        quarantine_offset: float = 31.0,
        block_offset: float = 56.0,
    ) -> OperatingPoint:
        """
        Calibrate operating point threshold from empirical score distribution on clean calibration traffic.
        Selects (1 - target_fpr) percentile and freezes the result.
        """
        scores = np.asarray(calibration_scores, dtype=float)
        if len(scores) == 0:
            # Default fallback if empty
            return OperatingPoint.default_production()

        # Percentile matching the desired false positive rate on clean data
        cutoff_percentile = (1.0 - self.target_fpr) * 100.0
        chosen_threshold = float(np.percentile(scores, cutoff_percentile))

        return OperatingPoint(
            alert_threshold=chosen_threshold,
            restrict_threshold=chosen_threshold + restrict_offset,
            quarantine_threshold=chosen_threshold + quarantine_offset,
            block_threshold=chosen_threshold + block_offset,
            target_calibration_fpr=self.target_fpr,
            frozen=True,
        )
