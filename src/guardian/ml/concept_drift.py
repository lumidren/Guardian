"""
Adaptive profile updating and Concept Drift handling for GUARDIAN (Section 6.2).
Prevents false positives caused by firmware updates and legitimate behavioral evolution.
"""

from dataclasses import dataclass
from enum import StrEnum

import numpy as np

from ..config import FEATURE_NAMES, config


class DriftAction(StrEnum):
    NO_DRIFT = "NO_DRIFT"                                 # <5% variation
    MINOR_AUTOMATIC = "MINOR_AUTOMATIC"                   # <10% drift: automatically adjust baseline
    MODERATE_USER_CONFIRM = "MODERATE_USER_CONFIRM"       # 10-30% drift: prompt user for approval
    MAJOR_ALERT = "MAJOR_ALERT"                           # >30% drift: alert user (possible firmware update/compromise)


@dataclass
class DriftReport:
    device_id: str
    overall_drift_ratio: float
    action: DriftAction
    feature_drifts: dict[str, float]
    recommendation: str


class ConceptDriftDetector:
    def __init__(
        self,
        minor_threshold: float = config.DRIFT_MINOR_THRESHOLD,
        moderate_threshold: float = config.DRIFT_MODERATE_THRESHOLD
    ):
        self.minor_threshold = minor_threshold
        self.moderate_threshold = moderate_threshold

    def calculate_drift(
        self,
        baseline_means: dict[str, float],
        recent_samples: np.ndarray,
        device_id: str = "unknown"
    ) -> DriftReport:
        """
        Calculate concept drift between historical baseline and recent observation window.
        """
        if recent_samples.shape[0] < 10 or not baseline_means:
            return DriftReport(
                device_id=device_id,
                overall_drift_ratio=0.0,
                action=DriftAction.NO_DRIFT,
                feature_drifts={},
                recommendation="Insufficient samples for drift assessment."
            )

        recent_means = np.mean(recent_samples, axis=0)
        feature_drifts: dict[str, float] = {}
        drift_ratios = []

        for i, name in enumerate(FEATURE_NAMES):
            base_m = baseline_means.get(name, 0.0)
            rec_m = float(recent_means[i])
            denominator = max(1.0, abs(base_m))
            rel_change = abs(rec_m - base_m) / denominator
            feature_drifts[name] = float(rel_change)
            drift_ratios.append(rel_change)

        overall_drift = float(np.mean(drift_ratios))

        if overall_drift < 0.05:
            action = DriftAction.NO_DRIFT
            rec = "Baseline nominal. No significant concept drift observed."
        elif overall_drift < self.minor_threshold:
            action = DriftAction.MINOR_AUTOMATIC
            rec = "Automatic minor profile adjustment applied. Safe legitimate evolution."
        elif overall_drift <= self.moderate_threshold:
            action = DriftAction.MODERATE_USER_CONFIRM
            rec = "Moderate drift detected (10-30%). Recommended: Ask user 'Did you change device settings or schedule?'"
        else:
            action = DriftAction.MAJOR_ALERT
            rec = "CRITICAL: Major profile drift (>30%). Alert generated: 'Possible firmware update or stealthy persistence. Review device behavior.'"

        return DriftReport(
            device_id=device_id,
            overall_drift_ratio=overall_drift,
            action=action,
            feature_drifts=feature_drifts,
            recommendation=rec
        )
