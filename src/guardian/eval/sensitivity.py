"""
Sensitivity Analysis and Operating Curve Generator for GUARDIAN (Milestone P2-5).

Generates operating curves by sweeping threat score decision thresholds,
measuring detection rate vs false alert rate per device per day, and finding
optimal calibrated operating points.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .metrics import (
    compute_binary_metrics,
    compute_false_alert_rate,
    compute_roc_auc,
)


@dataclass(frozen=True)
class OperatingCurvePoint:
    threshold: float
    tpr: float
    fpr: float
    precision: float
    recall: float
    f1: float
    false_alerts_per_device_day: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "threshold": round(self.threshold, 2),
            "tpr": round(self.tpr, 4),
            "fpr": round(self.fpr, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_alerts_per_device_day": round(self.false_alerts_per_device_day, 4),
        }


@dataclass(frozen=True)
class SensitivityReport:
    device_id: str
    points: list[OperatingCurvePoint]
    optimal_point: OperatingCurvePoint
    roc_auc: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "roc_auc": round(self.roc_auc, 4),
            "optimal_threshold": round(self.optimal_point.threshold, 2),
            "optimal_tpr": round(self.optimal_point.tpr, 4),
            "optimal_fpr": round(self.optimal_point.fpr, 4),
            "optimal_far_per_device_day": round(
                self.optimal_point.false_alerts_per_device_day, 4
            ),
            "curve_points": [p.to_dict() for p in self.points],
        }


class SensitivityAnalyzer:
    """
    Evaluates detector performance across varying threshold operating points.
    """

    def sweep_thresholds(
        self,
        y_true: Sequence[int],
        scores: Sequence[float],
        thresholds: Sequence[float] | None = None,
        num_devices: int = 1,
        days_observed: float = 1.0,
    ) -> list[OperatingCurvePoint]:
        """
        Evaluate classification metrics across a sequence of candidate thresholds.
        """
        if thresholds is None:
            thresholds = [float(x) for x in range(10, 95, 5)]

        points: list[OperatingCurvePoint] = []

        for th in thresholds:
            y_pred = [1 if s >= th else 0 for s in scores]
            metrics = compute_binary_metrics(y_true, y_pred)

            # False alarms: count negative windows that predicted 1
            false_alarms = metrics.fp
            far = compute_false_alert_rate(
                num_false_alerts=false_alarms,
                num_devices=num_devices,
                days_observed=days_observed,
            )

            points.append(
                OperatingCurvePoint(
                    threshold=float(th),
                    tpr=metrics.tpr,
                    fpr=metrics.fpr,
                    precision=metrics.precision,
                    recall=metrics.recall,
                    f1=metrics.f1,
                    false_alerts_per_device_day=far,
                )
            )

        return points

    def find_optimal_threshold(
        self,
        points: Sequence[OperatingCurvePoint],
        target_fpr: float = 0.05,
    ) -> OperatingCurvePoint:
        """
        Select the operating point that maximizes TPR subject to FPR <= target_fpr.
        Falls back to point minimizing FPR if no candidate satisfies the constraint.
        """
        eligible = [p for p in points if p.fpr <= target_fpr]
        if eligible:
            # Sort by highest TPR, then highest F1
            eligible.sort(key=lambda p: (p.tpr, p.f1), reverse=True)
            return eligible[0]

        # Fallback: select point with minimum FPR
        sorted_by_fpr = sorted(points, key=lambda p: p.fpr)
        return sorted_by_fpr[0]

    def generate_report(
        self,
        device_id: str,
        y_true: Sequence[int],
        scores: Sequence[float],
        thresholds: Sequence[float] | None = None,
        target_fpr: float = 0.05,
        num_devices: int = 1,
        days_observed: float = 1.0,
    ) -> SensitivityReport:
        """Generate comprehensive sensitivity report for a device score stream."""
        points = self.sweep_thresholds(
            y_true=y_true,
            scores=scores,
            thresholds=thresholds,
            num_devices=num_devices,
            days_observed=days_observed,
        )
        best = self.find_optimal_threshold(points, target_fpr=target_fpr)
        # Normalize scores to [0, 1] for ROC-AUC
        max_s = max(scores) if scores else 1.0
        norm_scores = [s / max(1.0, max_s) for s in scores]
        auc = compute_roc_auc(y_true, norm_scores)

        return SensitivityReport(
            device_id=device_id,
            points=points,
            optimal_point=best,
            roc_auc=auc,
        )
