"""
Unit tests for Sensitivity Analysis and Operating Curve Generator (Milestone P2-5).
Tests threshold sweep monotonicity, optimal operating point selection,
and sensitivity report generation.
"""

from guardian.eval.sensitivity import (
    OperatingCurvePoint,
    SensitivityAnalyzer,
    SensitivityReport,
)


def test_sweep_thresholds_monotonicity() -> None:
    # Synthetic scores: 5 negatives and 5 positives
    y_true = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1]
    scores = [10.0, 20.0, 30.0, 40.0, 50.0, 45.0, 55.0, 70.0, 85.0, 95.0]
    thresholds = [15.0, 35.0, 55.0, 75.0, 90.0]

    analyzer = SensitivityAnalyzer()
    points = analyzer.sweep_thresholds(
        y_true=y_true,
        scores=scores,
        thresholds=thresholds,
        num_devices=1,
        days_observed=1.0,
    )

    assert len(points) == len(thresholds)

    # Monotonicity checks: As threshold increases, TPR and FPR must be non-increasing
    for i in range(len(points) - 1):
        assert points[i].tpr >= points[i + 1].tpr
        assert points[i].fpr >= points[i + 1].fpr


def test_find_optimal_threshold() -> None:
    points = [
        OperatingCurvePoint(threshold=20.0, tpr=1.0, fpr=0.25, precision=0.8, recall=1.0, f1=0.89, false_alerts_per_device_day=5.0),
        OperatingCurvePoint(threshold=40.0, tpr=0.95, fpr=0.08, precision=0.92, recall=0.95, f1=0.93, false_alerts_per_device_day=1.6),
        OperatingCurvePoint(threshold=60.0, tpr=0.90, fpr=0.03, precision=0.97, recall=0.90, f1=0.93, false_alerts_per_device_day=0.6),
        OperatingCurvePoint(threshold=80.0, tpr=0.70, fpr=0.01, precision=0.98, recall=0.70, f1=0.82, false_alerts_per_device_day=0.2),
    ]

    analyzer = SensitivityAnalyzer()
    best = analyzer.find_optimal_threshold(points, target_fpr=0.05)
    # At target FPR <= 0.05, threshold 60.0 has highest TPR (0.90) with FPR=0.03
    assert best.threshold == 60.0
    assert best.fpr <= 0.05
    assert best.tpr == 0.90


def test_sensitivity_report_serialization() -> None:
    points = [
        OperatingCurvePoint(threshold=50.0, tpr=0.88, fpr=0.04, precision=0.95, recall=0.88, f1=0.91, false_alerts_per_device_day=0.8),
    ]
    report = SensitivityReport(
        device_id="dev_test",
        points=points,
        optimal_point=points[0],
        roc_auc=0.945,
    )

    d = report.to_dict()
    assert d["device_id"] == "dev_test"
    assert d["roc_auc"] == 0.945
    assert d["optimal_threshold"] == 50.0
    assert len(d["curve_points"]) == 1
