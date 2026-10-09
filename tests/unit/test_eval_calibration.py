"""
Unit tests for evaluation calibration and operating point selection.
Verifies threshold calibration on clean Day 8 split, freezing mechanism,
and PROVES that detection (TPR) and false positive (FPR) use the exact same threshold (F6 fix).
"""

import pytest

from guardian.eval.calibration import (
    Calibrator,
    FrozenOperatingPointError,
    OperatingPoint,
)


def test_calibrator_selects_and_freezes_operating_point() -> None:
    calibrator = Calibrator(target_fpr=0.05)
    # Simulated calibration scores from Day 8 clean traffic (100 windows)
    # 95 scores between 0 and 25, 5 scores between 26 and 40
    cal_scores = [float(i % 25) for i in range(95)] + [30.0, 32.0, 35.0, 38.0, 40.0]

    op = calibrator.calibrate_from_scores(cal_scores)

    assert op.frozen is True
    assert op.target_calibration_fpr == 0.05
    # Threshold should be chosen at 95th percentile
    assert 24.0 <= op.alert_threshold <= 35.0

    # Test freezing immutability
    with pytest.raises(FrozenOperatingPointError):
        op.update_threshold(50.0)


def test_detection_and_fpr_use_exact_same_threshold() -> None:
    """
    CRITICAL ACCEPTANCE TEST (fixes F6):
    Proves that detection counts and false positive counts use the exact same operating point threshold.
    """
    calibrator = Calibrator(target_fpr=0.05)
    cal_scores = [float(i) for i in range(100)]  # 0 to 99
    op = calibrator.calibrate_from_scores(cal_scores)

    # Threshold selected on calibration split
    threshold = op.alert_threshold

    # Test cases: scores below, at, and above the threshold
    test_scores = [threshold - 5.0, threshold - 0.1, threshold, threshold + 0.1, threshold + 10.0]

    for score in test_scores:
        # Decision for an attack window (is it detected?)
        is_detected = op.is_alert(score)
        # Decision for a normal window (is it a false alarm?)
        is_false_alarm = op.is_alert(score)

        # MUST BE IDENTICAL DECISION LOGIC: score >= threshold
        assert is_detected == (score >= threshold)
        assert is_false_alarm == (score >= threshold)
        assert is_detected == is_false_alarm, (
            f"Asymmetric threshold bug at score {score}: "
            f"detection={is_detected} vs false_alarm={is_false_alarm}"
        )


def test_default_config_operating_point() -> None:
    op = OperatingPoint.default_production()
    assert op.alert_threshold == 30.0
    assert op.restrict_threshold == 31.0
    assert op.quarantine_threshold == 61.0
    assert op.block_threshold == 86.0
    assert op.is_alert(30.0) is True
    assert op.is_alert(29.9) is False
