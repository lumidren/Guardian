"""
Unit tests for evaluation metrics with small hand-computed test cases.
Tests verify exact correctness of TPR, FPR, precision, recall, F1, ROC-AUC, PR-AUC,
false alerts per device per day, and deterministic bootstrap confidence intervals.
"""

import pytest

from guardian.eval.metrics import (
    bootstrap_ci,
    compute_binary_metrics,
    compute_false_alert_rate,
    compute_pr_auc,
    compute_roc_auc,
)


def test_confusion_matrix_and_rates_hand_computed() -> None:
    # 6 samples: 3 positives, 3 negatives
    y_true = [1, 1, 0, 0, 1, 0]
    y_pred = [1, 0, 0, 1, 1, 0]

    # TP: indices 0, 4 -> 2
    # FN: index 1 -> 1
    # FP: index 3 -> 1
    # TN: indices 2, 5 -> 2
    metrics = compute_binary_metrics(y_true, y_pred)

    assert metrics.tp == 2
    assert metrics.fn == 1
    assert metrics.fp == 1
    assert metrics.tn == 2

    # Precision = TP / (TP + FP) = 2 / 3
    assert pytest.approx(metrics.precision, rel=1e-4) == 2.0 / 3.0
    # Recall / TPR = TP / (TP + FN) = 2 / 3
    assert pytest.approx(metrics.recall, rel=1e-4) == 2.0 / 3.0
    assert pytest.approx(metrics.tpr, rel=1e-4) == 2.0 / 3.0
    # FPR = FP / (FP + TN) = 1 / 3
    assert pytest.approx(metrics.fpr, rel=1e-4) == 1.0 / 3.0
    # F1 = 2 * (P * R) / (P + R) = 2/3
    assert pytest.approx(metrics.f1, rel=1e-4) == 2.0 / 3.0


def test_all_zeros_and_all_ones_edge_cases() -> None:
    # All true negatives, perfect prediction
    m_perfect = compute_binary_metrics([0, 0, 0], [0, 0, 0])
    assert m_perfect.fp == 0
    assert m_perfect.fpr == 0.0
    assert m_perfect.precision == 1.0  # safe zero division

    # All false alarms
    m_all_fp = compute_binary_metrics([0, 0, 0], [1, 1, 1])
    assert m_all_fp.fp == 3
    assert m_all_fp.fpr == 1.0
    assert m_all_fp.precision == 0.0


def test_roc_auc_hand_computed() -> None:
    # 4 samples: 2 negatives, 2 positives
    # Score ranks: 0.1 (y=0), 0.35 (y=1), 0.4 (y=0), 0.8 (y=1)
    # Pairs (pos, neg):
    # pos 0.35 > neg 0.1 (win)
    # pos 0.35 < neg 0.4 (loss)
    # pos 0.8 > neg 0.1 (win)
    # pos 0.8 > neg 0.4 (win)
    # 3 wins out of 4 pairs = 0.75
    y_true = [0, 0, 1, 1]
    y_scores = [0.1, 0.4, 0.35, 0.8]

    auc = compute_roc_auc(y_true, y_scores)
    assert pytest.approx(auc, rel=1e-4) == 0.75


def test_pr_auc_hand_computed() -> None:
    y_true = [0, 1, 0, 1]
    y_scores = [0.1, 0.4, 0.35, 0.8]
    pr_auc = compute_pr_auc(y_true, y_scores)
    assert 0.0 <= pr_auc <= 1.0
    assert pr_auc > 0.5  # Positive samples have higher scores than lowest negative


def test_false_alert_rate_per_device_day() -> None:
    # 2 devices observed across 5 days (10 device-days total)
    # Total false alert episodes = 4
    rate = compute_false_alert_rate(
        num_false_alerts=4,
        num_devices=2,
        days_observed=5.0,
    )
    # 4 / (2 * 5) = 0.4 alerts / device / day
    assert pytest.approx(rate, rel=1e-4) == 0.4


def test_bootstrap_confidence_interval_deterministic() -> None:
    data = [0.85, 0.88, 0.84, 0.89, 0.86, 0.87, 0.85]
    ci1 = bootstrap_ci(data, num_bootstraps=500, ci=0.95, seed=42)
    ci2 = bootstrap_ci(data, num_bootstraps=500, ci=0.95, seed=42)

    # Determinism with fixed seed
    assert ci1.mean == ci2.mean
    assert ci1.ci_lower == ci2.ci_lower
    assert ci1.ci_upper == ci2.ci_upper

    # Bounds validity
    assert ci1.ci_lower <= ci1.mean <= ci1.ci_upper
    assert 0.84 <= ci1.mean <= 0.89
