"""
Evaluation metrics calculation module for GUARDIAN.

Provides deterministic calculations for confusion matrix rates, ROC-AUC, PR-AUC,
false alerts per device per day, and bootstrap confidence intervals.
"""

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class BinaryMetrics:
    tp: int
    fn: int
    fp: int
    tn: int
    tpr: float
    fpr: float
    precision: float
    recall: float
    f1: float


@dataclass(frozen=True)
class BootstrapCI:
    mean: float
    ci_lower: float
    ci_upper: float
    ci_level: float


def compute_binary_metrics(
    y_true: Sequence[int],
    y_pred: Sequence[int],
) -> BinaryMetrics:
    """Compute confusion matrix components and derived classification rates."""
    tp = sum(1 for yt, yp in zip(y_true, y_pred, strict=True) if yt == 1 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred, strict=True) if yt == 1 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred, strict=True) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred, strict=True) if yt == 0 and yp == 0)

    # Rates with safe division
    positives = tp + fn
    negatives = fp + tn
    predicted_positives = tp + fp

    tpr = (tp / positives) if positives > 0 else 0.0
    recall = tpr
    fpr = (fp / negatives) if negatives > 0 else 0.0

    if predicted_positives > 0:
        precision = tp / predicted_positives
    else:
        # If no positive predictions and no actual positives, precision is 1.0; else 0.0
        precision = 1.0 if positives == 0 else 0.0

    if precision + recall > 0:
        f1 = 2.0 * (precision * recall) / (precision + recall)
    else:
        f1 = 0.0

    return BinaryMetrics(
        tp=tp,
        fn=fn,
        fp=fp,
        tn=tn,
        tpr=tpr,
        fpr=fpr,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def compute_roc_auc(
    y_true: Sequence[int],
    y_scores: Sequence[float],
) -> float:
    """
    Compute Area Under Receiver Operating Characteristic Curve (ROC-AUC).
    Uses Mann-Whitney U rank statistic with tie averaging for deterministic results.
    """
    arr_true = np.asarray(y_true, dtype=int)
    arr_scores = np.asarray(y_scores, dtype=float)

    pos_mask = arr_true == 1
    neg_mask = arr_true == 0
    n_pos = int(np.sum(pos_mask))
    n_neg = int(np.sum(neg_mask))

    if n_pos == 0 or n_neg == 0:
        return 0.5  # Undefined single-class default

    # Rank all scores
    order = np.argsort(arr_scores)
    ranks = np.empty_like(order, dtype=float)
    ranks[order] = np.arange(1, len(arr_scores) + 1, dtype=float)

    # Average ranks for ties
    sorted_scores = arr_scores[order]
    unique_vals, start_indices, counts = np.unique(sorted_scores, return_index=True, return_counts=True)
    for start, count in zip(start_indices, counts, strict=True):
        if count > 1:
            tie_rank = np.mean(np.arange(start + 1, start + count + 1))
            val = sorted_scores[start]
            ranks[arr_scores == val] = tie_rank

    pos_rank_sum = float(np.sum(ranks[pos_mask]))
    u_stat = pos_rank_sum - (n_pos * (n_pos + 1)) / 2.0
    return float(u_stat / (n_pos * n_neg))


def compute_pr_auc(
    y_true: Sequence[int],
    y_scores: Sequence[float],
) -> float:
    """
    Compute Area Under Precision-Recall Curve (PR-AUC) using trapezoidal rule.
    """
    arr_true = np.asarray(y_true, dtype=int)
    arr_scores = np.asarray(y_scores, dtype=float)

    order = np.argsort(-arr_scores)
    sorted_true = arr_true[order]

    tp_cumsum = np.cumsum(sorted_true == 1)
    fp_cumsum = np.cumsum(sorted_true == 0)
    total_pos = int(np.sum(sorted_true == 1))

    if total_pos == 0:
        return 0.0

    recalls = tp_cumsum / total_pos
    precisions = tp_cumsum / (tp_cumsum + fp_cumsum)

    # Add initial boundary point (recall 0, precision at first sample)
    recalls = np.concatenate(([0.0], recalls))
    precisions = np.concatenate(([precisions[0]], precisions))

    # Trapezoidal integration of PR curve
    pr_auc = float(np.trapezoid(precisions, recalls))
    return max(0.0, min(1.0, pr_auc))


def compute_false_alert_rate(
    num_false_alerts: int,
    num_devices: int,
    days_observed: float,
) -> float:
    """
    Compute False Alerts Per Device Per Day.
    Formula: Total False Alerts / (Device Count * Days Observed).
    """
    if num_devices <= 0 or days_observed <= 0:
        return 0.0
    return float(num_false_alerts / (num_devices * days_observed))


def bootstrap_ci(
    data: Sequence[float],
    num_bootstraps: int = 1000,
    ci: float = 0.95,
    seed: int = 42,
) -> BootstrapCI:
    """
    Compute non-parametric bootstrap mean and confidence interval.
    Deterministic given the random seed.
    """
    arr = np.asarray(data, dtype=float)
    if len(arr) == 0:
        return BootstrapCI(mean=0.0, ci_lower=0.0, ci_upper=0.0, ci_level=ci)

    rng = np.random.default_rng(seed)
    indices = rng.integers(0, len(arr), size=(num_bootstraps, len(arr)))
    boot_means = np.mean(arr[indices], axis=1)

    alpha = 1.0 - ci
    lower_pct = 100.0 * (alpha / 2.0)
    upper_pct = 100.0 * (1.0 - alpha / 2.0)

    ci_lower = float(np.percentile(boot_means, lower_pct))
    ci_upper = float(np.percentile(boot_means, upper_pct))
    sample_mean = float(np.mean(arr))

    return BootstrapCI(
        mean=sample_mean,
        ci_lower=ci_lower,
        ci_upper=ci_upper,
        ci_level=ci,
    )
