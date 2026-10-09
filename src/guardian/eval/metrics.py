"""
Evaluation metrics calculation module for GUARDIAN.

Provides deterministic calculations for confusion matrix rates, ROC-AUC, PR-AUC,
false alerts per device per day, and bootstrap confidence intervals.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

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


@dataclass(frozen=True)
class EpisodeDetectionMetrics:
    total_episodes: int
    detected_episodes: int
    detection_rate: float
    detection_rate_ci: BootstrapCI
    mean_ttd_seconds: float
    median_ttd_seconds: float
    ttd_ci: BootstrapCI
    unbounded_episodes: int


def compute_episode_detection_metrics(
    episodes: Sequence[Any],
    alert_timeline: Sequence[tuple[str, float]],
    deadline_seconds: float = 60.0,
    seed: int = 42,
) -> EpisodeDetectionMetrics:
    """
    Compute headline episode-level detection rate and bounded time-to-detect.
    An episode is detected if and only if an alert for that device is raised within
    [ep.start_time, ep.start_time + deadline_seconds].
    """
    total = len(episodes)
    if total == 0:
        empty_ci = BootstrapCI(mean=0.0, ci_lower=0.0, ci_upper=0.0, ci_level=0.95)
        return EpisodeDetectionMetrics(
            total_episodes=0,
            detected_episodes=0,
            detection_rate=0.0,
            detection_rate_ci=empty_ci,
            mean_ttd_seconds=0.0,
            median_ttd_seconds=0.0,
            ttd_ci=empty_ci,
            unbounded_episodes=0,
        )

    alerts_by_device: dict[str, list[float]] = {}
    for dev_id, ts in alert_timeline:
        alerts_by_device.setdefault(dev_id, []).append(ts)

    detected_flags: list[float] = []
    ttd_values: list[float] = []
    unbounded = 0

    for ep in episodes:
        dev_id = ep.device_id
        start_t = ep.start_time
        deadline_t = start_t + deadline_seconds

        dev_alerts = alerts_by_device.get(dev_id, [])
        valid_alerts = [t for t in dev_alerts if start_t <= t <= deadline_t]
        if valid_alerts:
            first_alert = min(valid_alerts)
            detected_flags.append(1.0)
            ttd = max(0.0, first_alert - start_t)
            ttd_values.append(ttd)
        else:
            detected_flags.append(0.0)
            unbounded += 1

    detected_count = sum(1 for f in detected_flags if f == 1.0)
    det_rate = detected_count / total
    det_ci = bootstrap_ci(detected_flags, num_bootstraps=1000, ci=0.95, seed=seed)

    if ttd_values:
        mean_ttd = float(np.mean(ttd_values))
        median_ttd = float(np.median(ttd_values))
        ttd_ci = bootstrap_ci(ttd_values, num_bootstraps=1000, ci=0.95, seed=seed)
    else:
        mean_ttd = 0.0
        median_ttd = 0.0
        ttd_ci = BootstrapCI(mean=0.0, ci_lower=0.0, ci_upper=0.0, ci_level=0.95)

    return EpisodeDetectionMetrics(
        total_episodes=total,
        detected_episodes=detected_count,
        detection_rate=det_rate,
        detection_rate_ci=det_ci,
        mean_ttd_seconds=mean_ttd,
        median_ttd_seconds=median_ttd,
        ttd_ci=ttd_ci,
        unbounded_episodes=unbounded,
    )


def check_evaluation_cross_table_consistency(
    main_table_rows: Sequence[dict[str, Any]],
    main_fpr: float,
    ablation_fpr: float,
    tolerance: float = 0.1,
) -> tuple[bool, str]:
    """
    Enforce evaluation consistency across tables and prevent copied rows.
    - Rejects tables where all attack rows have identical TPR and F1 (catches G2).
    - Rejects tables where main FPR and ablation FPR disagree beyond tolerance (catches G3).
    """
    # 1. Check FPR consistency across tables
    if abs(main_fpr - ablation_fpr) > tolerance:
        return (
            False,
            f"FPR mismatch across tables: main FPR is {main_fpr}%, but ablation FPR is {ablation_fpr}% (tolerance {tolerance}%)",
        )

    # 2. Check for copied / identical rows in main table
    if len(main_table_rows) >= 2:
        first = main_table_rows[0]
        all_identical = True
        for row in main_table_rows[1:]:
            tpr_match = abs(row.get("tpr", 0.0) - first.get("tpr", 0.0)) < 1e-4
            f1_match = abs(row.get("f1", 0.0) - first.get("f1", 0.0)) < 1e-4
            ttd_match = abs(row.get("mean_ttd_s", 0.0) - first.get("mean_ttd_s", 0.0)) < 1e-4
            if not (tpr_match and f1_match and ttd_match):
                all_identical = False
                break
        if all_identical:
            return (
                False,
                "Identical copied rows detected across different attack classes in evaluation table.",
            )

    return True, "Evaluation tables consistent and non-identical."


def aggregate_multi_seed_results(
    seed_runs: Sequence[dict[str, Any]],
    ci_level: float = 0.95,
) -> dict[str, Any]:
    """
    Aggregate evaluation results across multiple random seeds with 95% bootstrap CIs.
    """
    n_seeds = len(seed_runs)
    if n_seeds == 0:
        return {"n_seeds": 0}

    total_episodes = sum(int(r.get("total_episodes", 0)) for r in seed_runs)
    det_rates = [float(r.get("detection_rate", 0.0)) for r in seed_runs]
    ttds = [float(r.get("mean_ttd_s", 0.0)) for r in seed_runs]
    fprs = [float(r.get("fpr", 0.0)) for r in seed_runs]

    det_ci = bootstrap_ci(det_rates, num_bootstraps=1000, ci=ci_level, seed=42)
    ttd_ci = bootstrap_ci(ttds, num_bootstraps=1000, ci=ci_level, seed=42)
    fpr_ci = bootstrap_ci(fprs, num_bootstraps=1000, ci=ci_level, seed=42)

    return {
        "n_seeds": n_seeds,
        "total_episodes": total_episodes,
        "detection_rate_mean": det_ci.mean,
        "detection_rate_ci_lower": det_ci.ci_lower,
        "detection_rate_ci_upper": det_ci.ci_upper,
        "ttd_mean": ttd_ci.mean,
        "ttd_ci_lower": ttd_ci.ci_lower,
        "ttd_ci_upper": ttd_ci.ci_upper,
        "fpr_mean": fpr_ci.mean,
        "fpr_ci_lower": fpr_ci.ci_lower,
        "fpr_ci_upper": fpr_ci.ci_upper,
    }

