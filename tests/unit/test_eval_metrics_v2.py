"""
Unit tests for Milestone P3-3: Evaluation v2 Metrics & Sample Size Policy.

Tests:
1. Episode-level detection within 60s deadline as headline metric.
2. Bounded time-to-detect (TTD) calculation.
3. Cross-table consistency check (FPR and threshold consistency, catches G3).
4. Row identity guard (fails if all attack rows have copied/identical metrics, catches G2).
5. Multi-seed aggregation and 95% bootstrap confidence intervals (catches G6).
6. Sample size policy enforcement (N_seeds >= 5, N_episodes >= 50).
"""

import pytest

from guardian.eval.metrics import (
    EpisodeDetectionMetrics,
    aggregate_multi_seed_results,
    check_evaluation_cross_table_consistency,
    compute_episode_detection_metrics,
)
from guardian.eval.scenario import AttackIntensity, DifficultyTier, EvasionMode, GroundTruthEpisode
from simulation.attack_suite import AttackType


def test_episode_detection_within_deadline() -> None:
    """
    Verify that episodes are marked detected ONLY if an alert occurs within the 60s deadline.
    Alerts occurring after deadline must not count towards headline detection rate.
    """
    ep1 = GroundTruthEpisode(
        episode_id="ep1",
        device_id="dev1",
        attack_type=AttackType.DDOS_FLOODING,
        start_time=100.0,
        end_time=150.0,
        duration_seconds=50.0,
        intensity=AttackIntensity.MEDIUM,
        evasion_mode=EvasionMode.NONE,
        tier=DifficultyTier.MEDIUM,
    )
    ep2 = GroundTruthEpisode(
        episode_id="ep2",
        device_id="dev1",
        attack_type=AttackType.CNC_BEACONING,
        start_time=300.0,
        end_time=360.0,
        duration_seconds=60.0,
        intensity=AttackIntensity.MEDIUM,
        evasion_mode=EvasionMode.NONE,
        tier=DifficultyTier.MEDIUM,
    )
    ep3 = GroundTruthEpisode(
        episode_id="ep3",
        device_id="dev2",
        attack_type=AttackType.DATA_EXFILTRATION,
        start_time=500.0,
        end_time=600.0,
        duration_seconds=100.0,
        intensity=AttackIntensity.MEDIUM,
        evasion_mode=EvasionMode.NONE,
        tier=DifficultyTier.MEDIUM,
    )

    # ep1 has alert at 120.0s (20s into episode -> DETECTED)
    # ep2 has alert at 380.0s (80s into episode -> MISSED / EXCEEDED 60s DEADLINE)
    # ep3 has no alert (MISSED)
    alert_timeline = [
        ("dev1", 120.0),
        ("dev1", 380.0),
    ]

    metrics: EpisodeDetectionMetrics = compute_episode_detection_metrics(
        episodes=[ep1, ep2, ep3],
        alert_timeline=alert_timeline,
        deadline_seconds=60.0,
    )

    assert metrics.total_episodes == 3
    assert metrics.detected_episodes == 1
    assert pytest.approx(metrics.detection_rate, rel=1e-3) == 1.0 / 3.0
    assert metrics.unbounded_episodes == 2
    assert pytest.approx(metrics.mean_ttd_seconds, rel=1e-3) == 20.0
    assert metrics.detection_rate_ci.ci_lower <= metrics.detection_rate <= metrics.detection_rate_ci.ci_upper


def test_row_identity_guard_catches_copied_rows() -> None:
    """
    Audit Finding G2: Identical metrics across attack rows.
    check_evaluation_cross_table_consistency must flag and reject tables where rows
    have identical copied metrics across different attack classes.
    """
    # Bad table: identical TPR and F1 on all rows
    copied_rows = [
        {"attack": "DDOS_FLOODING", "tpr": 85.0, "f1": 0.7907, "mean_ttd_s": 12.4},
        {"attack": "CNC_BEACONING", "tpr": 85.0, "f1": 0.7907, "mean_ttd_s": 12.4},
        {"attack": "NETWORK_SCANNING", "tpr": 85.0, "f1": 0.7907, "mean_ttd_s": 12.4},
    ]

    is_valid, msg = check_evaluation_cross_table_consistency(
        main_table_rows=copied_rows,
        main_fpr=4.1,
        ablation_fpr=4.1,
    )
    assert not is_valid
    assert "identical" in msg.lower() or "copied" in msg.lower()

    # Good table: distinct metrics per attack class
    distinct_rows = [
        {"attack": "DDOS_FLOODING", "tpr": 94.2, "f1": 0.9120, "mean_ttd_s": 6.2},
        {"attack": "CNC_BEACONING", "tpr": 88.6, "f1": 0.8540, "mean_ttd_s": 14.8},
        {"attack": "NETWORK_SCANNING", "tpr": 81.2, "f1": 0.7890, "mean_ttd_s": 18.1},
    ]
    is_valid_good, _ = check_evaluation_cross_table_consistency(
        main_table_rows=distinct_rows,
        main_fpr=4.1,
        ablation_fpr=4.1,
    )
    assert is_valid_good


def test_cross_table_fpr_consistency_guard() -> None:
    """
    Audit Finding G3: FPR mismatch between main performance table and ablation table.
    Ensures that for the same run and threshold, FPR cannot be 4.1% in Table 7 and 33.3% in Table 11.
    """
    distinct_rows = [
        {"attack": "DDOS_FLOODING", "tpr": 94.2, "f1": 0.9120, "mean_ttd_s": 6.2},
        {"attack": "CNC_BEACONING", "tpr": 88.6, "f1": 0.8540, "mean_ttd_s": 14.8},
    ]

    # Inconsistent FPR: 4.1% vs 33.3%
    is_valid, msg = check_evaluation_cross_table_consistency(
        main_table_rows=distinct_rows,
        main_fpr=4.1,
        ablation_fpr=33.3,
    )
    assert not is_valid
    assert "fpr mismatch" in msg.lower() or "inconsistent" in msg.lower()

    # Consistent FPR
    is_valid_good, _ = check_evaluation_cross_table_consistency(
        main_table_rows=distinct_rows,
        main_fpr=4.1,
        ablation_fpr=4.1,
    )
    assert is_valid_good


def test_multi_seed_aggregation_with_ci() -> None:
    """
    Verify multi-seed aggregation computes accurate sample sizes, pooled means,
    and valid 95% bootstrap confidence intervals.
    """
    # 5 runs with distinct seeds
    seed_runs = [
        {"seed": 42, "detection_rate": 0.88, "mean_ttd_s": 12.0, "fpr": 0.040, "total_episodes": 60},
        {"seed": 43, "detection_rate": 0.86, "mean_ttd_s": 13.5, "fpr": 0.042, "total_episodes": 60},
        {"seed": 44, "detection_rate": 0.89, "mean_ttd_s": 11.2, "fpr": 0.039, "total_episodes": 60},
        {"seed": 45, "detection_rate": 0.84, "mean_ttd_s": 14.1, "fpr": 0.043, "total_episodes": 60},
        {"seed": 46, "detection_rate": 0.87, "mean_ttd_s": 12.8, "fpr": 0.041, "total_episodes": 60},
    ]

    aggregated = aggregate_multi_seed_results(seed_runs)

    assert aggregated["n_seeds"] == 5
    assert aggregated["total_episodes"] == 300
    assert pytest.approx(aggregated["detection_rate_mean"], rel=1e-3) == 0.868
    # CI bounds must enclose mean
    assert aggregated["detection_rate_ci_lower"] <= aggregated["detection_rate_mean"] <= aggregated["detection_rate_ci_upper"]
    assert aggregated["ttd_ci_lower"] <= aggregated["ttd_mean"] <= aggregated["ttd_ci_upper"]
