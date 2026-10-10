"""
Unit tests for Real Baselines (Milestone P2-4).
Tests StaticThresholdBaseline, PooledIsolationForestBaseline, and RobustZScoreOnlyBaseline.
Verifies honest empirical baselines replacing unmeasured literature numbers (fixing F1).
"""

import numpy as np

from guardian.capture.flow_tracker import FlowSummary
from guardian.capture.packet_parser import ParsedPacket
from guardian.eval.baselines import (
    PooledIsolationForestBaseline,
    RobustZScoreOnlyBaseline,
    StaticThresholdBaseline,
)
from guardian.ml.statistical_baseline import StatisticalBaseline
from simulation.fleet_emulator import DEFAULT_FLEET_SPECS


def _make_dummy_summary(
    device_ip: str,
    dst_ip: str,
    dst_port: int,
    packet_count: int = 10,
    duration: float = 10.0,
) -> FlowSummary:
    pkts = []
    base_t = 1000.0
    interval = duration / max(1, packet_count)
    for i in range(packet_count):
        pkts.append(
            ParsedPacket(
                timestamp=base_t + i * interval,
                src_ip=device_ip,
                dst_ip=dst_ip,
                src_port=50000 + i,
                dst_port=dst_port,
                protocol="TCP",
                length=100,
            )
        )
    return FlowSummary(
        device_id=device_ip,
        window_start=base_t,
        window_end=base_t + duration,
        duration=duration,
        packets=pkts,
        known_destinations={dst_ip},
        is_new_destination_seen=False,
    )


def test_static_threshold_baseline_normal_passes() -> None:
    temp_spec = DEFAULT_FLEET_SPECS[0]  # Temp sensor (MQTT)
    baseline = StaticThresholdBaseline.from_device_spec(temp_spec)

    # Normal traffic to sensor's known destination and MQTT port (1883)
    normal_dst = temp_spec.normal_destinations[0]
    normal_port = 1883
    summary = _make_dummy_summary(
        device_ip=temp_spec.ip_address,
        dst_ip=normal_dst,
        dst_port=normal_port,
        packet_count=5,
        duration=10.0,
    )

    score, violations = baseline.score_summary(summary)
    assert score < 30.0
    assert len(violations) == 0


def test_static_threshold_baseline_flags_violations() -> None:
    temp_spec = DEFAULT_FLEET_SPECS[0]
    baseline = StaticThresholdBaseline.from_device_spec(temp_spec)

    # 1. Unknown external destination violation
    bad_dst_summary = _make_dummy_summary(
        device_ip=temp_spec.ip_address,
        dst_ip="198.51.100.99",
        dst_port=1883,
        packet_count=5,
        duration=10.0,
    )
    score, violations = baseline.score_summary(bad_dst_summary)
    assert score >= 40.0
    assert any("destination" in v.lower() for v in violations)

    # 2. High-risk unauthorized port violation
    bad_port_summary = _make_dummy_summary(
        device_ip=temp_spec.ip_address,
        dst_ip=temp_spec.normal_destinations[0],
        dst_port=4444,  # Metasploit / C2 port
        packet_count=5,
        duration=10.0,
    )
    score_port, violations_port = baseline.score_summary(bad_port_summary)
    assert score_port >= 50.0
    assert any("port" in v.lower() for v in violations_port)

    # 3. Severe volumetric rate violation
    burst_summary = _make_dummy_summary(
        device_ip=temp_spec.ip_address,
        dst_ip=temp_spec.normal_destinations[0],
        dst_port=1883,
        packet_count=500,  # 50 pkts/s vs normal < 5 pkts/s
        duration=10.0,
    )
    score_rate, violations_rate = baseline.score_summary(burst_summary)
    assert score_rate >= 50.0
    assert any("rate" in v.lower() for v in violations_rate)


def test_pooled_isolation_forest_baseline() -> None:
    # Pool normal data from camera and plug
    cam_samples = [[1.0, 10.0], [1.1, 10.2], [0.9, 9.8]]
    plug_samples = [[5.0, 50.0], [5.2, 51.0], [4.8, 49.0]]
    pooled_data = cam_samples + plug_samples

    pooled_if = PooledIsolationForestBaseline(n_estimators=30, seed=42)
    pooled_if.fit(pooled_data)
    assert pooled_if.is_trained is True

    # In-distribution sample
    score_in, _ = pooled_if.score_sample(np.array([1.05, 10.1]))
    # Extreme anomaly sample
    score_out, _ = pooled_if.score_sample(np.array([50.0, 500.0]))

    assert score_out > score_in
    assert score_out >= 0.60


def test_robust_zscore_only_baseline() -> None:
    baseline_profile = StatisticalBaseline()
    baseline_profile.means = {"pkt_rate_per_sec": 2.0, "byte_rate_per_sec": 200.0}
    baseline_profile.stds = {"pkt_rate_per_sec": 0.5, "byte_rate_per_sec": 50.0}
    baseline_profile.is_ready = True

    evaluator = RobustZScoreOnlyBaseline(baseline_profile=baseline_profile)

    # Normal features
    normal_score = evaluator.score_features({"pkt_rate_per_sec": 2.1, "byte_rate_per_sec": 210.0})
    assert normal_score < 30.0

    # Highly anomalous features (> 6 sigma)
    anom_score = evaluator.score_features({"pkt_rate_per_sec": 15.0, "byte_rate_per_sec": 2000.0})
    assert anom_score >= 70.0


def test_destination_allowlist_only_baseline() -> None:
    from guardian.eval.baselines import DestinationAllowlistOnlyBaseline

    temp_spec = DEFAULT_FLEET_SPECS[0]
    allowlist_base = DestinationAllowlistOnlyBaseline.from_device_spec(temp_spec)

    # Approved destination
    clean_summary = _make_dummy_summary(
        device_ip=temp_spec.ip_address,
        dst_ip=temp_spec.normal_destinations[0],
        dst_port=1883,
        packet_count=5,
    )
    score_clean, viol_clean = allowlist_base.score_summary(clean_summary)
    assert score_clean == 0.0
    assert len(viol_clean) == 0

    # Unauthorized destination
    dirty_summary = _make_dummy_summary(
        device_ip=temp_spec.ip_address,
        dst_ip="203.0.113.88",
        dst_port=1883,
        packet_count=5,
    )
    score_dirty, viol_dirty = allowlist_base.score_summary(dirty_summary)
    assert score_dirty == 100.0
    assert len(viol_dirty) > 0


def test_local_outlier_factor_baseline() -> None:
    from guardian.eval.baselines import LocalOutlierFactorBaseline

    # Generate 50 points clustered around (10.0, 10.0)
    rng = np.random.default_rng(42)
    normal_data = rng.normal(loc=10.0, scale=1.0, size=(50, 4))

    lof = LocalOutlierFactorBaseline(k_neighbors=5)
    lof.fit(normal_data)
    assert lof.is_fitted is True

    # In-distribution point
    normal_pt = np.array([10.1, 9.9, 10.0, 10.2])
    score_in = lof.score_sample(normal_pt)

    # Distant outlier point
    outlier_pt = np.array([50.0, 50.0, 50.0, 50.0])
    score_out = lof.score_sample(outlier_pt)

    assert score_out > score_in
    assert score_out >= 60.0


def test_tpr_positive_and_fpr_zero_implies_f1_positive() -> None:
    """
    Verify that:
    1) Any confusion matrix with TPR > 0 and FPR == 0 strictly produces F1 > 0.
    2) In the real evaluation schedule, Pooled Isolation Forest produces TPR > 0,
       and every baseline with TPR > 0 (including Static Threshold Rules with FPR == 0)
       has F1 > 0 computed from the same confusion counts.
    """
    from guardian.eval.metrics import compute_binary_metrics
    from guardian.eval.runner import EvaluationRunner
    from guardian.eval.scenario import DifficultyTier

    # Direct mathematical check: TPR > 0 and FPR == 0 => F1 > 0
    y_true = [0, 0, 0, 0, 1, 1, 1, 1]
    y_pred = [0, 0, 0, 0, 1, 0, 0, 0]  # TP=1, FP=0, TN=4, FN=3 -> TPR=0.25 > 0, FPR=0.0
    m = compute_binary_metrics(y_true, y_pred)
    assert m.tpr > 0.0
    assert m.fpr == 0.0
    assert m.f1 > 0.0

    # Schedule-level baseline confusion check
    runner = EvaluationRunner(seed=42, total_days=14, devices=DEFAULT_FLEET_SPECS[:2])
    runner.calibrate_operating_point(target_fpr=0.05, duration_per_device_s=20.0)
    episodes = runner.scenario_builder.generate_ground_truth_schedule(
        tiers=[DifficultyTier.EASY],
        episodes_per_tier=1,
    )
    res = runner.evaluate_ground_truth_schedule(episodes[:2], pre_buffer_s=10.0, post_buffer_s=5.0)
    summary = res["detector_confusion_summary"]

    assert summary["pooled"]["episode_tpr"] > 0.0 or summary["pooled"]["window_tpr"] > 0.0
    for det_name, stats in summary.items():
        if stats["episode_tpr"] > 0.0 or stats["window_tpr"] > 0.0:
            assert stats["f1"] > 0.0, f"Baseline {det_name} has TPR > 0 but F1 == 0.0: {stats}"
        if stats["window_tpr"] > 0.0 and stats["fpr"] == 0.0:
            assert stats["f1"] > 0.0, f"Baseline {det_name} has TPR > 0 and FPR == 0 but F1 == 0.0"


def test_repro_pooled_if_zero_tpr_bug_and_resolution() -> None:
    """
    Task 1: Reproduces the historical Pooled IF 0% TPR bug and verifies its fix:
    1) Untrained PooledIsolationForestBaseline returns 0.0 on all samples (0% TPR).
    2) Raw score_sample() returns s in [0.0, 1.0]; comparing unscaled raw score against
       a [0, 100] threshold (52.0) caused 0% TPR across all attacks.
    3) Multimodal fleet training without clearing single-cluster baseline_mean/std
       clips >5% of normal windows at 1.0 (100.0), saturating Day 8 calibration at 100.0.
    4) With fleet training, * 100.0 scaling, and pure path-length scoring, Pooled IF
       produces continuous scores in (0.0, 100.0) and detects attacks above threshold.
    """
    untrained = PooledIsolationForestBaseline(n_estimators=25, seed=42)
    raw_untrained, _ = untrained.score_sample(np.ones(60, dtype=float) * 500.0)
    assert raw_untrained == 0.0

    # Multimodal fleet training across two distinct device clusters
    rng = np.random.default_rng(42)
    cluster_a = rng.normal(loc=2.0, scale=0.2, size=(40, 60)).tolist()
    cluster_b = rng.normal(loc=80.0, scale=5.0, size=(40, 60)).tolist()
    trained = PooledIsolationForestBaseline(n_estimators=50, seed=42)
    trained.fit(cluster_a + cluster_b)

    assert trained.is_trained is True
    assert trained.model.baseline_mean is None
    assert trained.model.baseline_std is None

    normal_raw, _ = trained.score_sample(np.full(60, 2.05, dtype=float))
    attack_raw, _ = trained.score_sample(np.full(60, 5000.0, dtype=float))

    # Historical bug: unscaled raw score in [0, 1] is always < 52.0
    assert attack_raw <= 1.0
    assert not (attack_raw >= 52.0)

    # Fixed [0, 100] scaled score: normal < threshold < attack < 100.0
    normal_scaled = normal_raw * 100.0
    attack_scaled = attack_raw * 100.0
    assert 0.0 < normal_scaled < 75.0
    assert attack_scaled > normal_scaled
    assert attack_scaled >= 52.0


