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

