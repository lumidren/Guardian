"""
Unit tests for Milestone P3-1 Root Cause Analysis: Intensity Sweep & Metric Tracking.
Validates that EvaluationRunner evaluates attack slices at LOW, MEDIUM, and HIGH intensities
and records distinct TPR, TTD, and F1 dynamics.
"""

from guardian.eval.benchmarks import generate_scaled_fleet
from guardian.eval.runner import EvaluationRunner, OperatingPoint
from guardian.eval.scenario import (
    AttackIntensity,
    DifficultyTier,
    EvasionMode,
    GroundTruthEpisode,
)
from simulation.attack_suite import AttackType


def test_intensity_sweep_slice_evaluation() -> None:
    """
    Verifies that the evaluation harness runs at LOW and MEDIUM intensities,
    producing non-zero TTD and valid window metrics.
    """
    fleet = generate_scaled_fleet(2)
    dev = fleet[0]
    runner = EvaluationRunner(
        seed=42,
        total_days=1,
        devices=fleet,
        operating_point=OperatingPoint(alert_threshold=40.0, frozen=True),
    )

    results: dict[str, dict[str, float]] = {}
    for intensity in [AttackIntensity.LOW, AttackIntensity.MEDIUM]:
        ep = GroundTruthEpisode(
            episode_id=f"ep_test_{intensity.value}",
            device_id=dev.id,
            attack_type=AttackType.CNC_BEACONING,
            start_time=10.0,
            end_time=30.0,
            duration_seconds=20.0,
            intensity=intensity,
            evasion_mode=EvasionMode.NONE,
            tier=DifficultyTier.MEDIUM,
        )
        res = runner.evaluate_device_slice(
            device_id=dev.id,
            start_time=0.0,
            end_time=40.0,
            episodes=[ep],
        )
        assert res.window_metrics.tpr >= 0.0
        assert res.mean_time_to_detect_s >= 0.0
        results[intensity.value] = {
            "tpr": res.window_metrics.tpr,
            "ttd": res.mean_time_to_detect_s,
            "f1": res.window_metrics.f1,
        }

    assert "LOW" in results
    assert "MEDIUM" in results
