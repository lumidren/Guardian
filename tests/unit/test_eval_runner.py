"""
Unit tests for the EvaluationRunner and real pipeline integration.
Verifies loud failure on missing artifacts (F8 fix), pipeline execution,
and identical metrics across identical seeds (hash test).
"""

import hashlib
import json
from pathlib import Path

import pytest

from guardian.eval.runner import (
    ArtifactMissingError,
    EvaluationRunner,
)
from guardian.eval.scenario import (
    AttackIntensity,
    EvasionMode,
    GroundTruthEpisode,
)
from simulation.attack_suite import AttackType


def test_missing_model_fails_loudly(tmp_path: Path) -> None:
    """
    CRITICAL ACCEPTANCE TEST (fixes F8):
    A missing model, profile or config raises an error that stops the run.
    Never substitute zero silently.
    """
    runner = EvaluationRunner(seed=42)
    fake_path = tmp_path / "non_existent_model.json"

    with pytest.raises(ArtifactMissingError) as exc_info:
        runner.load_device_model_or_raise("dev_test_nonexistent", fake_path)

    assert "Missing required model artifact" in str(exc_info.value)
    assert "non_existent_model.json" in str(exc_info.value)


def test_pipeline_evaluates_stream_and_episode_deadline() -> None:
    runner = EvaluationRunner(seed=101, deadline_seconds=60.0)

    episode = GroundTruthEpisode(
        episode_id="ep_001",
        device_id="dev_01_temp",
        attack_type=AttackType.DDOS_FLOODING,
        start_time=8 * 86400.0 + 100.0,
        end_time=8 * 86400.0 + 160.0,
        duration_seconds=60.0,
        intensity=AttackIntensity.HIGH,
        evasion_mode=EvasionMode.NONE,
    )

    report = runner.evaluate_device_slice(
        device_id="dev_01_temp",
        start_time=8 * 86400.0 + 80.0,
        end_time=8 * 86400.0 + 200.0,
        episodes=[episode],
    )

    assert report.total_windows > 0
    assert report.total_episodes == 1
    assert report.detected_episodes in (0, 1)
    assert 0.0 <= report.roc_auc <= 1.0
    assert 0.0 <= report.pr_auc <= 1.0


def test_seed_determinism_hash_test() -> None:
    """
    CRITICAL ACCEPTANCE TEST:
    Same seed gives identical metrics (hash test).
    """
    runner1 = EvaluationRunner(seed=2026, deadline_seconds=60.0)
    rep1 = runner1.evaluate_device_slice(
        device_id="dev_01_temp",
        start_time=8 * 86400.0,
        end_time=8 * 86400.0 + 120.0,
        episodes=[],
    )

    runner2 = EvaluationRunner(seed=2026, deadline_seconds=60.0)
    rep2 = runner2.evaluate_device_slice(
        device_id="dev_01_temp",
        start_time=8 * 86400.0,
        end_time=8 * 86400.0 + 120.0,
        episodes=[],
    )

    json1 = json.dumps(rep1.to_dict(), sort_keys=True)
    json2 = json.dumps(rep2.to_dict(), sort_keys=True)

    hash1 = hashlib.sha256(json1.encode()).hexdigest()
    hash2 = hashlib.sha256(json2.encode()).hexdigest()

    assert hash1 == hash2, f"Determinism failure: hash1={hash1} != hash2={hash2}"
    assert rep1.total_windows == rep2.total_windows
    assert rep1.window_metrics.fpr == rep2.window_metrics.fpr
