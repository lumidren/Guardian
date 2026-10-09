"""
Unit tests for Model Training and Content-Hash Bundle Caching (Milestone P2-3).
Verifies that identical seeds avoid retraining (cache hits), tampered bundles are rejected,
and model sidecars record training sample counts, ranges, and held-out score percentiles.
"""

import json
from pathlib import Path

import pytest

from guardian.eval.caching import (
    ModelCacheManager,
    ModelSidecarData,
    TamperedBundleError,
)


def test_bundle_hash_determinism_and_cache_hit(tmp_path: Path) -> None:
    cache_mgr = ModelCacheManager(cache_dir=tmp_path)
    training_data = [[1.0, 2.0, 3.0], [1.1, 2.1, 3.1], [0.9, 1.9, 2.9]]
    features = ["f1", "f2", "f3"]
    config_state = {"n_estimators": 50, "max_depth": 5}

    h1 = cache_mgr.compute_bundle_hash(training_data, config_state, features)
    h2 = cache_mgr.compute_bundle_hash(training_data, config_state, features)
    assert h1 == h2

    # First run: trains and writes bundle
    bundle1 = cache_mgr.get_or_train_model(
        device_id="dev_test_01",
        seed=42,
        training_samples=training_data,
        feature_names=features,
        config_state=config_state,
    )
    assert bundle1.was_cached is False
    assert bundle1.model_path.exists()
    assert bundle1.sidecar_path.exists()

    # Second run with same seed and hash: MUST avoid retraining (cache hit)
    bundle2 = cache_mgr.get_or_train_model(
        device_id="dev_test_01",
        seed=42,
        training_samples=training_data,
        feature_names=features,
        config_state=config_state,
    )
    assert bundle2.was_cached is True
    assert bundle2.content_hash == bundle1.content_hash


def test_tampered_bundle_is_rejected(tmp_path: Path) -> None:
    cache_mgr = ModelCacheManager(cache_dir=tmp_path)
    training_data = [[1.0, 2.0, 3.0], [1.2, 2.2, 3.2]]
    features = ["f1", "f2", "f3"]
    config_state = {"n_estimators": 20}

    bundle = cache_mgr.get_or_train_model(
        device_id="dev_tamper",
        seed=99,
        training_samples=training_data,
        feature_names=features,
        config_state=config_state,
    )
    assert bundle.model_path.exists()

    # Tamper with sidecar JSON
    with open(bundle.sidecar_path, "r+", encoding="utf-8") as f:
        data = json.load(f)
        data["sample_count"] = 999999  # Tamper
        f.seek(0)
        json.dump(data, f)
        f.truncate()

    # Loading tampered bundle must raise TamperedBundleError
    with pytest.raises(TamperedBundleError):
        cache_mgr.load_verified_bundle(bundle.model_path, bundle.sidecar_path)


def test_sidecar_contains_quality_metrics(tmp_path: Path) -> None:
    cache_mgr = ModelCacheManager(cache_dir=tmp_path)
    training_data = [
        [1.0, 10.0],
        [2.0, 20.0],
        [3.0, 30.0],
        [4.0, 40.0],
        [5.0, 50.0],
    ]
    features = ["feat_a", "feat_b"]
    config_state = {"n_estimators": 30}

    bundle = cache_mgr.get_or_train_model(
        device_id="dev_sidecar",
        seed=7,
        training_samples=training_data,
        feature_names=features,
        config_state=config_state,
    )

    with open(bundle.sidecar_path, encoding="utf-8") as f:
        sidecar_dict = json.load(f)

    sidecar = ModelSidecarData.from_dict(sidecar_dict)
    assert sidecar.sample_count == 5
    assert sidecar.feature_names == features
    assert sidecar.training_range["feat_a"] == [1.0, 5.0]
    assert sidecar.training_range["feat_b"] == [10.0, 50.0]
    assert "p50" in sidecar.held_out_score_percentiles
    assert "p95" in sidecar.held_out_score_percentiles
