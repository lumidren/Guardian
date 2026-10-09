"""
Unit tests for GUARDIAN Isolation Forest anomaly detector.
"""

import tempfile
from pathlib import Path
import numpy as np
import pytest
from guardian.ml.isolation_forest import IsolationForestDetector


def test_isolation_forest_train_and_inference():
    np.random.seed(42)
    # 100 normal training samples in 60-dimensional space
    X_normal = np.random.normal(loc=10.0, scale=1.0, size=(100, 60))

    detector = IsolationForestDetector(n_estimators=50, subsample_size=64)
    detector.fit(X_normal, device_id="test_sensor")

    assert detector.is_trained
    assert len(detector.trees) == 50

    # Normal sample should have low/moderate anomaly score
    x_test_normal = np.random.normal(loc=10.0, scale=1.0, size=60)
    score_norm, attr_norm = detector.score_sample(x_test_normal)
    assert 0.0 <= score_norm <= 1.0
    assert score_norm < 0.65

    # Outlier sample with massive deviation on feature 0 & 1
    x_test_anom = np.copy(x_test_normal)
    x_test_anom[0] = 500.0  # huge spike
    x_test_anom[1] = 800.0

    score_anom, attr_anom = detector.score_sample(x_test_anom)
    assert score_anom > score_norm
    assert score_anom > 0.60
    assert len(attr_anom) > 0


def test_isolation_forest_save_and_load():
    X = np.random.normal(size=(50, 60))
    detector = IsolationForestDetector(n_estimators=20)
    detector.fit(X, device_id="persisted_device")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        detector.save(tmp_path)
        assert tmp_path.exists()

        loaded = IsolationForestDetector.load(tmp_path)
        assert loaded.is_trained
        assert loaded.device_id == "persisted_device"
        assert len(loaded.trees) == 20

        sample = np.random.normal(size=60)
        s1, _ = detector.score_sample(sample)
        s2, _ = loaded.score_sample(sample)
        assert abs(s1 - s2) < 1e-4
    finally:
        if tmp_path.exists():
            tmp_path.unlink()
