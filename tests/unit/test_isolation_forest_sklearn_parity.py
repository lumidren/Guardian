"""
Parity tests for GUARDIAN's pure-NumPy IsolationForestDetector against
canonical Liu et al. (2008) formulation and scikit-learn IsolationForest (dev dependency).
Verifies Spearman rank correlation >= 0.95 and similar ROC AUC on identical synthetic data.
"""

import numpy as np
import pytest

from guardian.eval.metrics import compute_roc_auc
from guardian.ml.isolation_forest import IsolationForestDetector, IsolationTreeNode, c_factor


def _spearman_rank_correlation(x: np.ndarray, y: np.ndarray) -> float:
    """Compute Spearman rank correlation coefficient between two 1D arrays."""
    rank_x = np.argsort(np.argsort(x)).astype(np.float64)
    rank_y = np.argsort(np.argsort(y)).astype(np.float64)
    return float(np.corrcoef(rank_x, rank_y)[0, 1])


def _canonical_liu_path_length(x: np.ndarray, node: IsolationTreeNode, depth: int = 0) -> float:
    """Standard unamplified Liu et al. (2008) path length traversal."""
    if node.is_leaf or node.feature_idx == -1:
        return depth + c_factor(node.size)
    if x[node.feature_idx] < node.split_val:
        return (
            _canonical_liu_path_length(x, node.left, depth + 1)
            if node.left
            else depth + 1.0
        )
    return (
        _canonical_liu_path_length(x, node.right, depth + 1)
        if node.right
        else depth + 1.0
    )


def _generate_synthetic_benchmark_data(
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray, list[int]]:
    """Generate identical synthetic training and graded evaluation dataset."""
    rng = np.random.default_rng(seed)
    x_train = rng.normal(0.0, 1.0, size=(300, 10))
    x_inliers = rng.normal(0.0, 1.0, size=(100, 10))
    scales = np.linspace(1.5, 12.0, 100).reshape(-1, 1)
    x_outliers = rng.normal(0.0, 1.0, size=(100, 10)) + scales
    x_test = np.vstack([x_inliers, x_outliers])
    y_true = [0] * 100 + [1] * 100
    return x_train, x_test, y_true


def test_isolation_forest_canonical_liu_et_al_parity() -> None:
    """
    Verify GUARDIAN's pure-NumPy IsolationForestDetector against the canonical
    Liu et al. (2008) path-length formulation on identical synthetic data:
    - Spearman rank correlation >= 0.95
    - Similar ROC AUC (within 0.03)
    """
    x_train, x_test, y_true = _generate_synthetic_benchmark_data(seed=42)

    detector = IsolationForestDetector(
        n_estimators=100,
        subsample_size=256,
        random_seed=42,
    )
    detector.fit(x_train)

    guardian_scores = np.array([detector.score_sample(x)[0] for x in x_test])

    canonical_scores_list: list[float] = []
    for x in x_test:
        avg_h = float(
            np.mean([_canonical_liu_path_length(x, t.root) for t in detector.trees if t.root])
        )
        canonical_scores_list.append(float(2.0 ** (-avg_h / detector.c_val)))
    canonical_scores = np.array(canonical_scores_list)

    rank_corr = _spearman_rank_correlation(guardian_scores, canonical_scores)
    auc_guardian = compute_roc_auc(y_true, guardian_scores.tolist())
    auc_canonical = compute_roc_auc(y_true, canonical_scores.tolist())

    assert rank_corr >= 0.95, f"Expected rank correlation >= 0.95, got {rank_corr:.4f}"
    assert auc_guardian >= 0.95
    assert abs(auc_guardian - auc_canonical) <= 0.03


def test_isolation_forest_sklearn_parity() -> None:
    """
    Compare GUARDIAN's pure-NumPy IsolationForestDetector directly against
    scikit-learn's IsolationForest (dev dependency only) on identical synthetic data:
    - Spearman score rank correlation >= 0.95
    - Similar ROC AUC (within 0.03)
    """
    sklearn_ensemble = pytest.importorskip("sklearn.ensemble")
    sklearn_iforest_cls = sklearn_ensemble.IsolationForest

    x_train, x_test, y_true = _generate_synthetic_benchmark_data(seed=42)

    detector = IsolationForestDetector(
        n_estimators=100,
        subsample_size=256,
        random_seed=42,
    )
    detector.fit(x_train)
    guardian_scores = np.array([detector.score_sample(x)[0] for x in x_test])

    sk_model = sklearn_iforest_cls(
        n_estimators=100,
        max_samples=256,
        random_state=42,
    )
    sk_model.fit(x_train)
    # sklearn score_samples returns negative anomaly scores (lower = more anomalous)
    sklearn_scores = -sk_model.score_samples(x_test)

    rank_corr = _spearman_rank_correlation(guardian_scores, sklearn_scores)
    auc_guardian = compute_roc_auc(y_true, guardian_scores.tolist())
    auc_sklearn = compute_roc_auc(y_true, sklearn_scores.tolist())

    assert rank_corr >= 0.95, f"Expected rank correlation >= 0.95 vs sklearn, got {rank_corr:.4f}"
    assert auc_guardian >= 0.95
    assert auc_sklearn >= 0.95
    assert abs(auc_guardian - auc_sklearn) <= 0.03
