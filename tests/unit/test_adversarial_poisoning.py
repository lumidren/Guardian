"""
Unit tests for Adversarial Baseline Poisoning & Tampering Robustness (Milestone P3-9).
Verifies:
1. Robust statistics resistance to baseline poisoning up to 50% breakdown point.
2. Cold-start progressive protection bounding attacker rate inflation.
3. Cryptographic hash tamper detection on persisted model bundles.
"""

import numpy as np
import pytest

from guardian.eval.caching import (
    ModelCacheManager,
    TamperedBundleError,
)
from guardian.ml.threat_scorer import ThreatScorer


def test_robust_statistics_poisoning_breakdown_point() -> None:
    """Robust Median & MAD must remain stable under 20% adversarial outlier poisoning."""
    rng = np.random.RandomState(42)

    # Benign baseline: 80 clean samples drawn from N(10, 2)
    clean_samples = rng.normal(loc=10.0, scale=2.0, size=80)

    # Adversarial poisoning: 20 outlier samples with extreme values (5,000)
    poisoned_samples = np.concatenate([clean_samples, np.full(20, 5000.0)])

    # Classical statistics
    clean_mean = float(np.mean(clean_samples))
    poisoned_mean = float(np.mean(poisoned_samples))
    poisoned_std = float(np.std(poisoned_samples))

    # Robust statistics
    clean_median = float(np.median(clean_samples))
    clean_mad = float(np.median(np.abs(clean_samples - clean_median)))

    poisoned_median = float(np.median(poisoned_samples))
    poisoned_mad = float(np.median(np.abs(poisoned_samples - poisoned_median)))

    # 1. Classical statistics are ruined by 20% poisoning (>5000% inflation)
    mean_inflation_ratio = poisoned_mean / clean_mean
    assert mean_inflation_ratio > 50.0, f"Classical mean did not inflate: {mean_inflation_ratio}"
    assert poisoned_std > 500.0

    # 2. Robust statistics remain stable within tight bounds (<15% shift)
    median_shift_pct = abs(poisoned_median - clean_median) / clean_median * 100.0
    assert median_shift_pct < 15.0, f"Robust median shifted excessively: {median_shift_pct:.2f}%"

    mad_shift_pct = abs(poisoned_mad - clean_mad) / clean_mad * 100.0
    assert mad_shift_pct < 50.0, f"Robust MAD shifted excessively: {mad_shift_pct:.2f}%"


def test_cold_start_progressive_poisoning_defense() -> None:
    """During Cold-Start Stage 1, heuristic ceilings prevent attackers from poisoning baseline."""
    threat_scorer = ThreatScorer()

    # Attacker injects massive volumetric burst during cold-start with uncataloged destinations
    poison_features = {
        "byte_rate_per_sec": 150000.0,  # 150 kB/s on a 200 B/s sensor
        "pkt_rate_per_sec": 850.0,
        "n_unique_dst_ips": 50.0,
        "new_dst_ip_flag": 1.0,
        "high_risk_port_flag": 1.0,
        "dns_query_count": 0.0,
        "port_entropy": 3.8,
    }

    # Assess under cold start: heuristic priors must flag high threat
    assessment = threat_scorer.assess(
        ml_score=0.0,  # ML model not trained yet
        statistical_score=0.85,
        features=poison_features,
        is_cold_start=True,
    )

    # Must be quarantined or restricted immediately
    assert assessment.threat_score >= 60, f"Cold-start poisoning tolerated: score={assessment.threat_score}"
    assert assessment.threat_level.value in ("QUARANTINE", "BLOCK")


def test_model_cache_hash_tamper_detection(tmp_path: object) -> None:
    """Model cache manager must detect binary or metadata tampering and raise TamperedBundleError."""
    from pathlib import Path
    cache_dir = Path(str(tmp_path)) / "models"
    mgr = ModelCacheManager(cache_dir=cache_dir)

    feature_names = [f"feat_{i}" for i in range(60)]
    training_samples = np.zeros((10, 60)).tolist()
    bundle = mgr.get_or_train_model(
        device_id="dev_test",
        seed=42,
        training_samples=training_samples,
        feature_names=feature_names,
        config_state={"n_estimators": 10},
    )

    # 1. Clean load succeeds
    loaded = mgr.load_verified_bundle(bundle.model_path, bundle.sidecar_path)
    assert loaded.device_id == "dev_test"

    # 2. Tampering sidecar payload on disk
    sidecar_text = bundle.sidecar_path.read_text(encoding="utf-8")
    tampered_sidecar = sidecar_text.replace('"sample_count": 10', '"sample_count": 9999')
    bundle.sidecar_path.write_text(tampered_sidecar, encoding="utf-8")

    # 3. Load must fail with TamperedBundleError
    with pytest.raises(TamperedBundleError) as exc_info:
        mgr.load_verified_bundle(bundle.model_path, bundle.sidecar_path)
    assert "Sidecar signature mismatch" in str(exc_info.value)
