"""Unit tests for src/guardian/ml module."""

import numpy as np

from guardian.config import FEATURE_NAMES, ThreatLevel
from guardian.ml.concept_drift import ConceptDriftDetector, DriftAction
from guardian.ml.isolation_forest import IsolationForestDetector
from guardian.ml.statistical_baseline import StatisticalBaseline
from guardian.ml.threat_scorer import ThreatScorer


def test_isolation_forest_detector_fit_and_score() -> None:
    rng = np.random.RandomState(42)
    # 50 nominal samples
    X_normal = rng.normal(loc=10.0, scale=1.0, size=(50, 60))
    detector = IsolationForestDetector(n_estimators=10, subsample_size=32, random_seed=42)
    detector.fit(X_normal)

    # Nominal sample should yield valid anomaly score and attribution
    nominal_vec = np.ones(60) * 10.0
    nom_score, nom_attrib = detector.score_sample(nominal_vec)
    assert 0.0 <= nom_score <= 100.0

    # Anomalous sample should yield higher anomaly score
    anomaly_vec = np.ones(60) * 50.0
    anom_score, anom_attrib = detector.score_sample(anomaly_vec)
    assert 0.0 <= anom_score <= 100.0
    assert anom_score >= nom_score
    assert len(nom_attrib) > 0


def test_statistical_baseline_fit_and_evaluate() -> None:
    rng = np.random.RandomState(42)
    X = rng.normal(loc=5.0, scale=2.0, size=(30, 60))
    stat = StatisticalBaseline()
    stat.fit(X)

    # Test within baseline
    test_dict = {name: 5.0 for name in FEATURE_NAMES}
    score_nom, devs_nom = stat.evaluate(test_dict)
    assert 0.0 <= score_nom <= 1.0

    # Test extreme outlier
    outlier_dict = {name: 100.0 for name in FEATURE_NAMES}
    score_outlier, devs_outlier = stat.evaluate(outlier_dict)
    assert score_outlier >= score_nom
    assert len(devs_outlier) > 0


def test_concept_drift_detector() -> None:
    drift_det = ConceptDriftDetector()
    rng = np.random.RandomState(42)
    baseline_means = {name: 10.0 for name in FEATURE_NAMES}

    # Samples exactly matching baseline (no drift)
    recent_nominal = np.full((20, 60), 10.0)
    report_nodrift = drift_det.calculate_drift(baseline_means, recent_nominal, device_id="dev_01")
    assert report_nodrift.action == DriftAction.NO_DRIFT

    # Samples with heavy drift
    recent_drift = rng.normal(loc=25.0, scale=0.5, size=(20, 60))
    report_drift = drift_det.calculate_drift(baseline_means, recent_drift, device_id="dev_01")
    assert report_drift.action in (DriftAction.MODERATE_USER_CONFIRM, DriftAction.MAJOR_ALERT)


def test_threat_scorer_weighted_fusion() -> None:
    scorer = ThreatScorer()
    features_nominal = {name: 0.0 for name in FEATURE_NAMES}

    # Low threat: inputs in [0.0, 1.0]
    assessment_low = scorer.assess(
        ml_score=0.10,
        statistical_score=0.05,
        features=features_nominal,
    )
    assert assessment_low.threat_level == ThreatLevel.MONITOR
    assert assessment_low.threat_score <= 30

    # High threat
    features_threat = {name: 0.0 for name in FEATURE_NAMES}
    features_threat["new_dst_ip_flag"] = 1.0
    features_threat["high_risk_port_flag"] = 1.0
    assessment_high = scorer.assess(
        ml_score=0.95,
        statistical_score=0.90,
        features=features_threat,
    )
    assert assessment_high.threat_level in (ThreatLevel.QUARANTINE, ThreatLevel.BLOCK)
    assert assessment_high.threat_score >= 60
