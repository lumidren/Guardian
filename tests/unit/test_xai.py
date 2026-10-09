"""Unit tests for src/guardian/xai module."""

from guardian.config import FEATURE_NAMES, ThreatLevel
from guardian.ml.threat_scorer import ThreatAssessment
from guardian.xai.explainer import AnomalyExplainer
from guardian.xai.nlg_engine import NLGEngine
from guardian.xai.templates import ATTACK_REMEDIATIONS, AttackClassification


def test_anomaly_explainer_attribution_and_classification() -> None:
    explainer = AnomalyExplainer()
    features = {name: 10.0 for name in FEATURE_NAMES}
    features["pkt_count_10s"] = 1500.0
    features["byte_rate_per_sec"] = 80000.0

    baseline_means = {name: 10.0 for name in FEATURE_NAMES}
    ml_attribution = {"pkt_count_10s": 0.45, "byte_rate_per_sec": 0.35}

    top_attrs, classification = explainer.explain(
        features=features,
        baseline_means=baseline_means,
        ml_attribution=ml_attribution,
        statistical_deviations=[],
        top_k=3,
    )
    assert len(top_attrs) <= 3
    assert top_attrs[0].feature_name in ("pkt_count_10s", "byte_rate_per_sec")
    assert isinstance(classification, AttackClassification)
    assert classification == AttackClassification.DDOS_FLOODING


def test_nlg_engine_report_generation() -> None:
    nlg = NLGEngine()
    features = {name: 5.0 for name in FEATURE_NAMES}
    features["pkt_count_10s"] = 2000.0
    baseline_means = {name: 5.0 for name in FEATURE_NAMES}

    assessment = ThreatAssessment(
        threat_score=92,
        threat_level=ThreatLevel.BLOCK,
        confidence_level="High (90-100%)",
        confidence_score=0.96,
        ml_score=0.92,
        statistical_score=0.88,
        layer_contributions={"Layer 1": 55.0},
    )

    report = nlg.generate_report(
        device_id="esp32_sensor_01",
        device_name="Living Room DHT22",
        assessment=assessment,
        features=features,
        baseline_means=baseline_means,
        ml_attribution={"pkt_count_10s": 0.8},
        statistical_deviations=[],
    )
    assert report.device_id == "esp32_sensor_01"
    assert report.threat_score == 92
    assert report.threat_level == "BLOCK"
    assert len(report.why_blocked_bullet_points) > 0
    assert len(report.recommended_actions) > 0
    assert "living room dht22" in report.plain_text_summary.lower()

    report_dict = report.to_dict()
    assert report_dict["threat_score"] == 92


def test_attack_remediations_coverage() -> None:
    for attack in AttackClassification:
        remediations = ATTACK_REMEDIATIONS.get(attack)
        assert remediations is not None
        assert len(remediations) > 0
