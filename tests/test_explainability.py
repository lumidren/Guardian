"""
Unit tests for Explainable AI (XAI) and Natural Language Generation (NLG).
"""

from guardian.config import ThreatLevel
from guardian.ml.statistical_baseline import DeviationDetail
from guardian.ml.threat_scorer import ThreatAssessment
from guardian.xai.nlg_engine import NLGEngine


def test_nlg_report_structure():
    nlg = NLGEngine()

    assessment = ThreatAssessment(
        threat_score=96,
        threat_level=ThreatLevel.BLOCK,
        confidence_level="High (90-100%)",
        confidence_score=0.96,
        ml_score=0.92,
        statistical_score=0.95,
        layer_contributions={"Layer 1 (Behavioral)": 55.0, "Layer 2 (Network)": 30.0, "Layer 3 (Physical)": 15.0}
    )

    features = {
        "pkt_count_10s": 4823.0,
        "protocol_http_ratio": 0.60,
        "protocol_mqtt_ratio": 0.40,
        "new_dst_ip_flag": 1.0,
        "unique_dst_ips": 1.0,
        "external_ip_ratio": 0.95,
    }

    baseline_means = {
        "pkt_count_10s": 100.0,
        "protocol_http_ratio": 0.05,
        "protocol_mqtt_ratio": 0.95,
        "new_dst_ip_flag": 0.0,
    }

    stat_deviations = [
        DeviationDetail("pkt_count_10s", 4823.0, 100.0, 10.0, 472.3, 4723.0, True),
        DeviationDetail("new_dst_ip_flag", 1.0, 0.0, 0.01, 100.0, 100.0, True),
    ]

    report = nlg.generate_report(
        device_id="dev_08_camera",
        device_name="Smart Security Camera",
        assessment=assessment,
        features=features,
        baseline_means=baseline_means,
        ml_attribution={"pkt_count_10s": 0.45, "new_dst_ip_flag": 0.35},
        statistical_deviations=stat_deviations
    )

    assert report.threat_score == 96
    assert report.threat_level == "BLOCK"
    assert report.confidence_level == "High (90-100%)"
    assert len(report.why_blocked_bullet_points) >= 2
    assert len(report.recommended_actions) >= 3
    assert "SMART SECURITY CAMERA BLOCK" in report.plain_text_summary
    assert "WHY WAS IT BLOCK?" in report.plain_text_summary
