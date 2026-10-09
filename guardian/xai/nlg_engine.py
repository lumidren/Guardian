"""
Natural Language Generation (NLG) engine for GUARDIAN (Section 3.3.2).
Renders structured, transparent, human-readable explanations in plain English.
"""

from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from ..ml.threat_scorer import ThreatAssessment
from .explainer import FeatureAttribution, AnomalyExplainer
from .templates import AttackClassification, ATTACK_REMEDIATIONS


@dataclass
class ExplainableAlertReport:
    device_id: str
    device_name: str
    timestamp: str
    threat_score: int
    threat_level: str
    confidence_level: str
    likely_attack: str
    why_blocked_bullet_points: List[Dict[str, any]]
    recommended_actions: List[str]
    plain_text_summary: str

    def to_dict(self) -> dict:
        return asdict(self)


class NLGEngine:
    def __init__(self):
        self.explainer = AnomalyExplainer()

    def generate_report(
        self,
        device_id: str,
        device_name: str,
        assessment: ThreatAssessment,
        features: Dict[str, float],
        baseline_means: Dict[str, float],
        ml_attribution: Dict[str, float],
        statistical_deviations: list,
        timestamp: Optional[float] = None
    ) -> ExplainableAlertReport:
        """
        Generate complete GUARDIAN Explainable Alert Report matching Section 3.3.2.
        """
        dt_str = datetime.fromtimestamp(timestamp or datetime.now().timestamp()).strftime("%I:%M:%S %p")
        top_attrs, classification = self.explainer.explain(
            features=features,
            baseline_means=baseline_means,
            ml_attribution=ml_attribution,
            statistical_deviations=statistical_deviations,
            top_k=4
        )

        bullets = []
        for i, attr in enumerate(top_attrs, 1):
            bullets.append({
                "number": i,
                "title": attr.human_name,
                "observed": f"{attr.observed_value:,.1f} {attr.unit}".strip(),
                "normal": f"{attr.normal_value:,.1f} {attr.unit}".strip(),
                "deviation_pct": f"{attr.deviation_pct:+,.1f}%",
                "severity": attr.severity,
                "detail": attr.explanation_text
            })

        remediations = ATTACK_REMEDIATIONS.get(classification, [
            "Keep device isolated",
            "Review connected network activity",
            "Check for vendor firmware updates"
        ])

        # Generate the formatted plain text summary
        summary_lines = [
            f"{device_name.upper()} {assessment.threat_level.value}",
            f"THREAT DETECTED: {dt_str}",
            "",
            f"WHY WAS IT {assessment.threat_level.value}?",
        ]

        for b in bullets:
            summary_lines.append(f"{b['number']}. {b['title']}")
            summary_lines.append(f"   Normal: {b['normal']}")
            summary_lines.append(f"   Detected: {b['observed']}")
            summary_lines.append(f"   Deviation: {b['deviation_pct']}")
            summary_lines.append(f"   Severity: {b['severity']}")
            summary_lines.append("")

        summary_lines.append(f"THREAT SCORE: {assessment.threat_score}/100")
        summary_lines.append(f"CONFIDENCE: {assessment.confidence_level}")
        summary_lines.append(f"LIKELY ATTACK: {classification.value}")
        summary_lines.append("")
        summary_lines.append("RECOMMENDED ACTION:")
        for rem in remediations:
            summary_lines.append(f"• {rem}")

        plain_text = "\n".join(summary_lines)

        return ExplainableAlertReport(
            device_id=device_id,
            device_name=device_name,
            timestamp=dt_str,
            threat_score=assessment.threat_score,
            threat_level=assessment.threat_level.value,
            confidence_level=assessment.confidence_level,
            likely_attack=classification.value,
            why_blocked_bullet_points=bullets,
            recommended_actions=remediations,
            plain_text_summary=plain_text
        )
