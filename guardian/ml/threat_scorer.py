"""
Multi-layer Threat Scorer for GUARDIAN.
Synthesizes ML Isolation Forest anomaly scores, Z-score statistics, and Layer 2/3 heuristics
into a unified Threat Score (0-100), Confidence Level, and Graduated Threat Level.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from ..config import ThreatLevel, config


@dataclass
class ThreatAssessment:
    threat_score: int              # 0 - 100
    threat_level: ThreatLevel      # MONITOR, RESTRICT, QUARANTINE, BLOCK
    confidence_level: str          # "High (90-100%)", "Medium (70-89%)", "Low (50-69%)"
    confidence_score: float        # 0.0 - 1.0
    ml_score: float                # Raw Isolation Forest score [0.0 - 1.0]
    statistical_score: float       # Raw Z-score statistical score [0.0 - 1.0]
    layer_contributions: Dict[str, float]  # Percentage contribution per layer


class ThreatScorer:
    def __init__(self):
        self.w_ml = 0.55
        self.w_stat = 0.25
        self.w_heuristics = 0.20

    def assess(
        self,
        ml_score: float,
        statistical_score: float,
        features: Dict[str, float],
        is_cold_start: bool = False
    ) -> ThreatAssessment:
        """
        Compute normalized threat assessment for the current flow window.
        """
        # If still in cold start, rely primarily on statistical & heuristic checks
        if is_cold_start:
            w_ml = 0.0
            w_stat = 0.60
            w_heur = 0.40
        else:
            w_ml = self.w_ml
            w_stat = self.w_stat
            w_heur = self.w_heuristics

        # Layer 2 & Layer 3 Heuristics score
        new_dst_flag = features.get("new_dst_ip_flag", 0.0)
        high_risk_port = features.get("high_risk_port_flag", 0.0)
        external_ratio = features.get("external_ip_ratio", 0.0)
        ttl_var = min(1.0, features.get("ip_ttl_variance", 0.0) / 10.0)
        clock_skew = min(1.0, features.get("tcp_clock_skew_est", 0.0) / 2.0)

        heuristic_score = min(1.0, (
            new_dst_flag * 0.45 +
            high_risk_port * 0.35 +
            external_ratio * 0.10 +
            ttl_var * 0.05 +
            clock_skew * 0.05
        ))

        # Composite anomaly calculation
        composite = (ml_score * w_ml) + (statistical_score * w_stat) + (heuristic_score * w_heur)
        
        # Non-linear amplifier for severe multiple-layer correlations (Defense in Depth)
        if ml_score > 0.65 and new_dst_flag > 0.5:
            composite = min(1.0, composite * 1.35)
        if high_risk_port > 0.5:
            composite = min(1.0, composite * 1.25)

        # Scale to integer 0 - 100
        threat_score = int(round(max(0.0, min(100.0, composite * 100.0))))

        # Map to Graduated Response Level
        if threat_score < config.THREAT_THRESHOLD_RESTRICT:
            threat_level = ThreatLevel.MONITOR
        elif threat_score < config.THREAT_THRESHOLD_QUARANTINE:
            threat_level = ThreatLevel.RESTRICT
        elif threat_score < config.THREAT_THRESHOLD_BLOCK:
            threat_level = ThreatLevel.QUARANTINE
        else:
            threat_level = ThreatLevel.BLOCK

        # Confidence Scoring (Section 9.1 Item 2)
        # Agreement between ML and Statistical baselines increases confidence
        agreement = 1.0 - abs(ml_score - statistical_score)
        sample_density_bonus = 0.2 if not is_cold_start else 0.0
        conf_float = max(0.50, min(0.99, (agreement * 0.5) + (composite * 0.3) + sample_density_bonus))

        if conf_float >= 0.88 or threat_score >= 85:
            conf_str = "High (90-100%)"
        elif conf_float >= 0.70 or threat_score >= 50:
            conf_str = "Medium (70-89%)"
        else:
            conf_str = "Low (50-69%)"

        # Multi-layer contribution breakdown
        l1_sum = features.get("pkt_count_10s", 0) + features.get("byte_count_10s", 0)
        layer_contributions = {
            "Layer 1 (Behavioral)": round(w_ml * 100, 1),
            "Layer 2 (Network Destinations)": round((w_heur * 0.7 + w_stat * 0.5) * 100, 1),
            "Layer 3 (Physical/Heuristic)": round((w_heur * 0.3 + w_stat * 0.5) * 100, 1),
        }

        return ThreatAssessment(
            threat_score=threat_score,
            threat_level=threat_level,
            confidence_level=conf_str,
            confidence_score=conf_float,
            ml_score=ml_score,
            statistical_score=statistical_score,
            layer_contributions=layer_contributions
        )
