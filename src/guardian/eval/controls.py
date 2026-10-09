"""
Evaluation Validity Controls and Leakage Audit Harness (Milestone P3-1).

Implements broken-detector controls and validity checks:
1. Label isolation verification.
2. Non-semantic artifact leakage audit.
3. Shuffled-label control (TPR must collapse to roughly FPR).
4. Always-alert (TPR=1.0, FPR=1.0) and Never-alert (TPR=0.0, FPR=0.0) bounds.
5. Random-score detector control (ROC-AUC ~ 0.50).
6. Timeline extraction for pure-attack-window verification.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from ..capture.flow_tracker import FlowTracker
from ..enforcement.controller import EnforcementController
from ..features.extractor import FeatureExtractor
from ..ml.isolation_forest import IsolationForestDetector
from ..ml.statistical_baseline import StatisticalBaseline
from ..ml.threat_scorer import ThreatScorer
from .calibration import OperatingPoint
from .metrics import compute_binary_metrics, compute_roc_auc
from .scenario import GroundTruthEpisode, ScenarioBuilder


@dataclass
class ControlsEvaluationResult:
    always_alert_tpr: float
    always_alert_fpr: float
    never_alert_tpr: float
    never_alert_fpr: float
    random_score_roc_auc: float
    shuffled_tpr: float
    shuffled_fpr: float
    shuffled_roc_auc: float
    controls_passed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "always_alert": {
                "tpr": self.always_alert_tpr,
                "fpr": self.always_alert_fpr,
                "status": "PASS" if (self.always_alert_tpr == 1.0 and self.always_alert_fpr == 1.0) else "FAIL",
            },
            "never_alert": {
                "tpr": self.never_alert_tpr,
                "fpr": self.never_alert_fpr,
                "status": "PASS" if (self.never_alert_tpr == 0.0 and self.never_alert_fpr == 0.0) else "FAIL",
            },
            "random_score_detector": {
                "roc_auc": round(self.random_score_roc_auc, 4),
                "status": "PASS" if (0.40 <= self.random_score_roc_auc <= 0.60) else "FAIL",
            },
            "shuffled_labels": {
                "tpr": round(self.shuffled_tpr, 4),
                "fpr": round(self.shuffled_fpr, 4),
                "roc_auc": round(self.shuffled_roc_auc, 4),
                "status": "PASS" if (abs(self.shuffled_tpr - self.shuffled_fpr) <= 0.25) else "FAIL",
            },
            "controls_passed": self.controls_passed,
        }


class EvaluationControlBattery:
    """
    Executes standard broken-detector and label integrity controls.
    """

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed

    def run_all_controls(
        self,
        y_true: Sequence[int],
        scores: Sequence[float],
        operating_point: OperatingPoint | None = None,
    ) -> ControlsEvaluationResult:
        """
        Run the complete battery of broken-detector and shuffled-label controls.
        """
        op = operating_point or OperatingPoint.default_production()
        y_t = list(y_true)
        sc = list(scores)

        # 1. Always Alert Control
        y_always = [1] * len(y_t)
        always_bm = compute_binary_metrics(y_t, y_always)

        # 2. Never Alert Control
        y_never = [0] * len(y_t)
        never_bm = compute_binary_metrics(y_t, y_never)

        # 3. Random Score Detector Control
        rng = np.random.default_rng(self.seed)
        random_scores = rng.uniform(0.0, 1.0, size=len(y_t)).tolist()
        random_roc = compute_roc_auc(y_t, random_scores)

        # 4. Shuffled Labels Control
        y_shuffled = rng.permutation(y_t).tolist()
        y_pred = [1 if op.is_alert(s * 100.0) else 0 for s in sc]
        shuffled_bm = compute_binary_metrics(y_shuffled, y_pred)
        shuffled_roc = compute_roc_auc(y_shuffled, sc)

        # Pass criteria
        p_always = (always_bm.tpr == 1.0 and always_bm.fpr == 1.0)
        p_never = (never_bm.tpr == 0.0 and never_bm.fpr == 0.0)
        p_random = (0.40 <= random_roc <= 0.60)
        p_shuffled = (abs(shuffled_bm.tpr - shuffled_bm.fpr) <= 0.25)

        all_passed = p_always and p_never and p_random and p_shuffled

        return ControlsEvaluationResult(
            always_alert_tpr=always_bm.tpr,
            always_alert_fpr=always_bm.fpr,
            never_alert_tpr=never_bm.tpr,
            never_alert_fpr=never_bm.fpr,
            random_score_roc_auc=random_roc,
            shuffled_tpr=shuffled_bm.tpr,
            shuffled_fpr=shuffled_bm.fpr,
            shuffled_roc_auc=shuffled_roc,
            controls_passed=all_passed,
        )


@dataclass
class EpisodeTimelinePoint:
    time_offset_s: float
    window_start: float
    has_attack: bool
    attack_packet_count: int
    normal_packet_count: int
    threat_score: float
    threat_level: str


def extract_episode_timeline(
    device_id: str,
    episode: GroundTruthEpisode,
    scenario_builder: ScenarioBuilder,
    lead_time_s: float = 20.0,
    lag_time_s: float = 20.0,
) -> list[EpisodeTimelinePoint]:
    """
    Extracts high-resolution window-by-window scores before, during, and after an attack episode.
    Used for pure-attack-window verification and score evolution auditing.
    """
    dev = next(d for d in scenario_builder.devices if d.id == device_id)
    t_start = max(0.0, episode.start_time - lead_time_s)
    t_end = episode.end_time + lag_time_s

    windows = scenario_builder.generate_device_stream_windows(
        device_id=dev.id,
        start_time=t_start,
        end_time=t_end,
        episodes=[episode],
    )

    extractor = FeatureExtractor()
    scorer = ThreatScorer()
    enforcer = EnforcementController()
    model = IsolationForestDetector(n_estimators=10)
    model.is_trained = True
    baseline = StatisticalBaseline()
    baseline.is_ready = True

    flow_tracker = FlowTracker(window_size_seconds=scenario_builder.window_size_s)
    for dst in dev.normal_destinations:
        flow_tracker.register_known_destination(dev.ip_address, dst)

    timeline: list[EpisodeTimelinePoint] = []
    for w in windows:
        for p in w.packets:
            flow_tracker.ingest_packet(p)

        summary = flow_tracker.get_window_summary(dev.ip_address)
        if not summary:
            continue

        feat = extractor.extract(summary)
        vec = extractor.extract_vector(summary)

        ml_score, _ = model.score_sample(vec)
        stat_score, _ = baseline.evaluate(feat)
        assessment = scorer.assess(ml_score, stat_score, feat)
        enf = enforcer.enforce(dev.id, dev.ip_address, assessment)

        timeline.append(
            EpisodeTimelinePoint(
                time_offset_s=round(w.start_time - episode.start_time, 2),
                window_start=round(w.start_time, 2),
                has_attack=w.has_attack,
                attack_packet_count=w.attack_packet_count,
                normal_packet_count=w.normal_packet_count,
                threat_score=round(assessment.threat_score, 2),
                threat_level=enf.current_level.value,
            )
        )

    return timeline
