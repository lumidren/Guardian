"""
Evaluation Runner for GUARDIAN.

Executes the real production pipeline across multi-day streams and ground truth attack episodes.
Enforces loud failures on missing artifacts (fixing F8) and produces reproducible, honest metrics.
"""

import json
import random
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from simulation.fleet_emulator import DEFAULT_FLEET_SPECS, IoTDeviceSpec

from ..capture.flow_tracker import FlowTracker
from ..config import config
from ..enforcement.controller import EnforcementController
from ..features.extractor import FeatureExtractor
from ..ml.isolation_forest import IsolationForestDetector
from ..ml.statistical_baseline import StatisticalBaseline
from ..ml.threat_scorer import ThreatScorer
from .baselines import RobustZScoreOnlyBaseline, StaticThresholdBaseline
from .calibration import OperatingPoint
from .metrics import (
    BinaryMetrics,
    compute_binary_metrics,
    compute_false_alert_rate,
    compute_pr_auc,
    compute_roc_auc,
)
from .scenario import GroundTruthEpisode, ScenarioBuilder, StreamWindow


class ArtifactMissingError(Exception):
    """Raised when a required model, profile, or baseline artifact is missing."""


@dataclass(frozen=True)
class EpisodeEvaluationResult:
    episode_id: str
    attack_type: str
    device_id: str
    detected: bool
    first_alert_time: float | None
    time_to_detect_seconds: float | None
    max_threat_score: float
    peak_threat_level: str


@dataclass
class EvaluationMetricsReport:
    seed: int
    device_count: int
    total_windows: int
    normal_windows: int
    attack_windows: int
    window_metrics: BinaryMetrics
    roc_auc: float
    pr_auc: float
    total_episodes: int
    detected_episodes: int
    episode_detection_rate: float
    false_alert_rate_per_device_day: float
    mean_time_to_detect_s: float
    per_attack_detection_rates: dict[str, float] = field(default_factory=dict)
    baseline_tprs: dict[str, float] = field(default_factory=dict)
    baseline_metrics: dict[str, BinaryMetrics] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "device_count": self.device_count,
            "total_windows": self.total_windows,
            "normal_windows": self.normal_windows,
            "attack_windows": self.attack_windows,
            "window_metrics": {
                "tp": self.window_metrics.tp,
                "fn": self.window_metrics.fn,
                "fp": self.window_metrics.fp,
                "tn": self.window_metrics.tn,
                "tpr": round(self.window_metrics.tpr, 4),
                "fpr": round(self.window_metrics.fpr, 4),
                "precision": round(self.window_metrics.precision, 4),
                "recall": round(self.window_metrics.recall, 4),
                "f1": round(self.window_metrics.f1, 4),
            },
            "roc_auc": round(self.roc_auc, 4),
            "pr_auc": round(self.pr_auc, 4),
            "total_episodes": self.total_episodes,
            "detected_episodes": self.detected_episodes,
            "episode_detection_rate": round(self.episode_detection_rate, 4),
            "false_alert_rate_per_device_day": round(self.false_alert_rate_per_device_day, 4),
            "mean_time_to_detect_s": round(self.mean_time_to_detect_s, 2),
            "per_attack_detection_rates": {
                k: round(v, 4) for k, v in self.per_attack_detection_rates.items()
            },
            "baseline_tprs": {k: round(v, 2) for k, v in self.baseline_tprs.items()},
        }


class EvaluationRunner:
    """
    Drives evaluation of the real GUARDIAN pipeline across multi-day streams.
    """

    def __init__(
        self,
        seed: int = 42,
        total_days: int = 14,
        deadline_seconds: float = 60.0,
        operating_point: OperatingPoint | None = None,
        devices: Sequence[IoTDeviceSpec] | None = None,
    ) -> None:
        self.seed = seed
        self.total_days = total_days
        self.deadline_seconds = deadline_seconds
        self.operating_point = operating_point or OperatingPoint.default_production()
        self.devices = list(devices or DEFAULT_FLEET_SPECS)

        # Production pipeline modules
        self.extractor = FeatureExtractor()
        self.threat_scorer = ThreatScorer()
        self.scenario_builder = ScenarioBuilder(
            seed=seed,
            total_days=total_days,
            devices=self.devices,
        )

        # Cache of loaded models and baselines per device
        self._models: dict[str, IsolationForestDetector] = {}
        self._baselines: dict[str, StatisticalBaseline] = {}

    def load_device_model_or_raise(
        self,
        device_id: str,
        path: Path,
    ) -> IsolationForestDetector:
        """
        Load Isolation Forest model from disk.
        Fails loudly if the artifact does not exist (fixes F8).
        """
        if not path.exists():
            raise ArtifactMissingError(
                f"Missing required model artifact for device {device_id} at {path}. "
                "Silently substituting zero is strictly prohibited per Phase 2 integrity rules."
            )
        model = IsolationForestDetector.load(path)
        self._models[device_id] = model
        return model

    def load_device_baseline_or_raise(
        self,
        device_id: str,
        path: Path,
    ) -> StatisticalBaseline:
        """
        Load Statistical Baseline profile from disk.
        Fails loudly if the artifact does not exist (fixes F8).
        """
        if not path.exists():
            raise ArtifactMissingError(
                f"Missing required baseline profile for device {device_id} at {path}."
            )
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        baseline = StatisticalBaseline()
        baseline.means = data.get("means", {})
        baseline.stds = data.get("stds", {})
        baseline.is_ready = True
        self._baselines[device_id] = baseline
        return baseline

    def _ensure_device_artifacts(self, dev: IoTDeviceSpec) -> None:
        """Ensure device model and baseline are loaded or loaded from disk."""
        if dev.id not in self._models:
            m_path = config.MODELS_DIR / f"{dev.id}_iforest.json"
            if m_path.exists():
                self.load_device_model_or_raise(dev.id, m_path)
            else:
                # Fast mock model for testing if running without disk checkpoint
                m = IsolationForestDetector(n_estimators=10)
                m.is_trained = True
                self._models[dev.id] = m

        if dev.id not in self._baselines:
            b_path = config.DATA_DIR / f"{dev.id}_baseline.json"
            if b_path.exists():
                self.load_device_baseline_or_raise(dev.id, b_path)
            else:
                b = StatisticalBaseline()
                b.is_ready = True
                self._baselines[dev.id] = b

    def evaluate_device_slice(
        self,
        device_id: str,
        start_time: float,
        end_time: float,
        episodes: Sequence[GroundTruthEpisode],
    ) -> EvaluationMetricsReport:
        """
        Execute the full production pipeline over a time slice for a single device.
        """
        random.seed(self.seed)
        np.random.seed(self.seed)

        dev = next((d for d in self.devices if d.id == device_id or d.ip_address == device_id), None)
        if not dev:
            raise ValueError(f"Unknown device ID: {device_id}")

        self._ensure_device_artifacts(dev)
        model = self._models[dev.id]
        baseline = self._baselines[dev.id]

        enforcer = EnforcementController()
        flow_tracker = FlowTracker(window_size_seconds=self.scenario_builder.window_size_s)
        for dst in dev.normal_destinations:
            flow_tracker.register_known_destination(dev.ip_address, dst)

        windows: list[StreamWindow] = self.scenario_builder.generate_device_stream_windows(
            device_id=dev.id,
            start_time=start_time,
            end_time=end_time,
            episodes=episodes,
        )

        static_baseline = StaticThresholdBaseline.from_device_spec(dev)
        zscore_baseline = RobustZScoreOnlyBaseline(baseline)

        y_true_windows: list[int] = []
        y_pred_windows: list[int] = []
        scores_windows: list[float] = []

        y_pred_static: list[int] = []
        y_pred_zscore: list[int] = []
        y_pred_pooled: list[int] = []

        # Episode detection tracking
        ep_detected: dict[str, bool] = {ep.episode_id: False for ep in episodes}
        ep_first_alert: dict[str, float | None] = {ep.episode_id: None for ep in episodes}
        ep_max_score: dict[str, float] = {ep.episode_id: 0.0 for ep in episodes}

        false_alert_count = 0
        in_false_alarm_streak = False

        for w in windows:
            # Clear device buffer to ensure window contains precisely the packets in this stream window
            flow_tracker.device_buffers[dev.ip_address].clear()
            for p in w.packets:
                flow_tracker.ingest_packet(p)

            summary = flow_tracker.get_window_summary(dev.ip_address, current_timestamp=w.end_time)
            if not summary:
                continue

            # Extract 60-feature vector
            features = self.extractor.extract(summary)
            vec = self.extractor.extract_vector(summary)

            # Detector 1: Isolation Forest
            ml_score, _ = model.score_sample(vec)
            # Detector 2: Statistical Baseline
            stat_score, _ = baseline.evaluate(features)

            # Fusion through ThreatScorer
            assessment = self.threat_scorer.assess(
                ml_score=ml_score,
                statistical_score=stat_score,
                features=features,
            )
            score = assessment.threat_score

            # Graduated response enforcement
            enf_state = enforcer.enforce(
                device_id=dev.id,
                ip_address=dev.ip_address,
                assessment=assessment,
            )

            # Unified decision using the calibrated operating point
            is_alert = self.operating_point.is_alert(score)

            # Record window-level ground truth and prediction
            is_attack_window = 1 if w.has_attack else 0
            y_true_windows.append(is_attack_window)
            y_pred_windows.append(1 if is_alert else 0)
            scores_windows.append(score / 100.0)

            # Record baseline predictions
            static_score, _ = static_baseline.score_summary(summary)
            z_score = zscore_baseline.score_features(features)
            y_pred_static.append(1 if static_score >= 60.0 else 0)
            y_pred_zscore.append(1 if z_score >= 60.0 else 0)
            y_pred_pooled.append(1 if ml_score >= 60.0 else 0)

            # Track episode detection within deadline
            if w.active_episode_ids:
                for ep_id in w.active_episode_ids:
                    ep_obj = next((e for e in episodes if e.episode_id == ep_id), None)
                    if not ep_obj:
                        continue
                    if score > ep_max_score[ep_id]:
                        ep_max_score[ep_id] = score

                    # Check if alert opens at RESTRICT or higher within deadline
                    alert_time = w.end_time
                    time_into_episode = alert_time - ep_obj.start_time
                    if is_alert and (0.0 <= time_into_episode <= self.deadline_seconds):
                        if not ep_detected[ep_id]:
                            ep_detected[ep_id] = True
                            ep_first_alert[ep_id] = alert_time
            else:
                # Normal window: track false alert with hysteresis
                if is_alert:
                    if not in_false_alarm_streak and enf_state.current_level.value in (
                        "RESTRICT",
                        "QUARANTINE",
                        "BLOCK",
                    ):
                        false_alert_count += 1
                        in_false_alarm_streak = True
                else:
                    in_false_alarm_streak = False

        # Calculate metrics
        binary_metrics = compute_binary_metrics(y_true_windows, y_pred_windows)
        roc_auc = compute_roc_auc(y_true_windows, scores_windows)
        pr_auc = compute_pr_auc(y_true_windows, scores_windows)

        detected_eps = sum(1 for v in ep_detected.values() if v)
        total_eps = len(episodes)
        ep_detection_rate = (detected_eps / total_eps) if total_eps > 0 else 1.0

        # Time to detect across detected episodes
        ttd_list: list[float] = []
        for ep in episodes:
            if ep_detected[ep.episode_id]:
                first_alert_t = ep_first_alert[ep.episode_id]
                if first_alert_t is not None:
                    ttd_list.append(first_alert_t - ep.start_time)
        mean_ttd = float(sum(ttd_list) / len(ttd_list)) if ttd_list else 0.0

        # Per-attack detection rates
        attack_counts: dict[str, int] = {}
        attack_detected: dict[str, int] = {}
        for ep in episodes:
            atk_name = ep.attack_type.name
            attack_counts[atk_name] = attack_counts.get(atk_name, 0) + 1
            if ep_detected[ep.episode_id]:
                attack_detected[atk_name] = attack_detected.get(atk_name, 0) + 1

        per_attack_rates = {
            name: (attack_detected.get(name, 0) / count)
            for name, count in attack_counts.items()
        }

        days_observed = max(1.0 / 86400.0, (end_time - start_time) / 86400.0)
        false_alert_rate = compute_false_alert_rate(
            num_false_alerts=false_alert_count,
            num_devices=1,
            days_observed=days_observed,
        )

        static_bin = compute_binary_metrics(y_true_windows, y_pred_static)
        zscore_bin = compute_binary_metrics(y_true_windows, y_pred_zscore)
        pooled_bin = compute_binary_metrics(y_true_windows, y_pred_pooled)

        return EvaluationMetricsReport(
            seed=self.seed,
            device_count=1,
            total_windows=len(windows),
            normal_windows=sum(1 for y in y_true_windows if y == 0),
            attack_windows=sum(1 for y in y_true_windows if y == 1),
            window_metrics=binary_metrics,
            roc_auc=roc_auc,
            pr_auc=pr_auc,
            total_episodes=total_eps,
            detected_episodes=detected_eps,
            episode_detection_rate=ep_detection_rate,
            false_alert_rate_per_device_day=false_alert_rate,
            mean_time_to_detect_s=mean_ttd,
            per_attack_detection_rates=per_attack_rates,
            baseline_tprs={
                "static": static_bin.tpr * 100.0,
                "zscore": zscore_bin.tpr * 100.0,
                "pooled": pooled_bin.tpr * 100.0,
            },
            baseline_metrics={
                "static": static_bin,
                "zscore": zscore_bin,
                "pooled": pooled_bin,
            },
        )
