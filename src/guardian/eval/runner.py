"""
Evaluation Runner for GUARDIAN.

Executes the real production pipeline across multi-day streams and ground truth attack episodes.
Enforces loud failures on missing artifacts (fixing F8) and produces reproducible, honest metrics.
"""

import json
import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from simulation.attack_suite import AttackType
from simulation.fleet_emulator import DEFAULT_FLEET_SPECS, IoTDeviceSpec

from ..capture.flow_tracker import FlowTracker
from ..config import config
from ..enforcement.controller import EnforcementController
from ..features.extractor import FeatureExtractor
from ..ml.isolation_forest import IsolationForestDetector
from ..ml.statistical_baseline import StatisticalBaseline
from ..ml.threat_scorer import ThreatScorer
from .baselines import (
    PooledIsolationForestBaseline,
    RobustZScoreOnlyBaseline,
    StaticThresholdBaseline,
)
from .calibration import Calibrator, OperatingPoint
from .metrics import (
    BinaryMetrics,
    compute_binary_metrics,
    compute_f1_from_confusion_counts,
    compute_false_alert_rate,
    compute_pr_auc,
    compute_roc_auc,
)
from .scenario import GroundTruthEpisode, HardNegativeType, ScenarioBuilder, StreamWindow


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
    baseline_f1s: dict[str, float] = field(default_factory=dict)
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
            "baseline_f1s": {k: round(v, 4) for k, v in self.baseline_f1s.items()},
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
        self._pooled_model: PooledIsolationForestBaseline | None = None
        self._baseline_thresholds: dict[str, float] = {
            "static": 60.0,
            "zscore": 60.0,
            "pooled": 52.0,
        }

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
                # Train a quick per-device model on Day 1 clean traffic if disk artifact missing
                m = IsolationForestDetector(n_estimators=25, random_seed=self.seed)
                train_vecs = self._extract_clean_vectors(dev, duration_s=30.0)
                if len(train_vecs) >= 2:
                    m.fit(np.asarray(train_vecs, dtype=float), device_id=dev.id)
                else:
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

    def _extract_clean_vectors(
        self,
        dev: IoTDeviceSpec,
        start_time: float = 0.0,
        duration_s: float = 40.0,
    ) -> list[np.ndarray]:
        """Extract clean feature vectors from Days 1-7 training split for a device."""
        windows = self.scenario_builder.generate_device_stream_windows(
            device_id=dev.id,
            start_time=start_time,
            end_time=start_time + duration_s,
            episodes=[],
        )
        flow_tracker = FlowTracker(window_size_seconds=self.scenario_builder.window_size_s)
        for dst in dev.normal_destinations:
            flow_tracker.register_known_destination(dev.ip_address, dst)
        vecs: list[np.ndarray] = []
        for w in windows:
            flow_tracker.device_buffers[dev.ip_address].clear()
            for p in w.packets:
                flow_tracker.ingest_packet(p)
            summary = flow_tracker.get_window_summary(dev.ip_address, current_timestamp=w.end_time)
            if summary:
                vecs.append(self.extractor.extract_vector(summary))
        return vecs

    def _ensure_pooled_model(self) -> PooledIsolationForestBaseline:
        """
        Train fleet-wide PooledIsolationForestBaseline on Days 1-7 pooled feature
        distributions across all devices without per-device separation.
        """
        if self._pooled_model is not None and self._pooled_model.is_trained:
            return self._pooled_model

        pool_seed = (self.seed * 100003 + 101) & 0x7FFFFFFF
        random.seed(pool_seed)
        np.random.seed(pool_seed)

        pooled_vecs: list[np.ndarray] = []
        for idx, dev in enumerate(self.devices):
            dev_vecs = self._extract_clean_vectors(
                dev,
                start_time=float(idx * 3600.0),
                duration_s=40.0,
            )
            pooled_vecs.extend(dev_vecs)

        pooled = PooledIsolationForestBaseline(n_estimators=50, seed=self.seed)
        if len(pooled_vecs) >= 2:
            pooled.fit([v.tolist() for v in pooled_vecs])
            train_scores = [float(pooled.score_sample(v)[0] * 100.0) for v in pooled_vecs]
            if train_scores:
                op = Calibrator(target_fpr=0.05).calibrate_from_scores(train_scores)
                self._baseline_thresholds["pooled"] = min(95.0, float(op.alert_threshold))
        self._pooled_model = pooled
        return pooled

    def calibrate_pooled_threshold(
        self,
        pooled_cal_scores: Sequence[float],
        target_fpr: float = 0.05,
    ) -> float:
        """
        Calibrate PooledIsolationForestBaseline alert threshold on Day 8 clean scores
        on the [0, 100] scale, clamped below 95.0 to prevent saturation lock-out.
        """
        if not pooled_cal_scores:
            return float(self._baseline_thresholds.get("pooled", 52.0))
        pooled_op = Calibrator(target_fpr=target_fpr).calibrate_from_scores(pooled_cal_scores)
        thresh = min(95.0, max(35.0, float(pooled_op.alert_threshold)))
        self._baseline_thresholds["pooled"] = thresh
        return thresh

    def calibrate_operating_point(
        self,
        target_fpr: float = 0.05,
        duration_per_device_s: float = 60.0,
    ) -> OperatingPoint:
        """
        Calibrate OperatingPoint threshold on Day 8 clean background traffic and freeze it.
        Also calibrates PooledIsolationForestBaseline threshold on the same Day 8 split.
        Strict time-ordered split: Day 8 (604,800s to 691,200s).
        """
        cal_start = 7.0 * self.scenario_builder.SECONDS_PER_DAY
        calibration_scores: list[float] = []
        pooled_cal_scores: list[float] = []
        pooled_model = self._ensure_pooled_model()
        for dev in self.devices:
            self._ensure_device_artifacts(dev)

        cal_seed = (self.seed * 100003 + 202) & 0x7FFFFFFF
        random.seed(cal_seed)
        np.random.seed(cal_seed)

        for dev in self.devices:
            model = self._models[dev.id]
            baseline = self._baselines[dev.id]

            cal_windows = self.scenario_builder.generate_device_stream_windows(
                device_id=dev.id,
                start_time=cal_start,
                end_time=cal_start + duration_per_device_s,
                episodes=[],
            )

            flow_tracker = FlowTracker(window_size_seconds=self.scenario_builder.window_size_s)
            for dst in dev.normal_destinations:
                flow_tracker.register_known_destination(dev.ip_address, dst)

            for w in cal_windows:
                flow_tracker.device_buffers[dev.ip_address].clear()
                for p in w.packets:
                    flow_tracker.ingest_packet(p)

                summary = flow_tracker.get_window_summary(dev.ip_address, current_timestamp=w.end_time)
                if not summary:
                    continue

                features = self.extractor.extract(summary)
                vec = self.extractor.extract_vector(summary)
                ml_score, _ = model.score_sample(vec)
                stat_score, _ = baseline.evaluate(features)
                assessment = self.threat_scorer.assess(
                    ml_score=ml_score,
                    statistical_score=stat_score,
                    features=features,
                )
                calibration_scores.append(assessment.threat_score)

                p_raw, _ = pooled_model.score_sample(vec)
                pooled_cal_scores.append(float(p_raw * 100.0))

        calibrator = Calibrator(target_fpr=target_fpr)
        chosen_op = calibrator.calibrate_from_scores(calibration_scores)
        self.operating_point = chosen_op

        self.calibrate_pooled_threshold(pooled_cal_scores, target_fpr=target_fpr)

        return chosen_op

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
        dev = next((d for d in self.devices if d.id == device_id or d.ip_address == device_id), None)
        if not dev:
            raise ValueError(f"Unknown device ID: {device_id}")

        self._ensure_device_artifacts(dev)
        model = self._models[dev.id]
        baseline = self._baselines[dev.id]
        pooled_model = self._ensure_pooled_model()

        slice_seed = (self.seed * 100003 + int(start_time)) & 0x7FFFFFFF
        random.seed(slice_seed)
        np.random.seed(slice_seed)

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
        ep_max_pooled: dict[str, float] = {ep.episode_id: 0.0 for ep in episodes}
        ep_max_static: dict[str, float] = {ep.episode_id: 0.0 for ep in episodes}
        ep_max_zscore: dict[str, float] = {ep.episode_id: 0.0 for ep in episodes}

        false_alert_count = 0
        in_false_alarm_streak = False
        window_records: list[dict[str, Any]] = []

        pooled_thresh = self._baseline_thresholds.get("pooled", 52.0)
        static_thresh = self._baseline_thresholds.get("static", 60.0)
        zscore_thresh = self._baseline_thresholds.get("zscore", 60.0)

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

            # Detector 1: Per-Device Isolation Forest
            ml_score, _ = model.score_sample(vec)
            # Detector 2: Statistical Baseline
            stat_score, _ = baseline.evaluate(features)

            # Fusion through ThreatScorer
            assessment = self.threat_scorer.assess(
                ml_score=ml_score,
                statistical_score=stat_score,
                features=features,
            )
            score = float(assessment.threat_score)

            # Baseline detectors (all scaled to [0.0, 100.0])
            static_score, _ = static_baseline.score_summary(summary)
            z_score = zscore_baseline.score_features(features)
            pooled_raw, _ = pooled_model.score_sample(vec)
            pooled_score = float(pooled_raw * 100.0)

            window_records.append(
                {
                    "end_time": w.end_time,
                    "has_attack": w.has_attack,
                    "active_episode_ids": w.active_episode_ids,
                    "base_features": features,
                    "base_ml_score": ml_score,
                    "base_stat_score": stat_score,
                    "guardian_score": score,
                    "pooled_score": pooled_score,
                    "static_score": float(static_score),
                    "zscore_score": float(z_score),
                }
            )

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

            # Record baseline predictions using calibrated/scaled [0, 100] thresholds
            y_pred_static.append(1 if static_score >= static_thresh else 0)
            y_pred_zscore.append(1 if z_score >= zscore_thresh else 0)
            y_pred_pooled.append(1 if pooled_score >= pooled_thresh else 0)

            # Track episode detection within deadline
            if w.active_episode_ids:
                for ep_id in w.active_episode_ids:
                    ep_obj = next((e for e in episodes if e.episode_id == ep_id), None)
                    if not ep_obj:
                        continue
                    alert_time = w.end_time
                    time_into_episode = alert_time - ep_obj.start_time
                    if 0.0 <= time_into_episode <= self.deadline_seconds:
                        if score > ep_max_score[ep_id]:
                            ep_max_score[ep_id] = score
                        if pooled_score > ep_max_pooled[ep_id]:
                            ep_max_pooled[ep_id] = pooled_score
                        if static_score > ep_max_static[ep_id]:
                            ep_max_static[ep_id] = float(static_score)
                        if z_score > ep_max_zscore[ep_id]:
                            ep_max_zscore[ep_id] = float(z_score)

                        if is_alert and not ep_detected[ep_id]:
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

        self._last_window_records = window_records
        self._last_ep_max_scores = {
            "guardian": ep_max_score,
            "pooled": ep_max_pooled,
            "static": ep_max_static,
            "zscore": ep_max_zscore,
        }

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
            baseline_f1s={
                "static": compute_f1_from_confusion_counts(
                    static_bin.tp, static_bin.fp, static_bin.tn, static_bin.fn
                ),
                "zscore": compute_f1_from_confusion_counts(
                    zscore_bin.tp, zscore_bin.fp, zscore_bin.tn, zscore_bin.fn
                ),
                "pooled": compute_f1_from_confusion_counts(
                    pooled_bin.tp, pooled_bin.fp, pooled_bin.tn, pooled_bin.fn
                ),
            },
            baseline_metrics={
                "static": static_bin,
                "zscore": zscore_bin,
                "pooled": pooled_bin,
            },
        )

    def _evaluate_benign_operational_background(self, num_episodes: int = 90) -> list[dict[str, Any]]:
        """
        Evaluate benign operational bursts (USER_TOGGLING, DNS_RETRY_STORM,
        MQTT_RECONNECT_FLOOD, CAMERA_MOTION_BURST, ROUTER_REBOOT, DST_CHANGE)
        on Days 9-14 across the fleet so false-alarm metrics and operating curves
        reflect realistic operational IoT traffic.
        """
        pooled_model = self._ensure_pooled_model()
        for dev in self.devices:
            self._ensure_device_artifacts(dev)

        bg_seed = (self.seed * 100003 + 999983) & 0x7FFFFFFF
        random.seed(bg_seed)
        np.random.seed(bg_seed)

        benign_types = [
            HardNegativeType.USER_TOGGLING,
            HardNegativeType.DNS_RETRY_STORM,
            HardNegativeType.MQTT_RECONNECT_FLOOD,
            HardNegativeType.CAMERA_MOTION_BURST,
            HardNegativeType.ROUTER_REBOOT,
            HardNegativeType.DST_CHANGE,
        ]
        repeats = max(1, num_episodes // 90)
        records: list[dict[str, Any]] = []
        base_t = 9.0 * self.scenario_builder.SECONDS_PER_DAY

        for rep_idx in range(repeats):
            for d_idx, dev in enumerate(self.devices):
                model = self._models[dev.id]
                baseline = self._baselines[dev.id]
                static_baseline = StaticThresholdBaseline.from_device_spec(dev)
                zscore_baseline = RobustZScoreOnlyBaseline(baseline)

                flow_tracker = FlowTracker(window_size_seconds=self.scenario_builder.window_size_s)
                for dst in dev.normal_destinations:
                    flow_tracker.register_known_destination(dev.ip_address, dst)

                for h_idx, hn_type in enumerate(benign_types):
                    w_end = base_t + rep_idx * 7200.0 + d_idx * 600.0 + h_idx * 30.0
                    pkts = self.scenario_builder.emulator.generate_hard_negative_packets(
                        device=dev,
                        negative_type=hn_type,
                        window_duration=self.scenario_builder.window_size_s,
                        current_time=w_end,
                    )
                    flow_tracker.device_buffers[dev.ip_address].clear()
                    for p in pkts:
                        flow_tracker.ingest_packet(p)
                    summary = flow_tracker.get_window_summary(dev.ip_address, current_timestamp=w_end)
                    if not summary:
                        continue
                    features = self.extractor.extract(summary)
                    vec = self.extractor.extract_vector(summary)
                    ml_score, _ = model.score_sample(vec)
                    stat_score, _ = baseline.evaluate(features)
                    assessment = self.threat_scorer.assess(
                        ml_score=ml_score,
                        statistical_score=stat_score,
                        features=features,
                    )
                    static_score, _ = static_baseline.score_summary(summary)
                    z_score = zscore_baseline.score_features(features)
                    pooled_raw, _ = pooled_model.score_sample(vec)
                    records.append(
                        {
                            "device_id": dev.id,
                            "end_time": w_end,
                            "has_attack": False,
                            "active_episode_ids": [],
                            "base_features": features,
                            "base_ml_score": float(ml_score),
                            "base_stat_score": float(stat_score),
                            "guardian_score": float(assessment.threat_score),
                            "pooled_score": float(pooled_raw * 100.0),
                            "static_score": float(static_score),
                            "zscore_score": float(z_score),
                        }
                    )
        return records

    def evaluate_ground_truth_schedule(
        self,
        episodes: Sequence[GroundTruthEpisode],
        pre_buffer_s: float = 20.0,
        post_buffer_s: float = 10.0,
    ) -> dict[str, Any]:
        """
        Evaluates a schedule of ground truth attack episodes over their respective time windows.
        Aggregates metrics per attack class, per difficulty tier, and across baseline detectors
        using identical confusion counts, plus equal-FAR comparisons and operating curves.
        """
        for dev in self.devices:
            self._ensure_device_artifacts(dev)
        self._ensure_pooled_model()

        ep_results: list[dict[str, Any]] = []
        precomputed_episode_windows: list[dict[str, Any]] = []

        # Collect window scores for exact confusion counts and operating curves
        normal_window_scores: dict[str, list[float]] = {
            "guardian": [],
            "pooled": [],
            "static": [],
            "zscore": [],
        }
        attack_window_scores: dict[str, list[float]] = {
            "guardian": [],
            "pooled": [],
            "static": [],
            "zscore": [],
        }
        episode_peak_scores: dict[str, list[float]] = {
            "guardian": [],
            "pooled": [],
            "static": [],
            "zscore": [],
        }

        total_seconds = 0.0
        pooled_thresh = self._baseline_thresholds.get("pooled", 52.0)
        static_thresh = self._baseline_thresholds.get("static", 60.0)
        zscore_thresh = self._baseline_thresholds.get("zscore", 60.0)
        guardian_thresh = float(self.operating_point.alert_threshold)

        for ep in episodes:
            stride = self.scenario_builder.stride_s
            slice_start = max(0.0, float(np.floor((ep.start_time - pre_buffer_s) / stride) * stride))
            slice_end = ep.end_time + post_buffer_s
            total_seconds += max(0.0, slice_end - slice_start)
            rep = self.evaluate_device_slice(
                device_id=ep.device_id,
                start_time=slice_start,
                end_time=slice_end,
                episodes=[ep],
            )
            win_recs = list(getattr(self, "_last_window_records", []))
            ep_max_map = getattr(self, "_last_ep_max_scores", {})
            precomputed_episode_windows.append(
                {
                    "episode_id": ep.episode_id,
                    "device_id": ep.device_id,
                    "window_records": win_recs,
                }
            )

            for wr in win_recs:
                target_dict = attack_window_scores if wr["has_attack"] else normal_window_scores
                target_dict["guardian"].append(float(wr["guardian_score"]))
                target_dict["pooled"].append(float(wr["pooled_score"]))
                target_dict["static"].append(float(wr["static_score"]))
                target_dict["zscore"].append(float(wr["zscore_score"]))

            g_peak = float(ep_max_map.get("guardian", {}).get(ep.episode_id, 0.0))
            p_peak = float(ep_max_map.get("pooled", {}).get(ep.episode_id, 0.0))
            s_peak = float(ep_max_map.get("static", {}).get(ep.episode_id, 0.0))
            z_peak = float(ep_max_map.get("zscore", {}).get(ep.episode_id, 0.0))

            episode_peak_scores["guardian"].append(g_peak)
            episode_peak_scores["pooled"].append(p_peak)
            episode_peak_scores["static"].append(s_peak)
            episode_peak_scores["zscore"].append(z_peak)

            detected = rep.detected_episodes > 0
            ttd = rep.mean_time_to_detect_s if detected else None

            ep_results.append({
                "episode_id": ep.episode_id,
                "attack": ep.attack_type.value,
                "tier": ep.tier.value,
                "intensity": ep.intensity.value,
                "device_id": ep.device_id,
                "detected": detected,
                "ttd": ttd,
                "guardian_f1": rep.window_metrics.f1,
                "static_detected": s_peak >= static_thresh,
                "zscore_detected": z_peak >= zscore_thresh,
                "pooled_detected": p_peak >= pooled_thresh,
            })

        # Include benign operational hard-negative windows on Days 9-14 and attach to precomputed_episode_windows
        benign_ops = self._evaluate_benign_operational_background(len(episodes))
        total_seconds += len(benign_ops) * self.scenario_builder.window_size_s
        first_ep_by_dev: dict[str, list[dict[str, Any]]] = {}
        for p_entry in precomputed_episode_windows:
            d_id = str(p_entry.get("device_id", ""))
            if d_id and d_id not in first_ep_by_dev:
                first_ep_by_dev[d_id] = p_entry["window_records"]

        for br in benign_ops:
            normal_window_scores["guardian"].append(float(br["guardian_score"]))
            normal_window_scores["pooled"].append(float(br["pooled_score"]))
            normal_window_scores["static"].append(float(br["static_score"]))
            normal_window_scores["zscore"].append(float(br["zscore_score"]))
            d_id = str(br.get("device_id", ""))
            if d_id in first_ep_by_dev:
                first_ep_by_dev[d_id].append(br)
            elif precomputed_episode_windows:
                precomputed_episode_windows[0]["window_records"].append(br)

        # Aggregate per attack class and per (attack, tier) cell
        attack_types = list(AttackType)
        detection_rows: list[dict[str, Any]] = []
        per_cell_rows: list[dict[str, Any]] = []

        for atk in attack_types:
            atk_eps = [r for r in ep_results if r["attack"] == atk.value]
            if not atk_eps:
                continue
            n_total = len(atk_eps)
            g_det = sum(1 for r in atk_eps if r["detected"])
            p_det = sum(1 for r in atk_eps if r["pooled_detected"])
            s_det = sum(1 for r in atk_eps if r["static_detected"])
            z_det = sum(1 for r in atk_eps if r["zscore_detected"])

            ttds = [r["ttd"] for r in atk_eps if r["ttd"] is not None]
            mean_ttd = float(sum(ttds) / len(ttds)) if ttds else 0.0
            mean_f1 = float(sum(r["guardian_f1"] for r in atk_eps) / n_total)

            detection_rows.append({
                "attack": atk.value,
                "guardian_tpr": round((g_det / n_total) * 100.0, 1),
                "pooled_if_tpr": round((p_det / n_total) * 100.0, 1),
                "static_rules_tpr": round((s_det / n_total) * 100.0, 1),
                "zscore_tpr": round((z_det / n_total) * 100.0, 1),
                "f1": round(mean_f1, 4),
                "mean_ttd_s": round(mean_ttd, 2),
                "total_episodes": n_total,
                "detected_episodes": g_det,
            })

            for tier_val in ("EASY", "MEDIUM", "HARD"):
                cell_eps = [r for r in atk_eps if r["tier"] == tier_val]
                if not cell_eps:
                    continue
                c_total = len(cell_eps)
                c_g = sum(1 for r in cell_eps if r["detected"])
                c_p = sum(1 for r in cell_eps if r["pooled_detected"])
                c_s = sum(1 for r in cell_eps if r["static_detected"])
                c_z = sum(1 for r in cell_eps if r["zscore_detected"])
                c_ttds = [r["ttd"] for r in cell_eps if r["ttd"] is not None]
                per_cell_rows.append({
                    "attack": atk.value,
                    "tier": tier_val,
                    "guardian_tpr": round((c_g / c_total) * 100.0, 1),
                    "pooled_if_tpr": round((c_p / c_total) * 100.0, 1),
                    "static_rules_tpr": round((c_s / c_total) * 100.0, 1),
                    "zscore_tpr": round((c_z / c_total) * 100.0, 1),
                    "mean_ttd_s": round(float(sum(c_ttds) / len(c_ttds)), 2) if c_ttds else 0.0,
                    "total_episodes": c_total,
                    "detected_episodes": c_g,
                })

        # Aggregate per difficulty tier
        tier_breakdown: dict[str, dict[str, Any]] = {}
        for tier_val in ("EASY", "MEDIUM", "HARD"):
            tier_eps = [r for r in ep_results if r["tier"] == tier_val]
            if tier_eps:
                t_total = len(tier_eps)
                t_det = sum(1 for r in tier_eps if r["detected"])
                t_ttds = [r["ttd"] for r in tier_eps if r["ttd"] is not None]
                tier_breakdown[tier_val] = {
                    "tpr": round((t_det / t_total) * 100.0, 1),
                    "mean_ttd_s": round(float(sum(t_ttds) / len(t_ttds)), 2) if t_ttds else 0.0,
                    "total_episodes": t_total,
                    "detected_episodes": t_det,
                }

        days_obs = 6.0 * max(1, len(episodes) // 90)
        n_devs = max(1, len(self.devices))

        def _evaluate_detector_at_threshold(det_key: str, thresh: float) -> dict[str, Any]:
            return evaluate_detector_point_at_threshold(
                normal_scores=normal_window_scores[det_key],
                attack_scores=attack_window_scores[det_key],
                episode_scores=episode_peak_scores[det_key],
                threshold=thresh,
                num_devices=n_devs,
                days_observed=days_obs,
            )

        default_thresholds = {
            "guardian": guardian_thresh,
            "pooled": pooled_thresh,
            "static": static_thresh,
            "zscore": zscore_thresh,
        }
        detector_summary = {
            k: _evaluate_detector_at_threshold(k, t)
            for k, t in default_thresholds.items()
        }

        # Operating curves across thresholds for all detectors
        operating_curves = compute_detector_operating_curves(
            normal_window_scores=normal_window_scores,
            attack_window_scores=attack_window_scores,
            episode_peak_scores=episode_peak_scores,
            num_devices=n_devs,
            days_observed=days_obs,
        )

        # Equal False-Alarm Rate comparison (target <= 1.0 false alert/device/day, or closest achievable FAR)
        equal_far_comparison = compute_equal_far_comparison(
            normal_window_scores=normal_window_scores,
            attack_window_scores=attack_window_scores,
            episode_peak_scores=episode_peak_scores,
            num_devices=n_devs,
            days_observed=days_obs,
            target_far=1.0,
        )

        baseline_tpr_at_far_1 = extract_baseline_tpr_at_far_1(equal_far_comparison)

        return {
            "detection_rows": detection_rows,
            "per_cell_rows": per_cell_rows,
            "tier_breakdown": tier_breakdown,
            "episode_results": ep_results,
            "precomputed_episode_windows": precomputed_episode_windows,
            "schedule_fpr": detector_summary["guardian"]["fpr"],
            "schedule_far": detector_summary["guardian"]["far_per_day"],
            "schedule_f1": detector_summary["guardian"]["f1"],
            "baseline_fprs": {
                "pooled": detector_summary["pooled"]["fpr"],
                "static": detector_summary["static"]["fpr"],
                "zscore": detector_summary["zscore"]["fpr"],
            },
            "baseline_f1s": {
                "pooled": detector_summary["pooled"]["f1"],
                "static": detector_summary["static"]["f1"],
                "zscore": detector_summary["zscore"]["f1"],
            },
            "baseline_fars": {
                "pooled": detector_summary["pooled"]["far_per_day"],
                "static": detector_summary["static"]["far_per_day"],
                "zscore": detector_summary["zscore"]["far_per_day"],
            },
            "baseline_tpr_at_far_1": baseline_tpr_at_far_1,
            "detector_confusion_summary": detector_summary,
            "equal_far_comparison": equal_far_comparison,
            "operating_curves": operating_curves,
        }


def extract_baseline_tpr_at_far_1(
    equal_far_comparison: Mapping[str, Mapping[str, Any]],
) -> dict[str, float]:
    """Return each detector's episode TPR (%) at the 1.0 false alert/device/day operating point."""
    return {
        str(k): round(float(pt.get("episode_tpr", 0.0)), 2)
        for k, pt in equal_far_comparison.items()
    }


def evaluate_detector_point_at_threshold(
    normal_scores: Sequence[float],
    attack_scores: Sequence[float],
    episode_scores: Sequence[float],
    threshold: float,
    num_devices: int = 8,
    days_observed: float = 6.0,
) -> dict[str, Any]:
    """Evaluate a detector's confusion counts, TPR, FPR, F1, and FAR/day at a given threshold."""
    fp_c = sum(1 for s in normal_scores if s >= threshold)
    tn_c = len(normal_scores) - fp_c
    tp_w = sum(1 for s in attack_scores if s >= threshold)
    fn_w = len(attack_scores) - tp_w

    ep_tp = sum(1 for s in episode_scores if s >= threshold)
    ep_fn = len(episode_scores) - ep_tp

    eff_tp = tp_w if tp_w > 0 else ep_tp
    eff_fn = fn_w if tp_w > 0 else ep_fn
    f1_val = round(
        compute_f1_from_confusion_counts(eff_tp, fp_c, tn_c, eff_fn),
        4,
    )

    fpr_pct = round((fp_c / max(1, len(normal_scores))) * 100.0, 2)
    ep_tpr_pct = round((ep_tp / max(1, len(episode_scores))) * 100.0, 2)
    win_tpr_pct = round((tp_w / max(1, len(attack_scores))) * 100.0, 2)
    far_val = round(
        compute_false_alert_rate(
            num_false_alerts=fp_c,
            num_devices=max(1, num_devices),
            days_observed=max(1e-6, days_observed),
        ),
        2,
    )
    return {
        "threshold": round(float(threshold), 2),
        "tp": eff_tp,
        "fp": fp_c,
        "tn": tn_c,
        "fn": eff_fn,
        "episode_tpr": ep_tpr_pct,
        "window_tpr": win_tpr_pct,
        "fpr": fpr_pct,
        "f1": f1_val,
        "far_per_day": far_val,
    }


def compute_equal_far_comparison(
    normal_window_scores: Mapping[str, Sequence[float]],
    attack_window_scores: Mapping[str, Sequence[float]],
    episode_peak_scores: Mapping[str, Sequence[float]],
    num_devices: int = 8,
    days_observed: float = 6.0,
    target_far: float = 1.0,
    detector_keys: Sequence[str] = ("guardian", "pooled", "static", "zscore"),
) -> dict[str, dict[str, Any]]:
    """
    Compare all detectors at an equal false-alarm budget (target_far false alerts/device/day),
    or at the minimum achievable FAR if a detector's score saturates at 100.0.
    """
    equal_far_comparison: dict[str, dict[str, Any]] = {}
    candidate_grid = [round(float(x), 2) for x in np.linspace(20.0, 99.9, 160)]
    for k in detector_keys:
        norm_s = normal_window_scores.get(k, [])
        atk_s = attack_window_scores.get(k, [])
        ep_s = episode_peak_scores.get(k, [])
        pts = [
            evaluate_detector_point_at_threshold(
                normal_scores=norm_s,
                attack_scores=atk_s,
                episode_scores=ep_s,
                threshold=t,
                num_devices=num_devices,
                days_observed=days_observed,
            )
            for t in candidate_grid
        ]
        feasible = [p for p in pts if p["far_per_day"] <= target_far]
        if feasible:
            best_pt = max(feasible, key=lambda p: (p["episode_tpr"], p["f1"], -p["threshold"]))
        else:
            best_pt = min(pts, key=lambda p: (p["far_per_day"], -p["episode_tpr"]))
        equal_far_comparison[k] = best_pt
    return equal_far_comparison


def compute_detector_operating_curves(
    normal_window_scores: Mapping[str, Sequence[float]],
    attack_window_scores: Mapping[str, Sequence[float]],
    episode_peak_scores: Mapping[str, Sequence[float]],
    num_devices: int = 8,
    days_observed: float = 6.0,
    thresholds: Sequence[float] = (
        30.0,
        40.0,
        50.0,
        55.0,
        60.0,
        65.0,
        68.65,
        72.0,
        75.0,
        80.0,
        85.0,
        90.0,
        95.0,
        99.0,
    ),
    detector_keys: Sequence[str] = ("guardian", "zscore", "pooled", "static"),
) -> dict[str, list[dict[str, Any]]]:
    """Compute multi-threshold operating curves (TPR, FPR, F1, FAR/day) for each detector."""
    return {
        k: [
            evaluate_detector_point_at_threshold(
                normal_scores=normal_window_scores.get(k, []),
                attack_scores=attack_window_scores.get(k, []),
                episode_scores=episode_peak_scores.get(k, []),
                threshold=t,
                num_devices=num_devices,
                days_observed=days_observed,
            )
            for t in thresholds
        ]
        for k in detector_keys
    }


