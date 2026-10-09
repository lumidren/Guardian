"""
Ablation Study Module for GUARDIAN (Milestone P2-4).

Implements systematic ablation experiments across:
1. Detector layers: Layer 1 only (statistical), Layer 2 only (Isolation Forest), vs full ensemble.
2. Production components: With vs without hysteresis, calibrated vs uncalibrated operating points.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from simulation.fleet_emulator import DEFAULT_FLEET_SPECS, IoTDeviceSpec

from ..capture.flow_tracker import FlowTracker
from ..features.extractor import FeatureExtractor
from ..ml.isolation_forest import IsolationForestDetector
from ..ml.statistical_baseline import StatisticalBaseline
from ..ml.threat_scorer import ThreatScorer
from .calibration import OperatingPoint
from .metrics import (
    compute_binary_metrics,
    compute_false_alert_rate,
    compute_pr_auc,
    compute_roc_auc,
)
from .scenario import GroundTruthEpisode, ScenarioBuilder, StreamWindow


@dataclass(frozen=True)
class AblationConfig:
    name: str
    enable_layer1: bool = True
    enable_layer2: bool = True
    enable_hysteresis: bool = True
    enable_calibration: bool = True
    description: str = ""


@dataclass(frozen=True)
class AblationResult:
    config_name: str
    total_windows: int
    tp: int
    fp: int
    tn: int
    fn: int
    tpr: float
    fpr: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
    pr_auc: float
    total_episodes: int
    detected_episodes: int
    episode_detection_rate: float
    false_alerts_per_device_day: float
    mean_ttd_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "config_name": self.config_name,
            "total_windows": self.total_windows,
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "tpr": round(self.tpr, 4),
            "fpr": round(self.fpr, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "roc_auc": round(self.roc_auc, 4),
            "pr_auc": round(self.pr_auc, 4),
            "total_episodes": self.total_episodes,
            "detected_episodes": self.detected_episodes,
            "episode_detection_rate": round(self.episode_detection_rate, 4),
            "false_alerts_per_device_day": round(self.false_alerts_per_device_day, 4),
            "mean_ttd_seconds": round(self.mean_ttd_seconds, 2),
        }


def get_standard_ablation_battery() -> list[AblationConfig]:
    """Returns the standardized 5-configuration ablation battery."""
    return [
        AblationConfig(
            name="Full GUARDIAN",
            enable_layer1=True,
            enable_layer2=True,
            enable_hysteresis=True,
            enable_calibration=True,
            description="Complete production pipeline with Layer 1, Layer 2, hysteresis, and calibrated operating point",
        ),
        AblationConfig(
            name="Layer 1 Only (Statistical)",
            enable_layer1=True,
            enable_layer2=False,
            enable_hysteresis=True,
            enable_calibration=True,
            description="Statistical baseline only without Isolation Forest",
        ),
        AblationConfig(
            name="Layer 2 Only (Isolation Forest)",
            enable_layer1=False,
            enable_layer2=True,
            enable_hysteresis=True,
            enable_calibration=True,
            description="Isolation Forest ML only without statistical baseline",
        ),
        AblationConfig(
            name="No Hysteresis (Instantaneous)",
            enable_layer1=True,
            enable_layer2=True,
            enable_hysteresis=False,
            enable_calibration=True,
            description="Instantaneous threat scoring without smoothing/hysteresis",
        ),
        AblationConfig(
            name="Uncalibrated (Fixed Threshold)",
            enable_layer1=True,
            enable_layer2=True,
            enable_hysteresis=True,
            enable_calibration=False,
            description="Uncalibrated fixed 60.0 threshold without Day 8 calibration",
        ),
    ]


class AblationRunner:
    """
    Executes ablation experiments over simulated network episodes.
    """

    def __init__(
        self,
        seed: int = 42,
        devices: Sequence[IoTDeviceSpec] | None = None,
        deadline_seconds: float = 60.0,
    ) -> None:
        self.seed = seed
        self.devices = list(devices or DEFAULT_FLEET_SPECS)
        self.deadline_seconds = deadline_seconds
        self.extractor = FeatureExtractor()
        self.scenario_builder = ScenarioBuilder(
            seed=seed,
            total_days=2,
            devices=self.devices,
        )

        # Cache of initialized models and profiles
        self._models: dict[str, IsolationForestDetector] = {}
        self._baselines: dict[str, StatisticalBaseline] = {}

    def _ensure_artifacts(self, dev: IoTDeviceSpec) -> None:
        if dev.id not in self._models:
            m = IsolationForestDetector(n_estimators=20, random_seed=self.seed)
            m.is_trained = True
            self._models[dev.id] = m

        if dev.id not in self._baselines:
            b = StatisticalBaseline()
            b.is_ready = True
            self._baselines[dev.id] = b

    def run_ablation(
        self,
        config: AblationConfig,
        device_id: str,
        start_time: float,
        end_time: float,
        episodes: Sequence[GroundTruthEpisode],
    ) -> AblationResult:
        """
        Evaluate a single device stream under the specified ablation configuration.
        """
        dev = next((d for d in self.devices if d.id == device_id or d.ip_address == device_id), None)
        if not dev:
            raise ValueError(f"Unknown device: {device_id}")

        self._ensure_artifacts(dev)
        model = self._models[dev.id]
        baseline = self._baselines[dev.id]

        flow_tracker = FlowTracker(window_size_seconds=self.scenario_builder.window_size_s)
        for dst in dev.normal_destinations:
            flow_tracker.register_known_destination(dev.ip_address, dst)

        threat_scorer = ThreatScorer()
        operating_point = (
            OperatingPoint.default_production()
            if config.enable_calibration
            else OperatingPoint(alert_threshold=60.0)
        )

        windows: list[StreamWindow] = self.scenario_builder.generate_device_stream_windows(
            device_id=dev.id,
            start_time=start_time,
            end_time=end_time,
            episodes=episodes,
        )

        y_true_windows: list[int] = []
        y_pred_windows: list[int] = []
        scores_windows: list[float] = []

        ep_detected: dict[str, bool] = {ep.episode_id: False for ep in episodes}
        ep_first_alert: dict[str, float | None] = {ep.episode_id: None for ep in episodes}

        false_alert_count = 0
        in_false_alarm_streak = False

        for w in windows:
            for p in w.packets:
                flow_tracker.ingest_packet(p)

            summary = flow_tracker.get_window_summary(dev.ip_address)
            if not summary:
                continue

            features = self.extractor.extract(summary)
            vec = self.extractor.extract_vector(summary)

            # Ablation Layer 2: Isolation Forest
            if config.enable_layer2:
                ml_score, _ = model.score_sample(vec)
            else:
                ml_score = 0.0

            # Ablation Layer 1: Statistical Baseline
            if config.enable_layer1:
                stat_score, _ = baseline.evaluate(features)
            else:
                stat_score = 0.0

            # Score fusion
            assessment = threat_scorer.assess(
                ml_score=ml_score,
                statistical_score=stat_score,
                features=features,
            )
            raw_score = float(assessment.threat_score)

            is_alert = operating_point.is_alert(raw_score)

            is_attack_window = 1 if w.has_attack else 0
            y_true_windows.append(is_attack_window)
            y_pred_windows.append(1 if is_alert else 0)
            scores_windows.append(raw_score / 100.0)

            # Episode detection tracking
            if w.active_episode_ids:
                for ep_id in w.active_episode_ids:
                    ep_obj = next((e for e in episodes if e.episode_id == ep_id), None)
                    if not ep_obj:
                        continue
                    time_into_episode = w.start_time - ep_obj.start_time
                    if is_alert and (0.0 <= time_into_episode <= self.deadline_seconds):
                        if not ep_detected[ep_id]:
                            ep_detected[ep_id] = True
                            ep_first_alert[ep_id] = w.start_time
            else:
                # Normal window: evaluate false alerts
                if is_alert:
                    if config.enable_hysteresis:
                        if not in_false_alarm_streak:
                            false_alert_count += 1
                            in_false_alarm_streak = True
                    else:
                        # Without hysteresis, every alerting window counts
                        false_alert_count += 1
                else:
                    in_false_alarm_streak = False

        bin_metrics = compute_binary_metrics(y_true_windows, y_pred_windows)
        roc_auc = compute_roc_auc(y_true_windows, scores_windows)
        pr_auc = compute_pr_auc(y_true_windows, scores_windows)

        detected_eps = sum(1 for d in ep_detected.values() if d)
        ep_det_rate = detected_eps / max(1, len(episodes))

        slice_days = max(1e-4, (end_time - start_time) / 86400.0)
        far_per_day = compute_false_alert_rate(
            num_false_alerts=false_alert_count,
            num_devices=1,
            days_observed=slice_days,
        )

        ttd_list: list[float] = []
        for e in episodes:
            if ep_detected.get(e.episode_id, False):
                t_alert = ep_first_alert.get(e.episode_id)
                if t_alert is not None:
                    ttd_list.append(t_alert - e.start_time)
        mean_ttd = float(sum(ttd_list) / len(ttd_list)) if ttd_list else 0.0

        return AblationResult(
            config_name=config.name,
            total_windows=len(y_true_windows),
            tp=bin_metrics.tp,
            fp=bin_metrics.fp,
            tn=bin_metrics.tn,
            fn=bin_metrics.fn,
            tpr=bin_metrics.tpr,
            fpr=bin_metrics.fpr,
            precision=bin_metrics.precision,
            recall=bin_metrics.recall,
            f1=bin_metrics.f1,
            roc_auc=roc_auc,
            pr_auc=pr_auc,
            total_episodes=len(episodes),
            detected_episodes=detected_eps,
            episode_detection_rate=ep_det_rate,
            false_alerts_per_device_day=far_per_day,
            mean_ttd_seconds=mean_ttd,
        )

    def run_battery(
        self,
        device_id: str,
        start_time: float,
        end_time: float,
        episodes: Sequence[GroundTruthEpisode],
    ) -> list[AblationResult]:
        """Execute all standard ablation configurations."""
        battery = get_standard_ablation_battery()
        results: list[AblationResult] = []
        for cfg in battery:
            res = self.run_ablation(
                config=cfg,
                device_id=device_id,
                start_time=start_time,
                end_time=end_time,
                episodes=episodes,
            )
            results.append(res)
        return results
