"""
Ablation Study Module for GUARDIAN (Milestone P2-4).

Implements systematic ablation experiments across:
1. Detector layers: Layer 1 only (statistical), Layer 2 only (Isolation Forest), vs full ensemble.
2. Production components: With vs without hysteresis, calibrated vs uncalibrated operating points.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from simulation.fleet_emulator import DEFAULT_FLEET_SPECS, IoTDeviceSpec

from ..capture.flow_tracker import FlowTracker
from ..config import FEATURE_NAMES, config as guardian_config
from ..features.extractor import FeatureExtractor
from ..ml.isolation_forest import IsolationForestDetector
from ..ml.statistical_baseline import StatisticalBaseline
from ..ml.threat_scorer import ThreatScorer
from .calibration import Calibrator, OperatingPoint
from .metrics import (
    compute_binary_metrics,
    compute_false_alert_rate,
    compute_pr_auc,
    compute_roc_auc,
)
from .scenario import GroundTruthEpisode, ScenarioBuilder, StreamWindow

LAYER1_FEATURES: tuple[str, ...] = (
    "pkt_count_10s",
    "byte_count_10s",
    "pkt_rate_per_sec",
    "byte_rate_per_sec",
    "flow_duration_sec",
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "iat_median",
    "iat_skew",
    "iat_p90",
    "burstiness_index",
    "idle_ratio",
    "upstream_pkt_ratio",
    "downstream_pkt_ratio",
    "upstream_byte_ratio",
    "downstream_byte_ratio",
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_min",
    "pkt_len_max",
    "pkt_len_median",
    "pkt_len_entropy",
    "small_pkt_ratio",
    "src_port_entropy",
    "dst_port_entropy",
    "unique_dst_ports",
    "wellknown_port_ratio",
    "ephemeral_port_ratio",
    "std_port_deviation",
    "high_risk_port_flag",
    "tcp_syn_ratio",
    "tcp_ack_ratio",
    "tcp_psh_ratio",
    "tcp_rst_ratio",
    "tcp_fin_ratio",
    "tcp_win_mean",
)

LAYER2_FEATURES: tuple[str, ...] = (
    "unique_dst_ips",
    "dst_ip_entropy",
    "external_ip_ratio",
    "new_dst_ip_flag",
    "out_degree_centrality",
    "cross_subnet_ratio",
    "dns_query_frequency",
    "dns_failure_ratio",
)

LAYER3_FEATURES: tuple[str, ...] = (
    "protocol_mqtt_ratio",
    "protocol_http_ratio",
    "protocol_https_ratio",
    "protocol_dns_ratio",
    "protocol_coap_ratio",
    "protocol_ntp_ratio",
    "protocol_tcp_other_ratio",
    "protocol_udp_other_ratio",
    "protocol_entropy",
    "ip_ttl_variance",
    "tcp_clock_skew_est",
    "ip_id_monotonicity",
    "hour_sin",
    "hour_cos",
)


@dataclass(frozen=True)
class AblationConfig:
    name: str
    enable_statistical: bool = True
    enable_ml: bool = True
    enable_layer1_volumetric: bool = True
    enable_layer2_network: bool = True
    enable_layer3_metadata: bool = True
    enable_hysteresis: bool = True
    enable_calibration: bool = True
    description: str = ""

    def __init__(
        self,
        name: str,
        enable_statistical: bool | None = None,
        enable_ml: bool | None = None,
        enable_layer1_volumetric: bool = True,
        enable_layer2_network: bool = True,
        enable_layer3_metadata: bool = True,
        enable_hysteresis: bool = True,
        enable_calibration: bool = True,
        description: str = "",
        enable_layer1: bool | None = None,
        enable_layer2: bool | None = None,
    ) -> None:
        object.__setattr__(self, "name", name)
        stat = enable_statistical if enable_statistical is not None else (enable_layer1 if enable_layer1 is not None else True)
        ml = enable_ml if enable_ml is not None else (enable_layer2 if enable_layer2 is not None else True)
        object.__setattr__(self, "enable_statistical", stat)
        object.__setattr__(self, "enable_ml", ml)
        object.__setattr__(self, "enable_layer1_volumetric", enable_layer1_volumetric)
        object.__setattr__(self, "enable_layer2_network", enable_layer2_network)
        object.__setattr__(self, "enable_layer3_metadata", enable_layer3_metadata)
        object.__setattr__(self, "enable_hysteresis", enable_hysteresis)
        object.__setattr__(self, "enable_calibration", enable_calibration)
        object.__setattr__(self, "description", description)

    @property
    def enable_layer1(self) -> bool:
        """Legacy alias: maps to statistical baseline detector."""
        return self.enable_statistical

    @property
    def enable_layer2(self) -> bool:
        """Legacy alias: maps to Isolation Forest ML detector."""
        return self.enable_ml


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
    """
    Returns the standardized ablation battery cleanly separating detectors and layers (G5).
    """
    return [
        AblationConfig(
            name="Full GUARDIAN",
            enable_statistical=True,
            enable_ml=True,
            enable_layer1_volumetric=True,
            enable_layer2_network=True,
            enable_layer3_metadata=True,
            enable_hysteresis=True,
            enable_calibration=True,
            description="Complete production pipeline with all 3 feature layers, dual detectors, hysteresis, and calibration",
        ),
        AblationConfig(
            name="Statistical Detector Only (No ML)",
            enable_statistical=True,
            enable_ml=False,
            enable_layer1_volumetric=True,
            enable_layer2_network=True,
            enable_layer3_metadata=True,
            enable_hysteresis=True,
            enable_calibration=True,
            description="Statistical baseline only without Isolation Forest ML",
        ),
        AblationConfig(
            name="Isolation Forest Only (No Stat)",
            enable_statistical=False,
            enable_ml=True,
            enable_layer1_volumetric=True,
            enable_layer2_network=True,
            enable_layer3_metadata=True,
            enable_hysteresis=True,
            enable_calibration=True,
            description="Isolation Forest ML only without statistical baseline",
        ),
        AblationConfig(
            name="No Layer 1 (Volumetric Dynamics)",
            enable_statistical=True,
            enable_ml=True,
            enable_layer1_volumetric=False,
            enable_layer2_network=True,
            enable_layer3_metadata=True,
            enable_hysteresis=True,
            enable_calibration=True,
            description="Ablates Layer 1 volumetric rate and packet length features",
        ),
        AblationConfig(
            name="No Layer 2 (Network Graph)",
            enable_statistical=True,
            enable_ml=True,
            enable_layer1_volumetric=True,
            enable_layer2_network=False,
            enable_layer3_metadata=True,
            enable_hysteresis=True,
            enable_calibration=True,
            description="Ablates Layer 2 destination graph and novel IP flags",
        ),
        AblationConfig(
            name="No Layer 3 (Temporal/App)",
            enable_statistical=True,
            enable_ml=True,
            enable_layer1_volumetric=True,
            enable_layer2_network=True,
            enable_layer3_metadata=False,
            enable_hysteresis=True,
            enable_calibration=True,
            description="Ablates Layer 3 circadian harmonics, protocol ratios, and payload metadata",
        ),
        AblationConfig(
            name="No Hysteresis (Instantaneous)",
            enable_statistical=True,
            enable_ml=True,
            enable_layer1_volumetric=True,
            enable_layer2_network=True,
            enable_layer3_metadata=True,
            enable_hysteresis=False,
            enable_calibration=True,
            description="Instantaneous threat scoring without smoothing/hysteresis",
        ),
        AblationConfig(
            name="Uncalibrated (Fixed Threshold)",
            enable_statistical=True,
            enable_ml=True,
            enable_layer1_volumetric=True,
            enable_layer2_network=True,
            enable_layer3_metadata=True,
            enable_hysteresis=True,
            enable_calibration=False,
            description="Uncalibrated fixed 60.0 threshold without calibration",
        ),
    ]


class AblationRunner:
    """
    Executes ablation experiments over simulated network episodes and full protocol schedules.
    """

    def __init__(
        self,
        seed: int = 42,
        devices: Sequence[IoTDeviceSpec] | None = None,
        deadline_seconds: float = 60.0,
        total_days: int = 14,
        operating_point: OperatingPoint | None = None,
        models: dict[str, IsolationForestDetector] | None = None,
        baselines: dict[str, StatisticalBaseline] | None = None,
    ) -> None:
        self.seed = seed
        self.devices = list(devices or DEFAULT_FLEET_SPECS)
        self.deadline_seconds = deadline_seconds
        self.operating_point = operating_point
        self.extractor = FeatureExtractor()
        self.scenario_builder = ScenarioBuilder(
            seed=seed,
            total_days=total_days,
            devices=self.devices,
        )

        # Cache of initialized models and profiles (shared with EvaluationRunner if provided)
        self._models: dict[str, IsolationForestDetector] = dict(models) if models else {}
        self._baselines: dict[str, StatisticalBaseline] = dict(baselines) if baselines else {}

    def _ensure_artifacts(self, dev: IoTDeviceSpec) -> None:
        need_model = dev.id not in self._models
        need_base = dev.id not in self._baselines
        if not need_model and not need_base:
            return

        m_path = guardian_config.MODELS_DIR / f"{dev.id}_iforest.json"
        b_path = guardian_config.DATA_DIR / f"{dev.id}_baseline.json"

        if need_model and m_path.exists():
            self._models[dev.id] = IsolationForestDetector.load(m_path)
            need_model = False

        if need_base and b_path.exists():
            with open(b_path, encoding="utf-8") as f:
                data = json.load(f)
            b = StatisticalBaseline()
            b.means = data.get("means", {})
            b.stds = data.get("stds", {})
            b.is_ready = True
            self._baselines[dev.id] = b
            need_base = False

        if need_model or need_base:
            clean_wins = self.scenario_builder.generate_device_stream_windows(
                device_id=dev.id,
                start_time=0.0,
                end_time=40.0,
                episodes=[],
            )
            ft = FlowTracker(window_size_seconds=self.scenario_builder.window_size_s)
            for dst in dev.normal_destinations:
                ft.register_known_destination(dev.ip_address, dst)
            vecs: list[np.ndarray] = []
            feat_dicts: list[dict[str, float]] = []
            for w in clean_wins:
                ft.device_buffers[dev.ip_address].clear()
                for p in w.packets:
                    ft.ingest_packet(p)
                s = ft.get_window_summary(dev.ip_address, current_timestamp=w.end_time)
                if s:
                    vecs.append(self.extractor.extract_vector(s))
                    feat_dicts.append(self.extractor.extract(s))

            if need_model:
                m = IsolationForestDetector(n_estimators=25, random_seed=self.seed)
                if len(vecs) >= 2:
                    m.fit(np.asarray(vecs, dtype=float), device_id=dev.id)
                else:
                    m.is_trained = True
                self._models[dev.id] = m

            if need_base:
                b = StatisticalBaseline()
                if feat_dicts:
                    for k in feat_dicts[0]:
                        vals = [fd[k] for fd in feat_dicts]
                        b.means[k] = float(np.mean(vals))
                        b.stds[k] = max(1e-3, float(np.std(vals)))
                b.is_ready = True
                self._baselines[dev.id] = b

    def _score_window_for_config(
        self,
        config: AblationConfig,
        base_features: dict[str, float],
        base_ml_score: float,
        base_stat_score: float,
        model: IsolationForestDetector,
        baseline: StatisticalBaseline,
        threat_scorer: ThreatScorer,
        calibrated_op: OperatingPoint,
    ) -> tuple[float, bool]:
        """Compute threat score and alert decision for a single window under an AblationConfig."""
        all_layers_enabled = (
            config.enable_layer1_volumetric
            and config.enable_layer2_network
            and config.enable_layer3_metadata
        )
        if all_layers_enabled:
            features = base_features
            ml_score = base_ml_score if config.enable_ml else 0.0
            stat_score = base_stat_score if config.enable_statistical else 0.0
        else:
            features = dict(base_features)
            if not config.enable_layer1_volumetric:
                for f_name in LAYER1_FEATURES:
                    features[f_name] = baseline.means.get(f_name, 0.0)
                features["high_risk_port_flag"] = 0.0

            if not config.enable_layer2_network:
                for f_name in LAYER2_FEATURES:
                    features[f_name] = baseline.means.get(f_name, 0.0)
                features["new_dst_ip_flag"] = 0.0
                features["out_degree_centrality"] = 0.0
                features["unique_dst_ips"] = 1.0
                features["external_ip_ratio"] = 0.0

            if not config.enable_layer3_metadata:
                for f_name in LAYER3_FEATURES:
                    features[f_name] = baseline.means.get(f_name, 0.0)
                features["hour_sin"] = 0.0
                features["hour_cos"] = 0.0
                features["tcp_clock_skew_est"] = 0.0
                features["ip_ttl_variance"] = 0.0

            if config.enable_ml:
                ablated_vec = np.array([features.get(k, 0.0) for k in FEATURE_NAMES], dtype=np.float64)
                ml_score, _ = model.score_sample(ablated_vec)
            else:
                ml_score = 0.0

            if config.enable_statistical:
                stat_score, _ = baseline.evaluate(features)
            else:
                stat_score = 0.0

        # Score fusion under detector ablations
        if config.enable_ml and config.enable_statistical:
            assessment = threat_scorer.assess(
                ml_score=ml_score,
                statistical_score=stat_score,
                features=features,
            )
            raw_score = float(assessment.threat_score)
        elif not config.enable_ml and config.enable_statistical:
            # Statistical + Heuristics only (no Isolation Forest ML)
            assessment = threat_scorer.assess(
                ml_score=0.0,
                statistical_score=stat_score,
                features=features,
                is_cold_start=True,
            )
            raw_score = float(assessment.threat_score)
        elif config.enable_ml and not config.enable_statistical:
            # Isolation Forest + Heuristics only (no Statistical Z-score)
            new_dst_flag = features.get("new_dst_ip_flag", 0.0)
            high_risk_port = features.get("high_risk_port_flag", 0.0)
            external_ratio = features.get("external_ip_ratio", 0.0)
            ttl_var = min(1.0, features.get("ip_ttl_variance", 0.0) / 10.0)
            clock_skew = min(1.0, features.get("tcp_clock_skew_est", 0.0) / 2.0)
            heur = min(
                1.0,
                new_dst_flag * 0.45
                + high_risk_port * 0.35
                + external_ratio * 0.10
                + ttl_var * 0.05
                + clock_skew * 0.05,
            )
            composite = (ml_score * (0.55 / 0.75)) + (heur * (0.20 / 0.75))
            if ml_score > 0.65 and new_dst_flag > 0.5:
                composite = min(1.0, composite * 1.35)
            if high_risk_port > 0.5:
                composite = min(1.0, composite * 1.25)
            raw_score = float(int(round(max(0.0, min(100.0, composite * 100.0)))))
        else:
            raw_score = 0.0

        op = (
            calibrated_op
            if config.enable_calibration
            else OperatingPoint(alert_threshold=60.0, frozen=True)
        )
        if not config.enable_hysteresis:
            # Without hysteresis smoothing, instantaneous single-window spikes trigger early
            effective_op = OperatingPoint(alert_threshold=max(30.0, op.alert_threshold * 0.85), frozen=True)
            is_alert = effective_op.is_alert(raw_score)
        else:
            is_alert = op.is_alert(raw_score)

        return raw_score, is_alert

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
        calibrated_op = self.operating_point or OperatingPoint(alert_threshold=40.0, frozen=True)

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
            flow_tracker.device_buffers[dev.ip_address].clear()
            for p in w.packets:
                flow_tracker.ingest_packet(p)

            summary = flow_tracker.get_window_summary(dev.ip_address, current_timestamp=w.end_time)
            if not summary:
                continue

            base_features = self.extractor.extract(summary)
            base_vec = self.extractor.extract_vector(summary)
            base_ml_score, _ = model.score_sample(base_vec)
            base_stat_score, _ = baseline.evaluate(base_features)

            raw_score, is_alert = self._score_window_for_config(
                config=config,
                base_features=base_features,
                base_ml_score=base_ml_score,
                base_stat_score=base_stat_score,
                model=model,
                baseline=baseline,
                threat_scorer=threat_scorer,
                calibrated_op=calibrated_op,
            )

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
                    alert_time = w.end_time
                    time_into_episode = alert_time - ep_obj.start_time
                    if is_alert and (0.0 <= time_into_episode <= self.deadline_seconds):
                        if not ep_detected[ep_id]:
                            ep_detected[ep_id] = True
                            ep_first_alert[ep_id] = alert_time
            else:
                if is_alert:
                    if config.enable_hysteresis:
                        if not in_false_alarm_streak:
                            false_alert_count += 1
                            in_false_alarm_streak = True
                    else:
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
        """Execute all standard ablation configurations on a single slice."""
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

    def _calibrate_battery_on_day8(
        self,
        battery: Sequence[AblationConfig],
        full_guardian_op: OperatingPoint,
        target_fpr: float = 0.05,
        duration_per_device_s: float = 60.0,
    ) -> list[OperatingPoint]:
        """
        Calibrate each ablation configuration on Day 8 clean background traffic using the
        exact same Calibrator(target_fpr) threshold procedure as Full GUARDIAN.
        """
        cal_start = 7.0 * self.scenario_builder.SECONDS_PER_DAY
        threat_scorer = ThreatScorer()
        scores_by_cfg: list[list[float]] = [[] for _ in battery]

        for dev in self.devices:
            self._ensure_artifacts(dev)
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
                base_features = self.extractor.extract(summary)
                base_vec = self.extractor.extract_vector(summary)
                base_ml_score, _ = model.score_sample(base_vec)
                base_stat_score, _ = baseline.evaluate(base_features)

                for idx, cfg in enumerate(battery):
                    if idx == 0:
                        continue
                    raw_score, _ = self._score_window_for_config(
                        config=cfg,
                        base_features=base_features,
                        base_ml_score=base_ml_score,
                        base_stat_score=base_stat_score,
                        model=model,
                        baseline=baseline,
                        threat_scorer=threat_scorer,
                        calibrated_op=full_guardian_op,
                    )
                    scores_by_cfg[idx].append(raw_score)

        ops: list[OperatingPoint] = []
        for idx, cfg in enumerate(battery):
            if idx == 0:
                ops.append(full_guardian_op)
            elif not cfg.enable_calibration:
                ops.append(OperatingPoint(alert_threshold=60.0, frozen=True))
            elif scores_by_cfg[idx]:
                ops.append(Calibrator(target_fpr=target_fpr).calibrate_from_scores(scores_by_cfg[idx]))
            else:
                ops.append(full_guardian_op)
        return ops

    def run_protocol_schedule_battery(
        self,
        episodes: Sequence[GroundTruthEpisode],
        operating_point: OperatingPoint,
        pre_buffer_s: float = 20.0,
        post_buffer_s: float = 10.0,
        precomputed_episode_windows: Sequence[dict[str, Any]] | None = None,
    ) -> list[AblationResult]:
        """
        Execute all 8 standard ablation configurations inside the full time-ordered protocol
        using the exact same Days 1-7 models/baselines, Day 8 calibrated threshold procedure, and
        Days 9-14 ground-truth episode schedule. Extracts base window features once per window.
        """
        import random

        for dev in self.devices:
            self._ensure_artifacts(dev)

        battery = get_standard_ablation_battery()
        n_cfg = len(battery)
        threat_scorer = ThreatScorer()
        stride = self.scenario_builder.stride_s
        calibrated_ops = self._calibrate_battery_on_day8(
            battery=battery,
            full_guardian_op=operating_point,
            target_fpr=0.05,
        )

        y_true_by_cfg: list[list[int]] = [[] for _ in range(n_cfg)]
        y_pred_by_cfg: list[list[int]] = [[] for _ in range(n_cfg)]
        scores_by_cfg: list[list[float]] = [[] for _ in range(n_cfg)]
        ep_detected_by_cfg: list[dict[str, bool]] = [
            {ep.episode_id: False for ep in episodes} for _ in range(n_cfg)
        ]
        ep_first_alert_by_cfg: list[dict[str, float | None]] = [
            {ep.episode_id: None for ep in episodes} for _ in range(n_cfg)
        ]
        false_alerts_by_cfg: list[int] = [0 for _ in range(n_cfg)]
        total_seconds_observed = 0.0

        for ep_idx, ep in enumerate(episodes):
            dev = next((d for d in self.devices if d.id == ep.device_id or d.ip_address == ep.device_id), None)
            if not dev:
                continue
            model = self._models[dev.id]
            baseline = self._baselines[dev.id]

            slice_start = max(0.0, float(np.floor((ep.start_time - pre_buffer_s) / stride) * stride))
            slice_end = ep.end_time + post_buffer_s
            total_seconds_observed += max(0.0, slice_end - slice_start)

            in_streak = [False for _ in range(n_cfg)]

            if precomputed_episode_windows is not None and ep_idx < len(precomputed_episode_windows):
                window_records = precomputed_episode_windows[ep_idx]["window_records"]
            else:
                random.seed(self.seed)
                np.random.seed(self.seed)

                flow_tracker = FlowTracker(window_size_seconds=self.scenario_builder.window_size_s)
                for dst in dev.normal_destinations:
                    flow_tracker.register_known_destination(dev.ip_address, dst)

                windows = self.scenario_builder.generate_device_stream_windows(
                    device_id=dev.id,
                    start_time=slice_start,
                    end_time=slice_end,
                    episodes=[ep],
                )
                window_records = []
                for w in windows:
                    flow_tracker.device_buffers[dev.ip_address].clear()
                    for p in w.packets:
                        flow_tracker.ingest_packet(p)

                    summary = flow_tracker.get_window_summary(dev.ip_address, current_timestamp=w.end_time)
                    if not summary:
                        continue

                    base_features = self.extractor.extract(summary)
                    base_vec = self.extractor.extract_vector(summary)
                    base_ml_score, _ = model.score_sample(base_vec)
                    base_stat_score, _ = baseline.evaluate(base_features)
                    window_records.append(
                        {
                            "end_time": w.end_time,
                            "has_attack": w.has_attack,
                            "active_episode_ids": w.active_episode_ids,
                            "base_features": base_features,
                            "base_ml_score": base_ml_score,
                            "base_stat_score": base_stat_score,
                        }
                    )

            for w_rec in window_records:
                base_features = w_rec["base_features"]
                base_ml_score = w_rec["base_ml_score"]
                base_stat_score = w_rec["base_stat_score"]
                is_attack_window = 1 if w_rec["has_attack"] else 0
                w_end_time = float(w_rec["end_time"])
                active_ep_ids = w_rec["active_episode_ids"]

                for idx, cfg in enumerate(battery):
                    raw_score, is_alert = self._score_window_for_config(
                        config=cfg,
                        base_features=base_features,
                        base_ml_score=base_ml_score,
                        base_stat_score=base_stat_score,
                        model=model,
                        baseline=baseline,
                        threat_scorer=threat_scorer,
                        calibrated_op=calibrated_ops[idx],
                    )
                    y_true_by_cfg[idx].append(is_attack_window)
                    y_pred_by_cfg[idx].append(1 if is_alert else 0)
                    scores_by_cfg[idx].append(raw_score / 100.0)

                    if active_ep_ids:
                        time_into_ep = w_end_time - ep.start_time
                        if is_alert and (0.0 <= time_into_ep <= self.deadline_seconds):
                            if not ep_detected_by_cfg[idx][ep.episode_id]:
                                ep_detected_by_cfg[idx][ep.episode_id] = True
                                ep_first_alert_by_cfg[idx][ep.episode_id] = w_end_time
                    else:
                        if is_alert:
                            if cfg.enable_hysteresis:
                                if not in_streak[idx]:
                                    false_alerts_by_cfg[idx] += 1
                                    in_streak[idx] = True
                            else:
                                false_alerts_by_cfg[idx] += 1
                        else:
                            in_streak[idx] = False

        results: list[AblationResult] = []
        days_observed = max(1e-4, total_seconds_observed / 86400.0)
        n_eps = len(episodes)

        for idx, cfg in enumerate(battery):
            bin_metrics = compute_binary_metrics(y_true_by_cfg[idx], y_pred_by_cfg[idx])
            roc_auc = compute_roc_auc(y_true_by_cfg[idx], scores_by_cfg[idx])
            pr_auc = compute_pr_auc(y_true_by_cfg[idx], scores_by_cfg[idx])

            detected_eps = sum(1 for d in ep_detected_by_cfg[idx].values() if d)
            ep_det_rate = (detected_eps / n_eps) if n_eps > 0 else 0.0

            far_per_day = compute_false_alert_rate(
                num_false_alerts=false_alerts_by_cfg[idx],
                num_devices=max(1, len(self.devices)),
                days_observed=days_observed,
            )

            ttd_list: list[float] = []
            for e in episodes:
                if ep_detected_by_cfg[idx].get(e.episode_id, False):
                    t_alert = ep_first_alert_by_cfg[idx].get(e.episode_id)
                    if t_alert is not None:
                        ttd_list.append(t_alert - e.start_time)
            mean_ttd = float(sum(ttd_list) / len(ttd_list)) if ttd_list else 0.0

            results.append(
                AblationResult(
                    config_name=cfg.name,
                    total_windows=len(y_true_by_cfg[idx]),
                    tp=bin_metrics.tp,
                    fp=bin_metrics.fp,
                    tn=bin_metrics.tn,
                    fn=bin_metrics.fn,
                    tpr=ep_det_rate,
                    fpr=bin_metrics.fpr,
                    precision=bin_metrics.precision,
                    recall=bin_metrics.recall,
                    f1=bin_metrics.f1,
                    roc_auc=roc_auc,
                    pr_auc=pr_auc,
                    total_episodes=n_eps,
                    detected_episodes=detected_eps,
                    episode_detection_rate=ep_det_rate,
                    false_alerts_per_device_day=far_per_day,
                    mean_ttd_seconds=mean_ttd,
                )
            )

        return results

