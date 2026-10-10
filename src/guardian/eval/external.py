"""
External IoT Dataset Validation Module for GUARDIAN (Milestone P3-5).

Supports public IoT security benchmarks (e.g. IoT-23 and TON_IoT Zeek conn.logs).
Maps external flow records to GUARDIAN's 60-feature schema and evaluates detection
performance across real-world malware captures (Mirai, Kenjiro, Torii, Gafgyt).
"""

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np

from ..features.extractor import HIGH_RISK_PORTS, shannon_entropy
from ..ml.threat_scorer import ThreatScorer
from .calibration import OperatingPoint
from .metrics import compute_binary_metrics


@dataclass(frozen=True)
class IoT23Record:
    """Represents a single Zeek/Bro connection record from the IoT-23 dataset."""

    ts: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    service: str
    duration: float
    orig_bytes: int
    resp_bytes: int
    conn_state: str
    history: str
    orig_pkts: int
    resp_pkts: int
    label: str
    detailed_label: str

    @property
    def is_malicious(self) -> bool:
        """True if label denotes malicious / attack activity."""
        lbl = self.label.lower()
        return "malicious" in lbl or "attack" in lbl or "c&c" in lbl or "ddos" in lbl or "partof" in lbl


@dataclass
class IoT23Window:
    """Aggregated sliding window of IoT-23 flow records."""

    device_id: str
    window_start: float
    window_end: float
    records: list[IoT23Record] = field(default_factory=list)
    has_attack: bool = False


class IoT23Adapter:
    """
    Adapter converting IoT-23 Zeek conn.log files into GUARDIAN sliding windows
    and extracting feature vectors mapped to GUARDIAN's 60-feature representation.
    """

    def parse_file(self, file_path: Path | str) -> list[IoT23Record]:
        """Parse Zeek/Bro conn.log file into structured IoT23Record objects."""
        path = Path(file_path)
        records: list[IoT23Record] = []

        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split("\t") if "\t" in line else line.split()
                if len(parts) < 15:
                    continue

                try:
                    ts = float(parts[0])
                    uid = parts[1]
                    orig_h = parts[2]
                    orig_p = int(parts[3]) if parts[3] != "-" else 0
                    resp_h = parts[4]
                    resp_p = int(parts[5]) if parts[5] != "-" else 0
                    proto = parts[6].upper()
                    service = parts[7]
                    duration = float(parts[8]) if parts[8] != "-" else 0.001
                    orig_bytes = int(parts[9]) if parts[9] != "-" else 0
                    resp_bytes = int(parts[10]) if parts[10] != "-" else 0
                    conn_state = parts[11]
                    history = parts[15] if len(parts) > 15 else ""
                    orig_pkts = int(parts[16]) if len(parts) > 16 and parts[16] != "-" else max(1, orig_bytes // 100)
                    resp_pkts = int(parts[18]) if len(parts) > 18 and parts[18] != "-" else (1 if resp_bytes > 0 else 0)
                    label = parts[-2] if len(parts) >= 22 else parts[-1]
                    detailed = parts[-1] if len(parts) >= 23 else ""

                    records.append(
                        IoT23Record(
                            ts=ts,
                            uid=uid,
                            orig_h=orig_h,
                            orig_p=orig_p,
                            resp_h=resp_h,
                            resp_p=resp_p,
                            proto=proto,
                            service=service,
                            duration=duration,
                            orig_bytes=orig_bytes,
                            resp_bytes=resp_bytes,
                            conn_state=conn_state,
                            history=history,
                            orig_pkts=orig_pkts,
                            resp_pkts=resp_pkts,
                            label=label,
                            detailed_label=detailed,
                        )
                    )
                except (ValueError, IndexError):
                    continue

        return records

    def aggregate_to_windows(
        self,
        records: Sequence[IoT23Record],
        window_size_s: float = 10.0,
        stride_s: float = 5.0,
    ) -> list[IoT23Window]:
        """Aggregate records into sliding time windows per originating device."""
        if not records:
            return []

        sorted_recs = sorted(records, key=lambda r: r.ts)
        t_start = sorted_recs[0].ts
        t_end = sorted_recs[-1].ts

        windows: list[IoT23Window] = []
        cur_t = t_start

        while cur_t <= t_end:
            w_start = cur_t
            w_end = cur_t + window_size_s

            window_recs = [r for r in sorted_recs if w_start <= r.ts < w_end]
            if window_recs:
                has_attack = any(r.is_malicious for r in window_recs)
                dev_id = window_recs[0].orig_h
                windows.append(
                    IoT23Window(
                        device_id=dev_id,
                        window_start=w_start,
                        window_end=w_end,
                        records=window_recs,
                        has_attack=has_attack,
                    )
                )

            cur_t += stride_s

        return windows

    def extract_features(self, window: IoT23Window) -> dict[str, float]:
        """
        Map external flow records within window to GUARDIAN's 60-feature schema.
        Handles missing physical/kernel features safely by assigning neutral defaults.
        """
        recs = window.records
        n_recs = len(recs)
        duration = max(0.001, window.window_end - window.window_start)

        # 1. Layer 1: Volumetric & Rate Dynamics
        total_pkts = sum(r.orig_pkts + r.resp_pkts for r in recs)
        total_bytes = sum(r.orig_bytes + r.resp_bytes for r in recs)
        pkt_rate = float(total_pkts / duration)
        byte_rate = float(total_bytes / duration)

        durations = [r.duration for r in recs if r.duration > 0]
        flow_duration = float(np.mean(durations)) if durations else 0.001

        # IAT estimations from flow start timestamps
        if n_recs > 1:
            iats = [recs[i].ts - recs[i - 1].ts for i in range(1, n_recs)]
            iat_mean = float(np.mean(iats))
            iat_std = float(np.std(iats))
            iat_min = float(np.min(iats))
            iat_max = float(np.max(iats))
            iat_median = float(np.median(iats))
        else:
            iat_mean = 0.1
            iat_std = 0.0
            iat_min = 0.1
            iat_max = 0.1
            iat_median = 0.1

        # 2. Layer 2: Network Destination Graph & Ports
        dst_ips = [r.resp_h for r in recs]
        unique_dst_ips = float(len(set(dst_ips)))
        dst_ip_entropy = shannon_entropy(dst_ips)
        out_degree_centrality = float(min(1.0, unique_dst_ips / max(1.0, n_recs * 0.1)))

        external_recs = sum(1 for r in recs if not r.resp_h.startswith("192.168.") and r.resp_h != "127.0.0.1")
        external_ip_ratio = float(external_recs / max(1, n_recs))
        new_dst_ip_flag = 1.0 if external_ip_ratio > 0.3 else 0.0

        dst_ports = [r.resp_p for r in recs if r.resp_p > 0]
        dst_port_entropy = shannon_entropy(dst_ports)
        high_risk_port_flag = 1.0 if any(p in HIGH_RISK_PORTS for p in dst_ports) else 0.0

        # 3. Layer 3: Protocol Signatures & Temporal Features
        dt_obj = datetime.fromtimestamp(window.window_end)
        hour_fraction = dt_obj.hour + (dt_obj.minute / 60.0)
        hour_sin = float(math.sin(2 * math.pi * hour_fraction / 24.0))
        hour_cos = float(math.cos(2 * math.pi * hour_fraction / 24.0))

        # TCP Flag estimation from Zeek connection history
        hist_str = "".join(r.history for r in recs)
        n_hist = max(1, len(hist_str))
        tcp_syn_ratio = float(hist_str.count("S") + hist_str.count("s")) / n_hist
        tcp_ack_ratio = float(hist_str.count("A") + hist_str.count("a")) / n_hist

        proto_entropy = shannon_entropy([r.proto for r in recs])

        features: dict[str, float] = {
            "pkt_count_10s": float(total_pkts),
            "byte_count_10s": float(total_bytes),
            "pkt_rate_per_sec": pkt_rate,
            "byte_rate_per_sec": byte_rate,
            "flow_duration_sec": flow_duration,
            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "iat_min": iat_min,
            "iat_max": iat_max,
            "iat_median": iat_median,
            "unique_dst_ips": unique_dst_ips,
            "dst_ip_entropy": dst_ip_entropy,
            "out_degree_centrality": out_degree_centrality,
            "external_ip_ratio": external_ip_ratio,
            "new_dst_ip_flag": new_dst_ip_flag,
            "dst_port_entropy": dst_port_entropy,
            "high_risk_port_flag": high_risk_port_flag,
            "hour_sin": hour_sin,
            "hour_cos": hour_cos,
            "tcp_syn_ratio": tcp_syn_ratio,
            "tcp_ack_ratio": tcp_ack_ratio,
            "protocol_entropy": proto_entropy,
            "tcp_clock_skew_est": 0.0,
            "ip_id_monotonicity": 1.0,
            "ip_ttl_variance": 0.0,
        }
        return features


class ExternalDatasetEvaluator:
    """
    Evaluates GUARDIAN's threat scoring pipeline on real external IoT datasets.
    """

    def __init__(self, seed: int = 42, alert_threshold: float = 40.0) -> None:
        self.seed = seed
        self.operating_point = OperatingPoint(alert_threshold=alert_threshold, frozen=True)
        self.adapter = IoT23Adapter()
        self.threat_scorer = ThreatScorer()

    def evaluate_iot23_log(
        self,
        file_path: Path | str,
        window_size_s: float = 10.0,
        stride_s: float = 5.0,
    ) -> dict[str, Any]:
        """Execute evaluation over an external Zeek conn.log trace."""
        records = self.adapter.parse_file(file_path)
        windows = self.adapter.aggregate_to_windows(records, window_size_s=window_size_s, stride_s=stride_s)

        y_true: list[int] = []
        y_pred: list[int] = []
        scores: list[float] = []

        for w in windows:
            feats = self.adapter.extract_features(w)

            # Evaluate through ThreatScorer
            # In external evaluation without device-specific model, Cold Start heuristic scoring is used
            assessment = self.threat_scorer.assess(
                ml_score=0.5,
                statistical_score=0.5,
                features=feats,
                is_cold_start=True,
            )
            score = float(assessment.threat_score)
            is_alert = self.operating_point.is_alert(score)

            is_att = 1 if w.has_attack else 0
            y_true.append(is_att)
            y_pred.append(1 if is_alert else 0)
            scores.append(score / 100.0)

        metrics = compute_binary_metrics(y_true, y_pred)
        n_total = len(windows)
        n_mal = sum(y_true)
        n_benign = n_total - n_mal

        return {
            "total_records": len(records),
            "total_windows": n_total,
            "malicious_windows": n_mal,
            "benign_windows": n_benign,
            "tp": metrics.tp,
            "fp": metrics.fp,
            "tn": metrics.tn,
            "fn": metrics.fn,
            "tpr": metrics.tpr,
            "fpr": metrics.fpr,
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1": metrics.f1,
            "operating_threshold": self.operating_point.alert_threshold,
        }


@dataclass(frozen=True)
class LabeledIoT23CaptureDataset:
    """
    Task 42: Structured container for a labeled IoT-23 capture that strictly isolates
    unlabeled detector inputs (features, timestamps, device IDs) from evaluation-only
    ground-truth labels (`eval_only_labels`, `eval_only_attack_families`).
    """

    source_path: str
    device_ids: tuple[str, ...]
    window_starts: tuple[float, ...]
    feature_dicts: tuple[dict[str, float], ...]
    eval_only_labels: tuple[int, ...]
    eval_only_attack_families: tuple[str, ...]


def load_labeled_iot23_capture(
    file_path: Path | str,
    window_size_s: float = 10.0,
    stride_s: float = 5.0,
) -> LabeledIoT23CaptureDataset:
    """
    Task 42: Load a labeled IoT-23 Zeek conn.log capture into unlabeled feature windows
    paired with evaluation-only ground-truth labels and malware family annotations.
    """
    adapter = IoT23Adapter()
    records = adapter.parse_file(file_path)
    windows = adapter.aggregate_to_windows(records, window_size_s=window_size_s, stride_s=stride_s)

    device_ids: list[str] = []
    window_starts: list[float] = []
    feature_dicts: list[dict[str, float]] = []
    eval_labels: list[int] = []
    eval_families: list[str] = []

    for w in windows:
        device_ids.append(w.device_id)
        window_starts.append(w.window_start)
        feature_dicts.append(adapter.extract_features(w))
        eval_labels.append(1 if w.has_attack else 0)
        mal_recs = [r for r in w.records if r.is_malicious]
        if mal_recs:
            fam = next((r.detailed_label for r in mal_recs if r.detailed_label and r.detailed_label != "-"), mal_recs[0].label)
            eval_families.append(fam)
        else:
            eval_families.append("Benign")

    return LabeledIoT23CaptureDataset(
        source_path=str(file_path),
        device_ids=tuple(device_ids),
        window_starts=tuple(window_starts),
        feature_dicts=tuple(feature_dicts),
        eval_only_labels=tuple(eval_labels),
        eval_only_attack_families=tuple(eval_families),
    )


def score_unlabeled_feature_windows(
    feature_dicts: Sequence[dict[str, float]],
    alert_threshold: float = 40.0,
) -> tuple[list[int], list[float]]:
    """
    Score unlabeled external feature windows without access to any ground-truth label fields.
    """
    scorer = ThreatScorer()
    op = OperatingPoint(alert_threshold=alert_threshold, frozen=True)
    y_pred: list[int] = []
    raw_scores: list[float] = []
    for feats in feature_dicts:
        assessment = scorer.assess(
            ml_score=0.5,
            statistical_score=0.5,
            features=feats,
            is_cold_start=True,
        )
        sc = float(assessment.threat_score)
        y_pred.append(1 if op.is_alert(sc) else 0)
        raw_scores.append(sc / 100.0)
    return y_pred, raw_scores


def generate_external_attack_detection_report(
    dataset: LabeledIoT23CaptureDataset,
    alert_threshold: float = 40.0,
) -> dict[str, Any]:
    """
    Task 43: Evaluate external IoT-23 attack detection where ground-truth labels are used
    strictly for post-hoc evaluation scoring (never during feature extraction or scoring).
    """
    from .metrics import wilson_score_ci

    y_pred, _ = score_unlabeled_feature_windows(dataset.feature_dicts, alert_threshold=alert_threshold)
    y_true = list(dataset.eval_only_labels)
    metrics = compute_binary_metrics(y_true, y_pred)

    n_pos = metrics.tp + metrics.fn
    n_neg = metrics.fp + metrics.tn
    tpr_ci = wilson_score_ci(metrics.tp, max(1, n_pos), scale_100=False)
    fpr_ci = wilson_score_ci(metrics.fp, max(1, n_neg), scale_100=False)

    per_family: dict[str, dict[str, Any]] = {}
    for fam, yt, yp in zip(dataset.eval_only_attack_families, y_true, y_pred, strict=True):
        if yt == 0:
            continue
        bucket = per_family.setdefault(fam, {"total": 0, "detected": 0})
        bucket["total"] += 1
        bucket["detected"] += int(yp == 1)

    for bucket in per_family.values():
        tot = bucket["total"]
        det = bucket["detected"]
        ci = wilson_score_ci(det, max(1, tot), scale_100=False)
        bucket["tpr"] = round(det / max(1, tot), 4)
        bucket["tpr_ci_95"] = [round(ci.ci_lower, 4), round(ci.ci_upper, 4)]

    return {
        "source_path": dataset.source_path,
        "labels_used_for_training": False,
        "total_windows": len(y_true),
        "malicious_windows": n_pos,
        "benign_windows": n_neg,
        "tp": metrics.tp,
        "fp": metrics.fp,
        "tn": metrics.tn,
        "fn": metrics.fn,
        "tpr": round(metrics.tpr, 4),
        "tpr_ci_95": [round(tpr_ci.ci_lower, 4), round(tpr_ci.ci_upper, 4)],
        "fpr": round(metrics.fpr, 4),
        "fpr_ci_95": [round(fpr_ci.ci_lower, 4), round(fpr_ci.ci_upper, 4)],
        "false_alerts_per_device_day": round(metrics.fpr * 8640.0, 2),
        "f1": round(metrics.f1, 4),
        "per_attack_family": per_family,
    }


EXTERNAL_DATASET_REGISTRY: tuple[dict[str, Any], ...] = (
    {
        "dataset_id": "iot23_somfy_02",
        "dataset_name": "Stratosphere IoT-23 — CTU-Honeypot-Capture-7-1 (Somfy-02)",
        "filename": "Somfy-02/2019-07-03-16-41-09-192.168.1.158.pcap",
        "size_bytes": 33104424,
        "sha256": "2a32158374fce6635272ff8fc0ff39b88e1e759100a6384b9a2c8b14ad5dc7b6",
        "license": "CC BY 4.0 (Creative Commons Attribution 4.0 International)",
        "doi": "https://doi.org/10.5281/zenodo.4743746",
        "label_policy": "Unlabeled benign capture (used for calibration and cross-domain FPR)",
    },
    {
        "dataset_id": "iot23_somfy_04",
        "dataset_name": "Stratosphere IoT-23 — CTU-Honeypot-Capture-7-1 (Somfy-04)",
        "filename": "Somfy-04/2019-07-05-16-41-14-192.168.1.158.pcap",
        "size_bytes": 33213386,
        "sha256": "b7e06c6dbd9cc731b13c741cb6244a36de0f181eeb884c409704f1d5bb991738",
        "license": "CC BY 4.0 (Creative Commons Attribution 4.0 International)",
        "doi": "https://doi.org/10.5281/zenodo.4743746",
        "label_policy": "Unlabeled benign capture (used for calibration and cross-domain FPR)",
    },
    {
        "dataset_id": "iot23_somfy_combined_64mb",
        "dataset_name": "Stratosphere IoT-23 — Combined Somfy TaHoma 64 MB Replay Trace",
        "filename": "somfy_combined_64mb.pcap",
        "size_bytes": 66317786,
        "sha256": "068ce86e900adaa96d9d6075ca652de7b52e535475d029b6c7e8701565c6f3d3",
        "license": "CC BY 4.0 (Creative Commons Attribution 4.0 International)",
        "doi": "https://doi.org/10.5281/zenodo.4743746",
        "label_policy": "Labels used strictly for post-hoc evaluation scoring; never for training",
    },
)


def generate_dataset_registry_markdown() -> str:
    """Task 45: Generate canonical external dataset, license, and SHA-256 checksum registry markdown."""
    lines = [
        "# External Dataset, License & Checksum Registry",
        "",
        "Canonical provenance, license, and SHA-256 checksum registry for external IoT captures",
        "evaluated by GUARDIAN (`src/guardian/eval/external.py`).",
        "",
        "| Dataset ID | File | Size (Bytes) | SHA-256 Checksum | License | DOI | Label Policy |",
        "| :--- | :--- | :---: | :--- | :---: | :--- | :--- |",
    ]
    for entry in EXTERNAL_DATASET_REGISTRY:
        lines.append(
            f"| `{entry['dataset_id']}` | `{entry['filename']}` | `{entry['size_bytes']}` | "
            f"`{entry['sha256']}` | {entry['license']} | {entry['doi']} | {entry['label_policy']} |"
        )
    lines.append("")
    return "\n".join(lines)
