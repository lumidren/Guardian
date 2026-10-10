"""
Empirical Simulator Calibration Module from Real IoT PCAP Telemetry (Phase 4 Section B, Tasks 27-46).

Derives statistical mixture models, micro-burst IAT distributions, bidirectional flow ratios,
TCP window/TTL stack parameters, and protocol mixes directly from empirical PCAP telemetry
(`eval/results/real_pcap_64mb_comparison.json` and live window feature summaries).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from ..features.registry import FEATURE_NAMES

DEFAULT_COMPARISON_JSON = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "eval"
    / "results"
    / "real_pcap_64mb_comparison.json"
)


@dataclass(frozen=True)
class FeatureEmpiricalStats:
    """Per-feature empirical distribution statistics extracted from real PCAP windows."""

    feature: str
    mean: float
    std: float
    median: float
    p95: float
    sim_mean: float
    sim_std: float
    ks_stat: float
    smd: float
    nonzero_variance_both: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature": self.feature,
            "mean": self.mean,
            "std": self.std,
            "median": self.median,
            "p95": self.p95,
            "sim_mean": self.sim_mean,
            "sim_std": self.sim_std,
            "ks_stat": self.ks_stat,
            "smd": self.smd,
            "nonzero_variance_both": self.nonzero_variance_both,
        }


def extract_per_feature_pcap_stats(
    comparison_json_path: Path | str | None = None,
    window_feature_dicts: Sequence[dict[str, float]] | None = None,
) -> dict[str, FeatureEmpiricalStats]:
    """
    Task 27: Extract per-feature empirical statistics (mean, std, median, p95, KS, SMD,
    and mutual nonzero-variance status) from the real 64 MB IoT PCAP comparison artifact
    or from a sequence of extracted window feature dictionaries.
    """
    if window_feature_dicts is not None and len(window_feature_dicts) > 0:
        out: dict[str, FeatureEmpiricalStats] = {}
        for fname in FEATURE_NAMES:
            arr = np.asarray([float(w.get(fname, 0.0)) for w in window_feature_dicts], dtype=np.float64)
            mean_v = float(np.mean(arr))
            std_v = float(np.std(arr))
            med_v = float(np.median(arr))
            p95_v = float(np.percentile(arr, 95))
            out[fname] = FeatureEmpiricalStats(
                feature=fname,
                mean=round(mean_v, 6),
                std=round(std_v, 6),
                median=round(med_v, 6),
                p95=round(p95_v, 6),
                sim_mean=round(mean_v, 6),
                sim_std=round(std_v, 6),
                ks_stat=0.0,
                smd=0.0,
                nonzero_variance_both=std_v > 0.0,
            )
        return out

    path = Path(comparison_json_path) if comparison_json_path is not None else DEFAULT_COMPARISON_JSON
    data = json.loads(path.read_text(encoding="utf-8"))
    stats_map: dict[str, FeatureEmpiricalStats] = {}
    for entry in data.get("features", []):
        fname = str(entry["feature"])
        r_std = float(entry["real_std"])
        s_std = float(entry["sim_std"])
        stats_map[fname] = FeatureEmpiricalStats(
            feature=fname,
            mean=float(entry["real_mean"]),
            std=r_std,
            median=float(entry["real_median"]),
            p95=float(entry["real_p95"]),
            sim_mean=float(entry["sim_mean"]),
            sim_std=s_std,
            ks_stat=float(entry["ks_stat"]),
            smd=float(entry["smd"]),
            nonzero_variance_both=(r_std > 0.0 and s_std > 0.0),
        )
    return stats_map
