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


@dataclass(frozen=True)
class PacketSizeMixtureModel:
    """
    Task 28: Two-component bimodal packet-size mixture model fitted from real PCAP stats:
    - Component 1 (ACK / small control frames): weight w_ack, mean mu_ack, std sigma_ack
    - Component 2 (TLS / application payload frames): weight (1 - w_ack), mean mu_payload, std sigma_payload
    """

    w_ack: float
    mu_ack: float
    sigma_ack: float
    mu_payload: float
    sigma_payload: float
    min_bytes: int
    max_bytes: int

    def sample(self, rng: np.random.Generator | None = None) -> int:
        gen = rng or np.random.default_rng()
        if float(gen.random()) < self.w_ack:
            val = float(gen.normal(self.mu_ack, self.sigma_ack))
        else:
            val = float(gen.normal(self.mu_payload, self.sigma_payload))
        return int(max(self.min_bytes, min(self.max_bytes, round(val))))


def fit_packet_size_mixture_model(
    stats: dict[str, FeatureEmpiricalStats] | None = None,
) -> PacketSizeMixtureModel:
    """
    Fit a bimodal packet-size mixture model directly from extracted real PCAP feature statistics.
    """
    s = stats or extract_per_feature_pcap_stats()
    mean_len = s["pkt_len_mean"].mean
    std_len = s["pkt_len_std"].mean
    min_len = max(40.0, s["pkt_len_min"].mean)
    max_len = max(min_len + 20.0, s["pkt_len_max"].p95)
    w_ack = max(0.15, min(0.85, s["small_pkt_ratio"].mean if s["small_pkt_ratio"].mean > 0 else 0.52))
    mu_ack = min_len + 6.0
    mu_payload = max(mu_ack + 20.0, (mean_len - w_ack * mu_ack) / max(0.15, 1.0 - w_ack))
    sigma_ack = 4.0
    sigma_payload = max(12.0, std_len * 0.75)
    return PacketSizeMixtureModel(
        w_ack=round(w_ack, 4),
        mu_ack=round(mu_ack, 2),
        sigma_ack=round(sigma_ack, 2),
        mu_payload=round(mu_payload, 2),
        sigma_payload=round(sigma_payload, 2),
        min_bytes=int(round(min_len)),
        max_bytes=int(round(max_len)),
    )


@dataclass(frozen=True)
class IATMicroBurstModel:
    """
    Task 29: Two-regime inter-arrival time (IAT) micro-burst model fitted from real PCAP stats:
    - Intra-burst regime (prob p_intra): sub-millisecond/millisecond back-to-back ACK/PSH segments
    - Inter-burst regime (prob 1 - p_intra): pause between keepalive/polling bursts
    """

    p_intra_burst: float
    intra_mean_s: float
    intra_min_s: float
    inter_mean_s: float
    inter_max_s: float
    burstiness_index: float

    def sample_timestamps(
        self,
        pkt_count: int,
        start_time: float,
        window_duration: float = 10.0,
        rng: np.random.Generator | None = None,
    ) -> list[float]:
        gen = rng or np.random.default_rng()
        if pkt_count <= 0:
            return []
        end_time = start_time + window_duration
        t = start_time + float(gen.uniform(0.01, min(0.5, window_duration * 0.1)))
        out = [t]
        for _ in range(pkt_count - 1):
            if float(gen.random()) < self.p_intra_burst:
                gap = max(self.intra_min_s, float(gen.exponential(self.intra_mean_s)))
            else:
                gap = min(self.inter_max_s, float(gen.exponential(self.inter_mean_s)))
            t = min(end_time - 1e-4, t + gap)
            out.append(t)
        return sorted(out)


def fit_iat_micro_burst_model(
    stats: dict[str, FeatureEmpiricalStats] | None = None,
) -> IATMicroBurstModel:
    """
    Fit an inter-arrival micro-burst model from extracted real PCAP IAT statistics.
    """
    s = stats or extract_per_feature_pcap_stats()
    iat_min = max(1e-5, s["iat_min"].mean)
    iat_med = max(iat_min * 1.5, s["iat_median"].mean)
    iat_mean = max(iat_med, s["iat_mean"].mean)
    iat_max = max(iat_mean * 1.5, s["iat_max"].mean)
    burst_idx = max(0.05, s["burstiness_index"].mean)
    p_intra = 0.68
    inter_mean = max(iat_mean * 1.2, (iat_mean - p_intra * iat_med) / (1.0 - p_intra))
    return IATMicroBurstModel(
        p_intra_burst=round(p_intra, 4),
        intra_mean_s=round(iat_med, 6),
        intra_min_s=round(iat_min, 6),
        inter_mean_s=round(inter_mean, 6),
        inter_max_s=round(iat_max, 6),
        burstiness_index=round(burst_idx, 4),
    )


@dataclass(frozen=True)
class BidirectionalRatioModel:
    """
    Task 30: Bidirectional packet and byte ratio model fitted from real PCAP telemetry.
    Ensures upstream + downstream ratios sum to 1.0 while matching empirical variance.
    """

    upstream_pkt_ratio_mean: float
    upstream_pkt_ratio_std: float
    downstream_pkt_ratio_mean: float
    upstream_byte_ratio_mean: float
    upstream_byte_ratio_std: float
    downstream_byte_ratio_mean: float

    def sample_outbound_flag(self, rng: np.random.Generator | None = None) -> bool:
        gen = rng or np.random.default_rng()
        return bool(float(gen.random()) < self.upstream_pkt_ratio_mean)


def fit_bidirectional_ratio_model(
    stats: dict[str, FeatureEmpiricalStats] | None = None,
) -> BidirectionalRatioModel:
    """
    Fit upstream/downstream packet and byte ratios directly from real PCAP feature statistics.
    """
    s = stats or extract_per_feature_pcap_stats()
    up_pkt = max(0.05, min(0.95, s["upstream_pkt_ratio"].mean))
    up_pkt_std = max(0.01, s["upstream_pkt_ratio"].std)
    down_pkt = round(1.0 - up_pkt, 6)
    up_byte = max(0.05, min(0.95, s["upstream_byte_ratio"].mean))
    up_byte_std = max(0.01, s["upstream_byte_ratio"].std)
    down_byte = round(1.0 - up_byte, 6)
    return BidirectionalRatioModel(
        upstream_pkt_ratio_mean=round(up_pkt, 6),
        upstream_pkt_ratio_std=round(up_pkt_std, 6),
        downstream_pkt_ratio_mean=down_pkt,
        upstream_byte_ratio_mean=round(up_byte, 6),
        upstream_byte_ratio_std=round(up_byte_std, 6),
        downstream_byte_ratio_mean=down_byte,
    )


@dataclass(frozen=True)
class TCPStackDistributionModel:
    """
    Task 31: TCP window size, flag ratios, and IPv4 TTL/IP-ID stack distributions fitted from real PCAP.
    """

    tcp_win_mean: float
    tcp_win_std: float
    outbound_ttl: int
    inbound_wan_ttl: int
    ip_ttl_variance_target: float
    tcp_psh_ratio: float
    tcp_ack_ratio: float
    tcp_syn_ratio: float
    ip_id_monotonicity_target: float

    def sample_tcp_window(self, is_outbound: bool, rng: np.random.Generator | None = None) -> int:
        gen = rng or np.random.default_rng()
        base = self.tcp_win_mean * (1.05 if is_outbound else 0.95)
        win = int(round(float(gen.normal(base, max(64.0, self.tcp_win_std * 0.35)))))
        return max(502, min(65535, win))

    def sample_ttl(self, is_outbound: bool, is_external: bool = True) -> int:
        if is_outbound or not is_external:
            return self.outbound_ttl
        return self.inbound_wan_ttl


def fit_tcp_window_and_ttl_distributions(
    stats: dict[str, FeatureEmpiricalStats] | None = None,
) -> TCPStackDistributionModel:
    """
    Fit TCP window size, PSH/ACK/SYN flag probabilities, and outbound/inbound TTL parameters
    from extracted real PCAP statistics.
    """
    import math

    s = stats or extract_per_feature_pcap_stats()
    win_mean = max(512.0, s["tcp_win_mean"].mean)
    win_std = max(64.0, s["tcp_win_mean"].std)
    ttl_var = max(0.0, s["ip_ttl_variance"].mean)
    # For ~50/50 bidirectional traffic, Var(TTL) = 0.25 * (64 - ttl_in)^2 => ttl_in = 64 - 2*sqrt(Var)
    ttl_delta = int(round(2.0 * math.sqrt(ttl_var)))
    outbound_ttl = 64
    inbound_ttl = max(32, min(64, outbound_ttl - ttl_delta))
    return TCPStackDistributionModel(
        tcp_win_mean=round(win_mean, 2),
        tcp_win_std=round(win_std, 2),
        outbound_ttl=outbound_ttl,
        inbound_wan_ttl=inbound_ttl,
        ip_ttl_variance_target=round(ttl_var, 4),
        tcp_psh_ratio=round(max(0.05, min(0.95, s["tcp_psh_ratio"].mean)), 4),
        tcp_ack_ratio=round(max(0.50, min(1.0, s["tcp_ack_ratio"].mean)), 4),
        tcp_syn_ratio=round(max(0.0, min(0.50, s["tcp_syn_ratio"].mean)), 4),
        ip_id_monotonicity_target=round(max(0.0, min(1.0, s["ip_id_monotonicity"].mean)), 4),
    )




