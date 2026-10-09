"""
Empirical Baselines Module for GUARDIAN (Milestone P2-4).

Implements real baselines that replace unmeasured literature numbers (fixing F1):
1. StaticThresholdBaseline: Rule-based static rate ceilings and destination/port allowlists.
2. PooledIsolationForestBaseline: Fleet-wide pooled anomaly detection (generic ML baseline).
3. RobustZScoreOnlyBaseline: Layer 1 statistical anomaly detection without Isolation Forest.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

import numpy as np

from simulation.fleet_emulator import IoTDeviceSpec

from ..capture.flow_tracker import FlowSummary
from ..ml.isolation_forest import IsolationForestDetector
from ..ml.statistical_baseline import StatisticalBaseline

HIGH_RISK_PORTS = {21, 22, 23, 2323, 3389, 4444, 5555, 6667, 8888, 9999, 1337, 31337}

PROTOCOL_DEFAULT_PORTS: dict[str, set[int]] = {
    "MQTT": {1883, 8883},
    "HTTP": {80, 8080},
    "HTTPS": {443, 8443},
    "RTSP": {554, 8554},
    "DNS": {53},
    "NTP": {123},
    "COAP": {5683, 5684},
}


@dataclass
class StaticThresholdBaseline:
    """
    Simulates commercial firewall/NIDS static rules.
    Enforces per-device destination allowlists, port allowlists, and volumetric rate ceilings.
    """

    device_id: str
    allowed_destinations: set[str] = field(default_factory=set)
    allowed_ports: set[int] = field(default_factory=set)
    max_packet_rate: float = 25.0  # packets / sec ceiling
    max_byte_rate: float = 25000.0  # bytes / sec ceiling

    @classmethod
    def from_device_spec(cls, spec: IoTDeviceSpec) -> "StaticThresholdBaseline":
        """Instantiate static baseline calibrated to device specification."""
        # spec.normal_packet_rate is defined per 10s window in fleet emulator
        pkts_per_sec = max(1.0, spec.normal_packet_rate / 10.0)
        pkt_ceiling = max(15.0, pkts_per_sec * 3.5)
        max_payload = spec.normal_byte_range[1] if spec.normal_byte_range else 500
        byte_ceiling = max(10000.0, pkt_ceiling * max_payload * 3.5)

        ports = set(PROTOCOL_DEFAULT_PORTS.get(spec.primary_protocol.upper(), {80, 443}))
        ports.update({53, 123})  # Standard DNS and NTP

        return cls(
            device_id=spec.id,
            allowed_destinations=set(spec.normal_destinations),
            allowed_ports=ports,
            max_packet_rate=pkt_ceiling,
            max_byte_rate=byte_ceiling,
        )

    def score_summary(self, summary: FlowSummary) -> tuple[float, list[str]]:
        """
        Evaluate a flow summary against static allowlists and ceilings.
        Returns:
            threat_score: float in [0.0, 100.0]
            violations: list of descriptive rule violation messages
        """
        violations: list[str] = []
        score = 0.0

        pkts = summary.packets
        n_pkts = len(pkts)
        duration = max(0.001, summary.duration)

        # 1. Destination IP verification
        dst_ips = {p.dst_ip for p in pkts}
        for dst in dst_ips:
            # Allow local subnet communications
            if not dst.startswith("192.168.1.") and dst not in self.allowed_destinations:
                violations.append(f"Unauthorized external destination: {dst}")
                score += 45.0

        # 2. Port verification
        dst_ports = {p.dst_port for p in pkts}
        for port in dst_ports:
            if port not in self.allowed_ports:
                if port in HIGH_RISK_PORTS:
                    violations.append(f"High-risk unauthorized destination port: {port}")
                    score += 55.0
                else:
                    violations.append(f"Unauthorized destination port: {port}")
                    score += 35.0

        # 3. Rate ceilings
        pkt_rate = n_pkts / duration
        if pkt_rate > self.max_packet_rate:
            ratio = pkt_rate / max(1.0, self.max_packet_rate)
            violations.append(
                f"Packet rate ceiling exceeded: {pkt_rate:.1f} pkts/s (ceiling {self.max_packet_rate:.1f})"
            )
            score += min(50.0, 25.0 * ratio)

        total_bytes = sum(p.length for p in pkts)
        byte_rate = total_bytes / duration
        if byte_rate > self.max_byte_rate:
            ratio = byte_rate / max(1.0, self.max_byte_rate)
            violations.append(
                f"Byte rate ceiling exceeded: {byte_rate:.1f} B/s (ceiling {self.max_byte_rate:.1f})"
            )
            score += min(50.0, 25.0 * ratio)

        return min(100.0, float(score)), violations


class PooledIsolationForestBaseline:
    """
    Fleet-wide Pooled Anomaly Detector (literature baseline).
    Trained on the pooled feature distributions of all devices without per-device separation.
    """

    def __init__(self, n_estimators: int = 100, seed: int = 42) -> None:
        self.n_estimators = n_estimators
        self.seed = seed
        self.model = IsolationForestDetector(n_estimators=n_estimators, random_seed=seed)

    @property
    def is_trained(self) -> bool:
        return self.model.is_trained

    def fit(self, pooled_samples: Sequence[Sequence[float]]) -> None:
        arr = np.asarray(pooled_samples, dtype=float)
        self.model.fit(arr, device_id="pooled_fleet_model")

    def score_sample(self, vec: np.ndarray) -> tuple[float, dict[str, float]]:
        return self.model.score_sample(vec)


class RobustZScoreOnlyBaseline:
    """
    Statistical Detector Baseline (Layer 1 ablation).
    Evaluates observed features purely using statistical z-scores without Isolation Forest.
    """

    def __init__(self, baseline_profile: StatisticalBaseline) -> None:
        self.baseline = baseline_profile

    def score_features(self, features: dict[str, float]) -> float:
        """Compute statistical deviation score mapped to [0.0, 100.0]."""
        base_score, deviations = self.baseline.evaluate(features)

        # Check all features present in both input and baseline profile
        max_abs_z = 0.0
        for k, v in features.items():
            if k in self.baseline.means:
                mean_val = self.baseline.means[k]
                std_val = max(1e-6, self.baseline.stds.get(k, 1.0))
                z = abs(v - mean_val) / std_val
                max_abs_z = max(max_abs_z, z)

        if deviations:
            max_dev_z = max(abs(d.z_score) for d in deviations)
            max_abs_z = max(max_abs_z, max_dev_z)

        if max_abs_z >= self.baseline.z_threshold:
            z_mapped = float(min(100.0, 100.0 / (1.0 + np.exp(-0.8 * (max_abs_z - 3.0)))))
            return max(base_score * 100.0, z_mapped)
        return float(base_score * 100.0)


@dataclass
class DestinationAllowlistOnlyBaseline:
    """
    Destination Allowlist Baseline (Layer 2 ablation).
    Flags any packet directed to an unauthorized non-local external IP destination.
    Simulates simple perimeter allowlisting without ML or volumetric baselines.
    """

    device_id: str
    allowed_destinations: set[str] = field(default_factory=set)

    @classmethod
    def from_device_spec(cls, spec: IoTDeviceSpec) -> "DestinationAllowlistOnlyBaseline":
        return cls(
            device_id=spec.id,
            allowed_destinations=set(spec.normal_destinations),
        )

    def score_summary(self, summary: FlowSummary) -> tuple[float, list[str]]:
        violations: list[str] = []
        for p in summary.packets:
            if not p.dst_ip.startswith("192.168.1.") and p.dst_ip not in self.allowed_destinations:
                violations.append(f"Unauthorized external destination: {p.dst_ip}")
        score = 100.0 if violations else 0.0
        return score, violations


class PerDeviceIsolationForestBaseline:
    """
    Per-device Isolation Forest Baseline (ML-only detector).
    Evaluates observed feature vector using device-specific Isolation Forest without statistical Layer 1.
    """

    def __init__(self, model: IsolationForestDetector) -> None:
        self.model = model

    def score_sample(self, vec: np.ndarray) -> tuple[float, dict[str, float]]:
        return self.model.score_sample(vec)


class LocalOutlierFactorBaseline:
    """
    Local Outlier Factor (LOF) Baseline.
    Pure NumPy implementation of density-based local outlier factor.
    Computes k-distance, reachability distance, and local reachability density.
    Scores mapped to [0.0, 100.0] threat scale.
    """

    def __init__(self, k_neighbors: int = 5) -> None:
        self.k_neighbors = k_neighbors
        self.X_train: np.ndarray | None = None
        self.is_fitted: bool = False
        self._lrd_train: np.ndarray | None = None

    def fit(self, X: np.ndarray | Sequence[Sequence[float]]) -> None:
        self.X_train = np.asarray(X, dtype=float)
        n_samples = len(self.X_train)
        if n_samples < 2:
            raise ValueError("LOF requires at least 2 training samples.")
        self.k = min(self.k_neighbors, n_samples - 1)
        self.is_fitted = True

        # Precompute pairwise Euclidean distances
        dists = np.linalg.norm(self.X_train[:, None, :] - self.X_train[None, :, :], axis=-1)
        np.fill_diagonal(dists, np.inf)

        # k-distance for each train sample
        sorted_dists = np.sort(dists, axis=1)
        self.k_dists = sorted_dists[:, self.k - 1]

        # local reachability density for train samples
        lrds = []
        for i in range(n_samples):
            neighbor_indices = np.argsort(dists[i])[: self.k]
            reach_dists = np.maximum(self.k_dists[neighbor_indices], dists[i, neighbor_indices])
            avg_reach = float(np.mean(reach_dists))
            lrd = 1.0 / max(1e-6, avg_reach)
            lrds.append(lrd)
        self._lrd_train = np.array(lrds)

    def score_sample(self, x: np.ndarray) -> float:
        """
        Compute LOF anomaly score mapped to [0.0, 100.0].
        LOF ~ 1 indicates in-distribution; LOF > 1.5 indicates an outlier.
        """
        if not self.is_fitted or self.X_train is None or self._lrd_train is None:
            return 0.0

        x_vec = np.asarray(x, dtype=float).reshape(1, -1)
        dists_to_train = np.linalg.norm(self.X_train - x_vec, axis=1)
        neighbor_indices = np.argsort(dists_to_train)[: self.k]
        neighbor_dists = dists_to_train[neighbor_indices]

        # reachability distance from x to neighbors
        reach_dists = np.maximum(self.k_dists[neighbor_indices], neighbor_dists)
        avg_reach = float(np.mean(reach_dists))
        lrd_x = 1.0 / max(1e-6, avg_reach)

        # LOF(x) = mean(lrd(neighbors)) / lrd(x)
        neighbor_lrds = self._lrd_train[neighbor_indices]
        lof_ratio = float(np.mean(neighbor_lrds) / max(1e-6, lrd_x))

        # Map LOF ratio: 1.0 -> 20.0, 1.5 -> 60.0, >= 2.0 -> 90.0+
        if lof_ratio <= 1.0:
            return float(max(0.0, lof_ratio * 20.0))
        # Sigmoid curve above 1.0
        score = 20.0 + 80.0 * (1.0 - np.exp(-1.8 * (lof_ratio - 1.0)))
        return float(min(100.0, max(0.0, score)))

