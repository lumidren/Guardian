"""
Empirical System Measurement and Scalability Benchmark Module (Milestone P2-6).

Measures real runtime metrics to eliminate unmeasured literals (fixing F2, F3, F4, F12):
1. psutil CPU and Memory RSS measurements with computed PASS/FAIL gates (F2).
2. Scalability benchmarks across 8, 12, 16, and 20 devices (F3).
3. Fair device iteration across trial loops (F4).
4. Three distinct latency measurements: compute latency, time-to-detect, enforcement latency (F12).
"""

import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np
import psutil

from simulation.fleet_emulator import DEFAULT_FLEET_SPECS, IoTDeviceSpec

from ..capture.flow_tracker import FlowTracker
from ..enforcement.controller import EnforcementController
from ..features.extractor import FeatureExtractor
from ..ml.isolation_forest import IsolationForestDetector
from ..ml.statistical_baseline import StatisticalBaseline
from ..ml.threat_scorer import ThreatScorer
from .scenario import GroundTruthEpisode, ScenarioBuilder


def generate_scaled_fleet(target_count: int) -> list[IoTDeviceSpec]:
    """
    Generate fleet specifications scaled to target device count (e.g. 8, 12, 16, 20).
    Guarantees unique IDs, IP addresses, and MAC addresses.
    """
    if target_count <= len(DEFAULT_FLEET_SPECS):
        return [
            IoTDeviceSpec(
                id=d.id,
                name=d.name,
                device_type=d.device_type,
                ip_address=d.ip_address,
                mac_address=d.mac_address,
                hardware=d.hardware,
                primary_protocol=d.primary_protocol,
                normal_destinations=list(d.normal_destinations),
                normal_packet_rate=d.normal_packet_rate,
                normal_byte_range=d.normal_byte_range,
                active_hours_range=d.active_hours_range,
            )
            for d in DEFAULT_FLEET_SPECS[:target_count]
        ]

    fleet: list[IoTDeviceSpec] = [
        IoTDeviceSpec(
            id=d.id,
            name=d.name,
            device_type=d.device_type,
            ip_address=d.ip_address,
            mac_address=d.mac_address,
            hardware=d.hardware,
            primary_protocol=d.primary_protocol,
            normal_destinations=list(d.normal_destinations),
            normal_packet_rate=d.normal_packet_rate,
            normal_byte_range=d.normal_byte_range,
            active_hours_range=d.active_hours_range,
        )
        for d in DEFAULT_FLEET_SPECS
    ]

    for i in range(len(DEFAULT_FLEET_SPECS), target_count):
        template = DEFAULT_FLEET_SPECS[i % len(DEFAULT_FLEET_SPECS)]
        d_id = f"dev_{i + 1:02d}_{template.device_type.lower().replace(' ', '_')}"
        d_name = f"{template.name} ({i + 1})"
        d_ip = f"192.168.1.{101 + i}"
        d_mac = f"30:AE:A4:00:{(i // 256):02X}:{(i % 256):02X}"

        fleet.append(
            IoTDeviceSpec(
                id=d_id,
                name=d_name,
                device_type=template.device_type,
                ip_address=d_ip,
                mac_address=d_mac,
                hardware=template.hardware,
                primary_protocol=template.primary_protocol,
                normal_destinations=list(template.normal_destinations),
                normal_packet_rate=template.normal_packet_rate,
                normal_byte_range=template.normal_byte_range,
                active_hours_range=template.active_hours_range,
            )
        )

    return fleet


@dataclass(frozen=True)
class SystemResourceReport:
    cpu_percent_avg: float
    cpu_percent_peak: float
    memory_rss_mb_avg: float
    memory_rss_mb_peak: float
    duration_seconds: float
    cpu_status: str
    memory_status: str
    overall_status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cpu_percent_avg": round(self.cpu_percent_avg, 2),
            "cpu_percent_peak": round(self.cpu_percent_peak, 2),
            "memory_rss_mb_avg": round(self.memory_rss_mb_avg, 2),
            "memory_rss_mb_peak": round(self.memory_rss_mb_peak, 2),
            "duration_seconds": round(self.duration_seconds, 2),
            "cpu_status": self.cpu_status,
            "memory_status": self.memory_status,
            "overall_status": self.overall_status,
        }


class SystemResourceBenchmark:
    """Measures real CPU and memory resource consumption via psutil."""

    def __init__(self, target_cpu_max: float = 25.0, target_mem_max_mb: float = 256.0) -> None:
        self.target_cpu_max = target_cpu_max
        self.target_mem_max_mb = target_mem_max_mb
        self.proc = psutil.Process()

    def measure_pipeline_run(
        self,
        devices: Sequence[IoTDeviceSpec],
        duration_seconds: float = 5.0,
    ) -> SystemResourceReport:
        extractor = FeatureExtractor()
        threat_scorer = ThreatScorer()
        enforcer = EnforcementController()

        # Warm up process CPU counter
        self.proc.cpu_percent()

        cpu_samples: list[float] = []
        mem_samples: list[float] = []

        scenario_builder = ScenarioBuilder(seed=42, total_days=1, devices=devices)
        t_start = time.perf_counter()

        # Execute realistic pipeline load across devices
        for dev in devices:
            windows = scenario_builder.generate_device_stream_windows(
                device_id=dev.id,
                start_time=0.0,
                end_time=max(20.0, duration_seconds),
                episodes=[],
            )
            tracker = FlowTracker()
            model = IsolationForestDetector(n_estimators=10)
            model.fit(np.zeros((5, 60)), device_id=dev.id)
            baseline = StatisticalBaseline()
            baseline.is_ready = True

            for w in windows:
                for p in w.packets:
                    tracker.ingest_packet(p)
                summary = tracker.get_window_summary(dev.ip_address)
                if summary:
                    features = extractor.extract(summary)
                    vec = extractor.extract_vector(summary)
                    ml_s, _ = model.score_sample(vec)
                    st_s, _ = baseline.evaluate(features)
                    assessment = threat_scorer.assess(ml_s, st_s, features)
                    enforcer.enforce(dev.id, dev.ip_address, assessment)

            # Sample OS process metrics
            mem_mb = self.proc.memory_info().rss / (1024.0 * 1024.0)
            mem_samples.append(mem_mb)
            cpu_val = self.proc.cpu_percent()
            cpu_samples.append(cpu_val)

        elapsed = time.perf_counter() - t_start

        avg_cpu = float(np.mean(cpu_samples)) if cpu_samples else 0.0
        peak_cpu = float(np.max(cpu_samples)) if cpu_samples else 0.0
        avg_mem = float(np.mean(mem_samples)) if mem_samples else 0.0
        peak_mem = float(np.max(mem_samples)) if mem_samples else 0.0

        cpu_ok = avg_cpu < self.target_cpu_max
        mem_ok = peak_mem < self.target_mem_max_mb

        return SystemResourceReport(
            cpu_percent_avg=avg_cpu,
            cpu_percent_peak=peak_cpu,
            memory_rss_mb_avg=avg_mem,
            memory_rss_mb_peak=peak_mem,
            duration_seconds=elapsed,
            cpu_status="PASS" if cpu_ok else "FAIL",
            memory_status="PASS" if mem_ok else "FAIL",
            overall_status="PASS" if (cpu_ok and mem_ok) else "FAIL",
        )


@dataclass(frozen=True)
class LatencyReport:
    compute_latency_mean_ms: float
    compute_latency_p95_ms: float
    compute_latency_max_ms: float
    time_to_detect_mean_s: float | None
    time_to_detect_min_s: float | None
    time_to_detect_max_s: float | None
    enforcement_latency_mean_ms: float
    enforcement_latency_p95_ms: float
    enforcement_latency_max_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "compute_latency_ms": {
                "mean": round(self.compute_latency_mean_ms, 3),
                "p95": round(self.compute_latency_p95_ms, 3),
                "max": round(self.compute_latency_max_ms, 3),
            },
            "time_to_detect_s": {
                "mean": round(self.time_to_detect_mean_s, 2)
                if self.time_to_detect_mean_s is not None
                else None,
                "min": round(self.time_to_detect_min_s, 2)
                if self.time_to_detect_min_s is not None
                else None,
                "max": round(self.time_to_detect_max_s, 2)
                if self.time_to_detect_max_s is not None
                else None,
            },
            "enforcement_latency_ms": {
                "mean": round(self.enforcement_latency_mean_ms, 3),
                "p95": round(self.enforcement_latency_p95_ms, 3),
                "max": round(self.enforcement_latency_max_ms, 3),
            },
        }


class LatencyBenchmark:
    """Measures compute, time-to-detect, and enforcement latencies."""

    def measure_latencies(
        self,
        devices: Sequence[IoTDeviceSpec],
        episodes: Sequence[GroundTruthEpisode],
        start_time: float = 0.0,
        end_time: float = 60.0,
    ) -> LatencyReport:
        extractor = FeatureExtractor()
        threat_scorer = ThreatScorer()
        enforcer = EnforcementController()
        scenario_builder = ScenarioBuilder(seed=42, total_days=1, devices=devices)

        compute_latencies_ms: list[float] = []
        enforcement_latencies_ms: list[float] = []
        time_to_detect_s: list[float] = []

        ep_detected: dict[str, bool] = {e.episode_id: False for e in episodes}

        for dev in devices:
            windows = scenario_builder.generate_device_stream_windows(
                device_id=dev.id,
                start_time=start_time,
                end_time=end_time,
                episodes=episodes,
            )
            tracker = FlowTracker()
            model = IsolationForestDetector(n_estimators=10)
            model.fit(np.zeros((5, 60)), device_id=dev.id)
            baseline = StatisticalBaseline()
            baseline.is_ready = True

            for w in windows:
                for p in w.packets:
                    tracker.ingest_packet(p)
                summary = tracker.get_window_summary(dev.ip_address)
                if not summary:
                    continue

                # Measure 1: Compute Latency (feature extraction + scoring)
                t0 = time.perf_counter()
                features = extractor.extract(summary)
                vec = extractor.extract_vector(summary)
                ml_s, _ = model.score_sample(vec)
                st_s, _ = baseline.evaluate(features)
                assessment = threat_scorer.assess(ml_s, st_s, features)
                comp_ms = (time.perf_counter() - t0) * 1000.0
                compute_latencies_ms.append(comp_ms)

                # Measure 2: Enforcement Latency
                t_enf0 = time.perf_counter()
                state = enforcer.enforce(dev.id, dev.ip_address, assessment)
                enf_ms = (time.perf_counter() - t_enf0) * 1000.0
                enforcement_latencies_ms.append(max(enf_ms, state.enforcement_latency_ms))

                # Measure 3: Time-to-detect from attack onset
                if w.active_episode_ids:
                    for ep_id in w.active_episode_ids:
                        if assessment.threat_score >= 60 and not ep_detected[ep_id]:
                            ep_obj = next((e for e in episodes if e.episode_id == ep_id), None)
                            if ep_obj:
                                ep_detected[ep_id] = True
                                ttd = max(0.0, w.start_time - ep_obj.start_time)
                                time_to_detect_s.append(ttd)

        c_mean = float(np.mean(compute_latencies_ms)) if compute_latencies_ms else 0.0
        c_p95 = float(np.percentile(compute_latencies_ms, 95)) if compute_latencies_ms else 0.0
        c_max = float(np.max(compute_latencies_ms)) if compute_latencies_ms else 0.0

        enf_mean = float(np.mean(enforcement_latencies_ms)) if enforcement_latencies_ms else 0.0
        enf_p95 = float(np.percentile(enforcement_latencies_ms, 95)) if enforcement_latencies_ms else 0.0
        enf_max = float(np.max(enforcement_latencies_ms)) if enforcement_latencies_ms else 0.0

        ttd_mean = float(np.mean(time_to_detect_s)) if time_to_detect_s else None
        ttd_min = float(np.min(time_to_detect_s)) if time_to_detect_s else None
        ttd_max = float(np.max(time_to_detect_s)) if time_to_detect_s else None

        return LatencyReport(
            compute_latency_mean_ms=c_mean,
            compute_latency_p95_ms=c_p95,
            compute_latency_max_ms=c_max,
            time_to_detect_mean_s=ttd_mean,
            time_to_detect_min_s=ttd_min,
            time_to_detect_max_s=ttd_max,
            enforcement_latency_mean_ms=enf_mean,
            enforcement_latency_p95_ms=enf_p95,
            enforcement_latency_max_ms=enf_max,
        )


@dataclass(frozen=True)
class ScalabilityPoint:
    device_count: int
    throughput_windows_per_sec: float
    compute_latency_ms: float
    cpu_percent: float
    memory_rss_mb: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_count": self.device_count,
            "throughput_windows_per_sec": round(self.throughput_windows_per_sec, 2),
            "compute_latency_ms": round(self.compute_latency_ms, 3),
            "cpu_percent": round(self.cpu_percent, 2),
            "memory_rss_mb": round(self.memory_rss_mb, 2),
        }


@dataclass(frozen=True)
class ScalabilityReport:
    points: list[ScalabilityPoint]

    def to_dict(self) -> dict[str, Any]:
        return {"points": [p.to_dict() for p in self.points]}


class ScalabilityBenchmark:
    """Executes empirical fleet scalability benchmarks across 8, 12, 16, 20 devices."""

    def __init__(self, device_counts: Sequence[int] | None = None) -> None:
        self.device_counts = list(device_counts or [8, 12, 16, 20])
        self.proc = psutil.Process()

    def run_scalability_sweep(self, duration_per_tier_s: float = 5.0) -> ScalabilityReport:
        points: list[ScalabilityPoint] = []
        extractor = FeatureExtractor()
        threat_scorer = ThreatScorer()
        enforcer = EnforcementController()

        for count in self.device_counts:
            fleet = generate_scaled_fleet(count)
            scenario_builder = ScenarioBuilder(seed=42, total_days=1, devices=fleet)

            # Concurrent multi-device tracking state
            trackers = {d.id: FlowTracker() for d in fleet}
            models: dict[str, IsolationForestDetector] = {}
            baselines: dict[str, StatisticalBaseline] = {}
            for d in fleet:
                m = IsolationForestDetector(n_estimators=10)
                m.fit(np.zeros((5, 60)), device_id=d.id)
                models[d.id] = m
                b = StatisticalBaseline()
                b.is_ready = True
                baselines[d.id] = b

            # Generate windows across all devices
            dev_windows: dict[str, list[Any]] = {}
            for dev in fleet:
                dev_windows[dev.id] = scenario_builder.generate_device_stream_windows(
                    device_id=dev.id,
                    start_time=0.0,
                    end_time=max(20.0, duration_per_tier_s),
                    episodes=[],
                )

            t0_wall = time.perf_counter()
            t0_cpu = self.proc.cpu_times()

            total_windows = 0
            latencies_ms: list[float] = []

            # Realistic interleaved processing across devices concurrently
            max_w_len = max((len(w_list) for w_list in dev_windows.values()), default=0)
            for w_idx in range(max_w_len):
                for dev in fleet:
                    w_list = dev_windows[dev.id]
                    if w_idx >= len(w_list):
                        continue
                    w = w_list[w_idx]
                    total_windows += 1
                    trk = trackers[dev.id]
                    for p in w.packets:
                        trk.ingest_packet(p)
                    summary = trk.get_window_summary(dev.ip_address)
                    if summary:
                        t0 = time.perf_counter()
                        features = extractor.extract(summary)
                        vec = extractor.extract_vector(summary)
                        ml_s, _ = models[dev.id].score_sample(vec)
                        st_s, _ = baselines[dev.id].evaluate(features)
                        assessment = threat_scorer.assess(ml_s, st_s, features)
                        enforcer.enforce(dev.id, dev.ip_address, assessment)
                        latencies_ms.append((time.perf_counter() - t0) * 1000.0)

            t1_wall = time.perf_counter()
            t1_cpu = self.proc.cpu_times()
            wall_delta = max(0.001, t1_wall - t0_wall)
            cpu_time = (t1_cpu.user - t0_cpu.user) + (t1_cpu.system - t0_cpu.system)
            cpu_pct = max(1.5, (cpu_time / wall_delta) * 100.0)
            mem_mb = self.proc.memory_info().rss / (1024.0 * 1024.0)

            throughput = total_windows / wall_delta
            avg_lat = float(np.mean(latencies_ms)) if latencies_ms else 0.0

            points.append(
                ScalabilityPoint(
                    device_count=count,
                    throughput_windows_per_sec=throughput,
                    compute_latency_ms=avg_lat,
                    cpu_percent=cpu_pct,
                    memory_rss_mb=mem_mb,
                )
            )

        return ScalabilityReport(points=points)


@dataclass(frozen=True)
class LoadTestReport:
    device_count: int
    duration_seconds: float
    total_packets_offered: int
    total_packets_processed: int
    total_packets_dropped: int
    packet_drop_rate_pct: float
    peak_queue_depth: int
    queue_capacity: int
    throughput_pps: float
    cpu_percent_avg: float
    memory_rss_mb: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_count": self.device_count,
            "duration_seconds": round(self.duration_seconds, 2),
            "total_packets_offered": self.total_packets_offered,
            "total_packets_processed": self.total_packets_processed,
            "total_packets_dropped": self.total_packets_dropped,
            "packet_drop_rate_pct": round(self.packet_drop_rate_pct, 2),
            "peak_queue_depth": self.peak_queue_depth,
            "queue_capacity": self.queue_capacity,
            "throughput_pps": round(self.throughput_pps, 2),
            "cpu_percent_avg": round(self.cpu_percent_avg, 2),
            "memory_rss_mb": round(self.memory_rss_mb, 2),
        }


class RealTimeLoadBenchmark:
    """
    Real-time packet stream replay with bounded ring buffer and drop counters (Milestone P3-6).
    Simulates high network interface ingestion load and buffer saturation under DDoS.
    """

    def __init__(self, queue_capacity: int = 5000, processing_rate_pps: float = 20000.0) -> None:
        self.queue_capacity = queue_capacity
        self.processing_rate_pps = processing_rate_pps
        self.proc = psutil.Process()

    def run_load_test(
        self,
        devices: Sequence[IoTDeviceSpec],
        duration_seconds: float = 5.0,
        burst_factor: float = 1.0,
    ) -> LoadTestReport:
        from copy import copy

        scenario_builder = ScenarioBuilder(seed=42, total_days=1, devices=devices)
        all_packets: list[Any] = []
        for dev in devices:
            windows = scenario_builder.generate_device_stream_windows(
                device_id=dev.id,
                start_time=0.0,
                end_time=max(20.0, duration_seconds),
                episodes=[],
            )
            for w in windows:
                all_packets.extend(w.packets)

        # Apply burst replication if requested (e.g. simulating volumetric DDoS)
        if burst_factor > 1.0:
            burst_int = int(burst_factor)
            replicated: list[Any] = []
            for p in all_packets:
                replicated.append(p)
                for b_idx in range(1, burst_int):
                    p_copy = copy(p)
                    p_copy.timestamp = p.timestamp + (b_idx * 0.0001)
                    replicated.append(p_copy)
            all_packets = replicated

        # Order packets strictly by arrival timestamp
        all_packets.sort(key=lambda p: p.timestamp)

        total_offered = len(all_packets)
        total_dropped = 0
        total_processed = 0
        peak_queue = 0
        queue: list[Any] = []

        trackers = {d.ip_address: FlowTracker() for d in devices}

        t0_wall = time.perf_counter()
        t0_cpu = self.proc.cpu_times()

        if not all_packets:
            return LoadTestReport(
                device_count=len(devices),
                duration_seconds=duration_seconds,
                total_packets_offered=0,
                total_packets_processed=0,
                total_packets_dropped=0,
                packet_drop_rate_pct=0.0,
                peak_queue_depth=0,
                queue_capacity=self.queue_capacity,
                throughput_pps=0.0,
                cpu_percent_avg=0.0,
                memory_rss_mb=self.proc.memory_info().rss / (1024.0 * 1024.0),
            )

        t_min = all_packets[0].timestamp
        t_max = all_packets[-1].timestamp
        time_span = max(0.01, t_max - t_min)
        dt = 0.05  # 50 ms time step
        steps = max(1, int(time_span / dt))
        pkt_idx = 0

        for step in range(steps + 1):
            curr_t = t_min + (step * dt)
            # 1. Enqueue arriving packets up to curr_t
            while pkt_idx < total_offered and all_packets[pkt_idx].timestamp <= curr_t:
                pkt = all_packets[pkt_idx]
                pkt_idx += 1
                if len(queue) < self.queue_capacity:
                    queue.append(pkt)
                    if len(queue) > peak_queue:
                        peak_queue = len(queue)
                else:
                    total_dropped += 1

            # 2. Process up to service capacity for this time step
            capacity = max(1, int(self.processing_rate_pps * dt))
            to_process = min(len(queue), capacity)
            for _ in range(to_process):
                p = queue.pop(0)
                trk = trackers.get(p.src_ip)
                if trk:
                    trk.ingest_packet(p)
                total_processed += 1

        # Drain any remaining packets in queue up to capacity
        while queue:
            p = queue.pop(0)
            trk = trackers.get(p.src_ip)
            if trk:
                trk.ingest_packet(p)
            total_processed += 1

        # Ensure any remaining offered packets in stream not reached by time slicing are accounted for
        while pkt_idx < total_offered:
            if len(queue) < self.queue_capacity:
                total_processed += 1
            else:
                total_dropped += 1
            pkt_idx += 1

        t1_wall = time.perf_counter()
        t1_cpu = self.proc.cpu_times()
        wall_delta = max(0.001, t1_wall - t0_wall)
        cpu_time = (t1_cpu.user - t0_cpu.user) + (t1_cpu.system - t0_cpu.system)
        cpu_pct = max(1.0, (cpu_time / wall_delta) * 100.0)
        mem_rss = self.proc.memory_info().rss / (1024.0 * 1024.0)

        throughput_pps = total_processed / wall_delta
        drop_rate = (total_dropped / total_offered * 100.0) if total_offered > 0 else 0.0

        return LoadTestReport(
            device_count=len(devices),
            duration_seconds=wall_delta,
            total_packets_offered=total_offered,
            total_packets_processed=total_processed,
            total_packets_dropped=total_dropped,
            packet_drop_rate_pct=drop_rate,
            peak_queue_depth=peak_queue,
            queue_capacity=self.queue_capacity,
            throughput_pps=throughput_pps,
            cpu_percent_avg=cpu_pct,
            memory_rss_mb=mem_rss,
        )
