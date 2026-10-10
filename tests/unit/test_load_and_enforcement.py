"""
Unit tests for Real Load, Drop Counters, and Firewall Enforcement (Milestone P3-6).
Resolves Audit Finding G7:
- Real-time packet stream replay with drop counters and queue saturation under load.
- Scalability benchmark across 8, 12, 16, 20 devices with non-flat throughput and non-zero CPU.
- Transparent firewall enforcement benchmarking disaggregating in-memory vs kernel dispatch.
"""

from guardian.config import ThreatLevel
from guardian.enforcement.controller import EnforcementController
from guardian.enforcement.iptables_driver import LinuxIptablesDriver
from guardian.eval.benchmarks import (
    RealTimeLoadBenchmark,
    ScalabilityBenchmark,
    generate_scaled_fleet,
)
from guardian.ml.threat_scorer import ThreatAssessment


def test_real_time_load_benchmark_normal_load() -> None:
    """Under normal traffic load, all packets are processed with zero drops."""
    fleet = generate_scaled_fleet(4)
    benchmark = RealTimeLoadBenchmark(
        queue_capacity=5000,
        processing_rate_pps=20000.0,
    )

    report = benchmark.run_load_test(
        devices=fleet,
        duration_seconds=5.0,
        burst_factor=1.0,  # normal traffic
    )

    assert report.total_packets_offered > 0
    assert report.total_packets_processed > 0
    assert report.total_packets_dropped == 0
    assert report.packet_drop_rate_pct == 0.0
    assert report.total_packets_offered == report.total_packets_processed
    assert report.throughput_pps > 0.0
    assert report.peak_queue_depth <= report.queue_capacity


def test_real_time_load_benchmark_burst_drop_counters() -> None:
    """Under burst/DDoS load exceeding processing capacity, drop counters increment realistically."""
    fleet = generate_scaled_fleet(4)
    # Constrained queue and low processing rate to induce buffer saturation
    benchmark = RealTimeLoadBenchmark(
        queue_capacity=50,
        processing_rate_pps=500.0,
    )

    report = benchmark.run_load_test(
        devices=fleet,
        duration_seconds=5.0,
        burst_factor=50.0,  # heavy burst simulating DDoS
    )

    assert report.total_packets_offered > 0
    assert report.total_packets_dropped > 0
    assert report.packet_drop_rate_pct > 0.0
    # Accounting invariant: offered == processed + dropped
    assert report.total_packets_offered == report.total_packets_processed + report.total_packets_dropped
    assert report.peak_queue_depth == report.queue_capacity


def test_scalability_non_flat_and_nonzero_cpu() -> None:
    """Scalability sweep across fleet sizes must show non-flat throughput and non-zero CPU (fixing G7)."""
    benchmark = ScalabilityBenchmark(device_counts=[8, 12, 16, 20])
    report = benchmark.run_scalability_sweep(duration_per_tier_s=5.0)

    assert len(report.points) == 4
    counts = [p.device_count for p in report.points]
    assert counts == [8, 12, 16, 20]

    # CPU must be strictly non-zero across all tiers (fixing G7 where 8 devices had 0.0% CPU)
    for p in report.points:
        assert p.cpu_percent > 0.0, f"CPU was 0.0% for {p.device_count} devices (G7 violation)"
        assert p.memory_rss_mb > 10.0, f"Memory RSS implausible: {p.memory_rss_mb} MB"
        assert p.throughput_windows_per_sec > 0.0
        assert p.compute_latency_ms > 0.0

    # Throughput, CPU, or memory across device tiers must not be identical flat constants
    throughputs = [p.throughput_windows_per_sec for p in report.points]
    assert len(set(round(t, 1) for t in throughputs)) > 1, f"Throughput was flat: {throughputs}"
    cpus = [p.cpu_percent for p in report.points]
    mems = [p.memory_rss_mb for p in report.points]
    assert max(cpus) - min(cpus) > 1e-4 or max(mems) - min(mems) > 1e-4, "CPU and memory were completely flat"


def test_firewall_enforcement_latency_transparency() -> None:
    """Enforcement must distinguish in-memory table lookup from kernel command dispatch."""
    driver = LinuxIptablesDriver()
    latencies = driver.measure_enforcement_latency("192.168.1.101", ThreatLevel.QUARANTINE)

    assert "in_memory_ms" in latencies
    assert "dispatch_ms" in latencies
    assert "total_ms" in latencies

    # In-memory table lookup is fast (< 1.0 ms)
    assert latencies["in_memory_ms"] < 1.0
    # Kernel dispatch overhead is measured realistically (>= 0.5 ms)
    assert latencies["dispatch_ms"] >= 0.5
    # Total latency must be greater than in-memory latency alone
    assert latencies["total_ms"] >= latencies["in_memory_ms"]

    controller = EnforcementController()
    assessment = ThreatAssessment(
        threat_score=75,
        threat_level=ThreatLevel.QUARANTINE,
        confidence_level="High (90-100%)",
        confidence_score=0.95,
        ml_score=0.85,
        statistical_score=0.70,
        layer_contributions={"layer_1": 40.0, "layer_2": 60.0},
    )
    state = controller.enforce("dev_test", "192.168.1.101", assessment)
    assert state.enforcement_latency_ms > 0.0


def test_real_time_load_sweep_8_to_32_devices() -> None:
    """
    Real-time load test across fleet sizes 8, 12, 16, 20, 32 must report CPU,
    p95 latency, and dropped windows per fleet size, not only offered packets.
    """
    benchmark = RealTimeLoadBenchmark(queue_capacity=5000, processing_rate_pps=20000.0)
    reports = benchmark.run_fleet_load_sweep(
        fleet_sizes=(8, 12, 16, 20, 32),
        duration_seconds=20.0,
        tick_deadline_ms=25.0,
    )

    assert [r.device_count for r in reports] == [8, 12, 16, 20, 32]
    for r in reports:
        d = r.to_dict()
        assert d["total_packets_offered"] > 0
        assert d["cpu_percent_avg"] > 0.0
        assert d["p95_latency_ms"] > 0.0
        assert d["windows_offered"] == r.device_count * 6
        assert d["windows_processed"] + d["dropped_windows"] == d["windows_offered"]

    # p95 latency and CPU must grow from 8 devices to 32 devices
    assert reports[-1].p95_latency_ms > reports[0].p95_latency_ms
    assert reports[-1].cpu_percent_avg >= reports[0].cpu_percent_avg
    assert reports[-1].dropped_windows >= reports[0].dropped_windows

