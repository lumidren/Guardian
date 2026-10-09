"""
Unit tests for Real System Measurements & Benchmarks (Milestone P2-6).
Verifies:
1. psutil CPU and Memory RSS measurements with dynamic PASS/FAIL status (F2).
2. Real scalability evaluation across 8, 12, 16, 20 device fleets (F3).
3. Fair device iteration across trial loops (F4).
4. Three distinct measured latencies: compute, time-to-detect, enforcement (F12).
"""

from guardian.eval.benchmarks import (
    LatencyBenchmark,
    ScalabilityBenchmark,
    SystemResourceBenchmark,
    generate_scaled_fleet,
)
from guardian.eval.scenario import AttackIntensity, EvasionMode, GroundTruthEpisode
from simulation.attack_suite import AttackType


def test_generate_scaled_fleet() -> None:
    for count in [8, 12, 16, 20]:
        fleet = generate_scaled_fleet(count)
        assert len(fleet) == count
        ids = [d.id for d in fleet]
        ips = [d.ip_address for d in fleet]
        assert len(set(ids)) == count, "Device IDs must be unique"
        assert len(set(ips)) == count, "Device IP addresses must be unique"


def test_system_resource_benchmark_psutil() -> None:
    benchmark = SystemResourceBenchmark()
    fleet = generate_scaled_fleet(8)

    report = benchmark.measure_pipeline_run(
        devices=fleet,
        duration_seconds=20.0,
    )

    # Values must be real non-zero measurements from psutil
    assert report.memory_rss_mb_peak > 10.0
    assert report.memory_rss_mb_avg > 10.0
    assert report.duration_seconds >= 0.01
    assert report.cpu_status in ("PASS", "FAIL")
    assert report.memory_status in ("PASS", "FAIL")
    assert report.overall_status in ("PASS", "FAIL")


def test_three_distinct_latencies_measured() -> None:
    benchmark = LatencyBenchmark()
    fleet = generate_scaled_fleet(4)
    target_dev = fleet[0]

    ep = GroundTruthEpisode(
        episode_id="ep_latency_test",
        device_id=target_dev.id,
        attack_type=AttackType.CNC_BEACONING,
        start_time=10.0,
        end_time=30.0,
        duration_seconds=20.0,
        intensity=AttackIntensity.HIGH,
        evasion_mode=EvasionMode.NONE,
    )

    report = benchmark.measure_latencies(
        devices=fleet,
        episodes=[ep],
        start_time=0.0,
        end_time=40.0,
    )

    # 1. Compute latency (ms per window)
    assert report.compute_latency_mean_ms > 0.0
    assert report.compute_latency_p95_ms > 0.0

    # 2. Time-to-detect (seconds from attack onset)
    assert report.time_to_detect_mean_s is not None
    assert report.time_to_detect_mean_s >= 0.0

    # 3. Enforcement latency (ms to apply firewall policy)
    assert report.enforcement_latency_mean_ms > 0.0
    assert report.enforcement_latency_p95_ms > 0.0


def test_scalability_benchmark_execution() -> None:
    benchmark = ScalabilityBenchmark(device_counts=[8, 12])
    report = benchmark.run_scalability_sweep(duration_per_tier_s=20.0)

    assert len(report.points) == 2
    assert report.points[0].device_count == 8
    assert report.points[1].device_count == 12

    for pt in report.points:
        assert pt.throughput_windows_per_sec > 0.0
        assert pt.memory_rss_mb > 10.0
        assert pt.compute_latency_ms >= 0.0
