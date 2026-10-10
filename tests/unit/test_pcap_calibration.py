"""Unit tests for empirical simulator calibration from real PCAP telemetry (Tasks 27-46)."""

from __future__ import annotations

from pathlib import Path

from guardian.eval.pcap_calibration import (
    extract_per_feature_pcap_stats,
    fit_bidirectional_ratio_model,
    fit_iat_micro_burst_model,
    fit_packet_size_mixture_model,
    fit_protocol_mix_per_device_type,
    fit_tcp_window_and_ttl_distributions,
)
from guardian.features.registry import FEATURE_NAMES


def test_extract_per_feature_pcap_stats() -> None:
    """Task 27: Verify per-feature stats extraction returns all 60 canonical features."""
    stats = extract_per_feature_pcap_stats()
    assert len(stats) == 60
    assert list(stats.keys()) == list(FEATURE_NAMES)
    pkt_cnt = stats["pkt_count_10s"]
    assert pkt_cnt.mean > 0.0
    assert pkt_cnt.std > 0.0
    assert pkt_cnt.p95 >= pkt_cnt.median
    assert pkt_cnt.nonzero_variance_both is True


def test_fit_packet_size_mixture_model() -> None:
    """Task 28: Verify bimodal packet-size mixture model fits ACK and payload modes."""
    import numpy as np

    model = fit_packet_size_mixture_model()
    assert 0.15 <= model.w_ack <= 0.85
    assert model.mu_payload > model.mu_ack
    assert model.max_bytes > model.min_bytes >= 40
    rng = np.random.default_rng(42)
    samples = [model.sample(rng) for _ in range(200)]
    assert min(samples) >= model.min_bytes
    assert max(samples) <= model.max_bytes
    assert np.std(samples) > 10.0


def test_fit_iat_micro_burst_model() -> None:
    """Task 29: Verify inter-arrival micro-burst model fits intra- and inter-burst regimes."""
    import numpy as np

    model = fit_iat_micro_burst_model()
    assert 0.3 <= model.p_intra_burst <= 0.9
    assert model.intra_mean_s >= model.intra_min_s > 0.0
    assert model.inter_mean_s > model.intra_mean_s
    rng = np.random.default_rng(42)
    ts = model.sample_timestamps(16, start_time=100.0, window_duration=10.0, rng=rng)
    assert len(ts) == 16
    assert ts == sorted(ts)
    assert 100.0 <= ts[0] <= ts[-1] <= 110.0


def test_fit_bidirectional_ratio_model() -> None:
    """Task 30: Verify bidirectional packet/byte ratio model sums to 1.0 and matches real PCAP."""
    import numpy as np

    model = fit_bidirectional_ratio_model()
    assert abs((model.upstream_pkt_ratio_mean + model.downstream_pkt_ratio_mean) - 1.0) < 1e-5
    assert abs((model.upstream_byte_ratio_mean + model.downstream_byte_ratio_mean) - 1.0) < 1e-5
    assert 0.35 <= model.upstream_pkt_ratio_mean <= 0.65
    rng = np.random.default_rng(42)
    flags = [model.sample_outbound_flag(rng) for _ in range(400)]
    assert 0.30 <= (sum(flags) / len(flags)) <= 0.70


def test_fit_tcp_window_and_ttl_distributions() -> None:
    """Task 31: Verify TCP window and TTL distributions match real PCAP stack telemetry."""
    import numpy as np

    model = fit_tcp_window_and_ttl_distributions()
    assert 1000.0 <= model.tcp_win_mean <= 65535.0
    assert model.outbound_ttl == 64
    assert 32 <= model.inbound_wan_ttl <= 255
    rng = np.random.default_rng(42)
    ttls = [model.sample_ttl(is_outbound=(i % 2 == 0), is_external=True) for i in range(100)]
    assert abs(float(np.var(ttls)) - model.ip_ttl_variance_target) < 50.0
    win = model.sample_tcp_window(is_outbound=True, rng=rng)
    assert 502 <= win <= 65535


def test_fit_protocol_mix_per_device_type() -> None:
    """Task 32: Verify protocol mix per device type sums to 1.0 and reflects real PCAP ratios."""
    mixes = fit_protocol_mix_per_device_type()
    assert "Smart Home Gateway" in mixes
    assert "Environmental Sensor" in mixes
    assert "Edge Compute" in mixes
    for dtype, mix in mixes.items():
        weights = mix.normalized_weights()
        assert abs(sum(weights.values()) - 1.0) < 1e-4, f"Weights for {dtype} do not sum to 1.0"
        assert weights["DNS"] > 0.0
        assert weights["NTP"] > 0.0


def test_bidirectional_traffic_generation() -> None:
    """Task 33: Verify calibrated bidirectional traffic generates both outbound and inbound responses."""
    from simulation.fleet_emulator import DEFAULT_FLEET_SPECS, IoTFleetEmulator

    emulator = IoTFleetEmulator()
    device = DEFAULT_FLEET_SPECS[0]
    pkts = emulator.generate_bidirectional_window_packets(device, current_time=1000.0)
    outbound = [p for p in pkts if p.is_outbound]
    inbound = [p for p in pkts if not p.is_outbound]
    assert len(outbound) > 0
    assert len(inbound) > 0
    assert all(p.src_ip == device.ip_address and p.ttl == 64 for p in outbound)
    assert all(p.dst_ip == device.ip_address and p.ttl == 171 for p in inbound)


def test_ack_psh_packet_patterns() -> None:
    """Task 34: Verify ACK/PSH packet pattern separates bare ACK control frames from PSH payload frames."""
    from simulation.fleet_emulator import DEFAULT_FLEET_SPECS, IoTFleetEmulator

    emulator = IoTFleetEmulator()
    device = DEFAULT_FLEET_SPECS[0]
    pkts = emulator.generate_bidirectional_window_packets(device, current_time=1000.0)
    psh_pkts = [p for p in pkts if p.tcp_flags.get("PSH")]
    ack_only = [p for p in pkts if not p.tcp_flags.get("PSH")]
    assert len(psh_pkts) > 0 and len(ack_only) > 0
    assert all(p.length >= 72 for p in psh_pkts)
    assert all(54 <= p.length <= 74 for p in ack_only)


def test_tls_keepalive_burst_model() -> None:
    """Task 35: Verify TLS keepalive burst model produces paired HTTPS request+ACK micro-bursts."""
    from simulation.fleet_emulator import DEFAULT_FLEET_SPECS, IoTFleetEmulator

    emulator = IoTFleetEmulator()
    device = DEFAULT_FLEET_SPECS[3]
    pkts = emulator.generate_tls_keepalive_burst_packets(device, current_time=1000.0)
    assert len(pkts) >= 4
    assert all(p.app_protocol == "HTTPS" for p in pkts)
    iats_ms = [(pkts[i].timestamp - pkts[i - 1].timestamp) * 1000.0 for i in range(1, len(pkts))]
    assert min(iats_ms) < 20.0
    assert max(iats_ms) > 250.0


def test_ephemeral_port_allocation() -> None:
    """Task 36: Verify persistent ephemeral port allocation keeps unique_dst_ports=2 across bidirectional flows."""
    from simulation.fleet_emulator import DEFAULT_FLEET_SPECS, IoTFleetEmulator

    emulator = IoTFleetEmulator()
    device = DEFAULT_FLEET_SPECS[0]
    w1 = emulator.generate_bidirectional_window_packets(device, current_time=1000.0)
    w2 = emulator.generate_bidirectional_window_packets(device, current_time=1010.0)
    dst_ports_w1 = {p.dst_port for p in w1}
    dst_ports_w2 = {p.dst_port for p in w2}
    assert len(dst_ports_w1) == 2
    assert dst_ports_w1 == dst_ports_w2
    rotated = emulator.port_allocator.rotate_port(device.id, device.normal_destinations[0], 1883)
    assert 49152 <= rotated <= 65535


def test_dns_and_ntp_background_chatter() -> None:
    """Task 37: Verify DNS and NTP background chatter generates bidirectional UDP/53 and UDP/123 pairs."""
    from simulation.fleet_emulator import DEFAULT_FLEET_SPECS, IoTFleetEmulator

    emulator = IoTFleetEmulator()
    device = DEFAULT_FLEET_SPECS[0]
    pkts = emulator.generate_dns_ntp_background_chatter(device, current_time=1000.0)
    dns_pkts = [p for p in pkts if p.app_protocol == "DNS"]
    ntp_pkts = [p for p in pkts if p.app_protocol == "NTP"]
    assert len(dns_pkts) == 2 and any(p.is_outbound for p in dns_pkts) and any(not p.is_outbound for p in dns_pkts)
    assert len(ntp_pkts) == 2 and any(p.is_outbound for p in ntp_pkts) and any(not p.is_outbound for p in ntp_pkts)
    assert all(p.protocol == "UDP" for p in pkts)


def test_per_device_type_parameter_files_from_calibration(tmp_path: Path) -> None:
    """Task 38: Verify per-device-type calibrated parameter files serialize all 5 fitted sub-models."""
    from guardian.eval.pcap_calibration import save_calibrated_device_type_profiles

    out_file = tmp_path / "calibrated_devices.json"
    payload = save_calibrated_device_type_profiles(out_file)
    assert out_file.exists()
    assert "Smart Home Gateway" in payload["device_types"]
    gw = payload["device_types"]["Smart Home Gateway"]
    for key in (
        "packet_size_model",
        "inter_arrival_model",
        "bidirectional_model",
        "tcp_window_ttl_model",
        "protocol_mix_model",
    ):
        assert key in gw


def test_ks_test_per_feature_vs_real_nonzero_variance_only() -> None:
    """Task 39: Verify KS and SMD evaluation runs strictly on nonzero-variance features and improves match rate."""
    from guardian.eval.pcap_calibration import compute_calibrated_ks_and_smd_report

    report = compute_calibrated_ks_and_smd_report(n_windows=250, seed=42)
    assert report["nonzero_variance_feature_count"] == 27
    assert report["excluded_zero_variance_count"] == 33
    assert len(report["features"]) == 27
    assert report["match_rate"] >= 0.85
    for fname, row in report["features"].items():
        assert row["real_std"] > 0.0, f"{fname} must have nonzero real variance"
        assert row["calibrated_sim_std"] > 0.0, f"{fname} must have nonzero calibrated sim variance"
        assert 0.0 <= row["ks_stat"] <= 1.0
