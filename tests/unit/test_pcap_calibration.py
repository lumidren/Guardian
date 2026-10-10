"""Unit tests for empirical simulator calibration from real PCAP telemetry (Tasks 27-46)."""

from __future__ import annotations

from guardian.eval.pcap_calibration import (
    extract_per_feature_pcap_stats,
    fit_bidirectional_ratio_model,
    fit_iat_micro_burst_model,
    fit_packet_size_mixture_model,
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
    assert 1000.0 <= model.tcp_win_mean <= 16384.0
    assert model.outbound_ttl == 64
    assert 40 <= model.inbound_wan_ttl < 64
    rng = np.random.default_rng(42)
    ttls = [model.sample_ttl(is_outbound=(i % 2 == 0), is_external=True) for i in range(100)]
    assert abs(float(np.var(ttls)) - model.ip_ttl_variance_target) < 5.0
    win = model.sample_tcp_window(is_outbound=True, rng=rng)
    assert 502 <= win <= 65535




