"""Unit tests for empirical simulator calibration from real PCAP telemetry (Tasks 27-46)."""

from __future__ import annotations

from guardian.eval.pcap_calibration import extract_per_feature_pcap_stats
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
