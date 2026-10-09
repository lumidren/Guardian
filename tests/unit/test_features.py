"""Unit tests for src/guardian/features module."""

import time

from guardian.capture.flow_tracker import FlowSummary
from guardian.capture.packet_parser import ParsedPacket
from guardian.config import FEATURE_NAMES
from guardian.features.definitions import FEATURE_REGISTRY, LayerType
from guardian.features.extractor import FeatureExtractor
from guardian.features.normalization import FeatureNormalizer, StreamingNormalizer


def test_feature_registry_completeness() -> None:
    assert len(FEATURE_REGISTRY) == 60
    assert len(FEATURE_NAMES) == 60
    for name in FEATURE_NAMES:
        assert name in FEATURE_REGISTRY
        meta = FEATURE_REGISTRY[name]
        assert meta.name == name
        assert isinstance(meta.layer, LayerType)


def test_feature_extractor_returns_all_60_features() -> None:
    now = time.time()
    pkts = [
        ParsedPacket(
            timestamp=now + (i * 0.2),
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            src_port=50000 + i,
            dst_port=443,
            protocol="TCP",
            length=120,
            is_outbound=True,
            app_protocol="HTTPS",
        )
        for i in range(10)
    ]
    summary = FlowSummary(
        device_id="192.168.1.10",
        window_start=now,
        window_end=now + 2.0,
        duration=2.0,
        packets=pkts,
        known_destinations={"8.8.8.8"},
    )
    extractor = FeatureExtractor()
    features = extractor.extract(summary)
    assert len(features) == 60
    for name in FEATURE_NAMES:
        assert name in features
        assert isinstance(features[name], float)
    assert features["pkt_count_10s"] == 10.0
    assert features["byte_count_10s"] == 1200.0


def test_streaming_normalizer_welford_update() -> None:
    normalizer = StreamingNormalizer()
    assert normalizer is not None
    features = {name: 10.0 for name in FEATURE_NAMES}
    normalizer.update(features)
    assert normalizer.counts[FEATURE_NAMES[0]] == 1

    features2 = {name: 20.0 for name in FEATURE_NAMES}
    normalizer.update(features2)
    assert normalizer.counts[FEATURE_NAMES[0]] == 2
    assert normalizer.means[FEATURE_NAMES[0]] == 15.0

    transformed = normalizer.transform({name: 15.0 for name in FEATURE_NAMES})
    assert len(transformed) == 60
    # At mean, normalized value should be approximately 0.0
    assert abs(transformed[FEATURE_NAMES[0]]) < 1e-4

    # Backward compatibility alias test
    alias_inst = FeatureNormalizer()
    assert isinstance(alias_inst, StreamingNormalizer)
