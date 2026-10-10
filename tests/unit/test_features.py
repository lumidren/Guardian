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


def test_registry_is_single_source_of_truth_for_readme_code_and_docs() -> None:
    from pathlib import Path

    from guardian.features.registry import (
        EXCLUDED_PAYLOAD_FEATURES,
        render_readme_feature_table,
    )
    from guardian.features.registry import (
        FEATURE_NAMES as REG_NAMES,
    )
    from guardian.features.registry import (
        FEATURE_REGISTRY as REG_MAP,
    )

    assert REG_NAMES == FEATURE_NAMES
    assert list(REG_MAP.keys()) == REG_NAMES
    assert all(not meta.requires_payload_bytes for meta in REG_MAP.values())
    assert set(EXCLUDED_PAYLOAD_FEATURES.keys()) == {
        "mqtt_topic_count",
        "mqtt_new_topic",
        "mqtt_msg_rate",
        "mqtt_payload_len_mean",
    }

    root = Path(__file__).resolve().parents[2]
    readme_text = (root / "README.md").read_text(encoding="utf-8")
    expected_table = render_readme_feature_table()
    assert expected_table in readme_text, (
        "README.md 60-feature table must be generated from src/guardian/features/registry.py"
    )

    real_doc_text = (root / "docs" / "REAL_DATA_VALIDATION.md").read_text(encoding="utf-8")
    for feat_name in REG_NAMES:
        assert f"`{feat_name}`" in real_doc_text, (
            f"Feature {feat_name} from registry.py missing in docs/REAL_DATA_VALIDATION.md"
        )


def test_single_registry_source_of_truth_invariants() -> None:
    """Task 47: Verify registry.py is the single source of truth across definitions, config, and extractor."""
    from guardian.features.definitions import (
        get_canonical_feature_registry,
        validate_registry_invariants,
    )

    assert validate_registry_invariants() is True
    canonical = get_canonical_feature_registry()
    assert len(canonical) == 60
    assert list(canonical.keys()) == FEATURE_NAMES


def test_sync_readme_feature_table_from_registry(tmp_path: object) -> None:
    """Task 48: Verify sync_readme_feature_table regenerates the 60-feature table in README."""
    from pathlib import Path

    from guardian.features.registry import (
        render_readme_feature_table,
        sync_readme_feature_table,
    )

    sample_readme = Path(str(tmp_path)) / "README.md"
    sample_readme.write_text(
        "# Demo\n\n| # | Feature Name | Layer | Description & Formula | Unit | Suspicious Trend |\n| :---: | :--- | :---: | :--- | :---: | :---: |\n| 1 | `old` | 1 | Old row | x | y |\n\n## Footer\n",
        encoding="utf-8",
    )
    changed = sync_readme_feature_table(sample_readme)
    assert changed is True
    assert render_readme_feature_table() in sample_readme.read_text(encoding="utf-8")
    assert sync_readme_feature_table(sample_readme) is False


def test_readme_table_equals_registry_row_by_row() -> None:
    """Task 49: Verify every row and column of the README.md 60-feature table equals FEATURE_REGISTRY."""
    from pathlib import Path

    from guardian.features.registry import (
        FEATURE_REGISTRY as REG_MAP,
    )
    from guardian.features.registry import (
        render_readme_feature_table,
    )

    root = Path(__file__).resolve().parents[2]
    readme_lines = (root / "README.md").read_text(encoding="utf-8").splitlines()
    expected_lines = render_readme_feature_table().splitlines()
    header = expected_lines[0]
    assert header in readme_lines
    start = readme_lines.index(header)
    actual_slice = readme_lines[start : start + len(expected_lines)]
    assert actual_slice == expected_lines
    data_rows = actual_slice[2:]
    assert len(data_rows) == 60
    for idx, (row, meta) in enumerate(zip(data_rows, REG_MAP.values(), strict=True), start=1):
        cells = [c.strip() for c in row.strip().strip("|").split("|")]
        assert int(cells[0]) == idx
        assert cells[1] == f"`{meta.name}`"
        assert cells[3] == meta.description
        assert cells[4] == meta.unit


def test_clock_skew_feature_scope_documented() -> None:
    """Task 50: Verify clock-skew feature scope policy explicitly documents software TCP TSval heuristic vs out-of-scope RF."""
    from guardian.features.registry import get_clock_skew_feature_policy

    pol = get_clock_skew_feature_policy()
    assert pol["feature_name"] == "tcp_clock_skew_est"
    assert pol["index"] == 56
    assert pol["requires_rf_or_sdr_hardware"] is False
    assert pol["physical_layer_identity_in_scope"] is False
    assert pol["fallback_when_ts_option_absent"] == 0.0
    assert "ADR-007" in str(pol["scope_note"])

