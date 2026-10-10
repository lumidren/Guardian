"""
Unit tests for External IoT Dataset Validation (Milestone P3-5).
Tests Zeek conn.log parser, IoT-23 feature mapping to GUARDIAN schema, and external dataset evaluation.
"""

from pathlib import Path

import numpy as np

from guardian.eval.external import (
    ExternalDatasetEvaluator,
    IoT23Adapter,
    IoT23Record,
)

SAMPLE_ZEEK_CONN_LOG = """#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents	label	detailed-label
1532135688.0	C123	192.168.1.101	51234	192.168.1.1	1883	tcp	mqtt	0.05	120	80	SF	-	-	0	ShADF	2	240	2	160	-	Benign	-
1532135689.5	C124	192.168.1.101	51235	192.168.1.1	1883	tcp	mqtt	0.04	110	80	SF	-	-	0	ShADF	2	220	2	160	-	Benign	-
1532135695.0	C125	192.168.1.101	51236	198.51.100.55	23	tcp	-	0.001	0	0	S0	-	-	0	S	1	60	0	0	-	Malicious	PartOfAHorizontalPortScan
1532135696.0	C126	192.168.1.101	51237	198.51.100.56	23	tcp	-	0.001	0	0	S0	-	-	0	S	1	60	0	0	-	Malicious	PartOfAHorizontalPortScan
1532135697.0	C127	192.168.1.101	51238	198.51.100.57	23	tcp	-	0.001	0	0	S0	-	-	0	S	1	60	0	0	-	Malicious	PartOfAHorizontalPortScan
"""


def test_iot23_log_parsing(tmp_path: Path) -> None:
    log_file = tmp_path / "sample_conn.log"
    log_file.write_text(SAMPLE_ZEEK_CONN_LOG, encoding="utf-8")

    adapter = IoT23Adapter()
    records = adapter.parse_file(log_file)

    assert len(records) == 5
    first = records[0]
    assert isinstance(first, IoT23Record)
    assert first.orig_h == "192.168.1.101"
    assert first.resp_h == "192.168.1.1"
    assert first.resp_p == 1883
    assert first.proto == "TCP"
    assert first.is_malicious is False

    scan = records[2]
    assert scan.resp_p == 23
    assert scan.is_malicious is True
    assert scan.detailed_label == "PartOfAHorizontalPortScan"


def test_feature_mapping_to_guardian_vector(tmp_path: Path) -> None:
    log_file = tmp_path / "sample_conn.log"
    log_file.write_text(SAMPLE_ZEEK_CONN_LOG, encoding="utf-8")

    adapter = IoT23Adapter()
    records = adapter.parse_file(log_file)

    windows = adapter.aggregate_to_windows(records, window_size_s=10.0, stride_s=5.0)
    assert len(windows) > 0

    w0 = windows[0]
    feats = adapter.extract_features(w0)

    # Check Layer 1 volumetric features
    assert "pkt_count_10s" in feats
    assert "byte_count_10s" in feats
    assert feats["pkt_count_10s"] > 0
    assert not np.isnan(feats["pkt_count_10s"])

    # Check Layer 2 network destination features
    assert "out_degree_centrality" in feats
    assert "unique_dst_ips" in feats
    assert "new_dst_ip_flag" in feats

    # Check Layer 3 protocol and temporal features
    assert "hour_sin" in feats
    assert "hour_cos" in feats
    assert -1.0 <= feats["hour_sin"] <= 1.0


def test_external_dataset_evaluator_execution(tmp_path: Path) -> None:
    log_file = tmp_path / "sample_conn.log"
    log_file.write_text(SAMPLE_ZEEK_CONN_LOG, encoding="utf-8")

    evaluator = ExternalDatasetEvaluator(seed=42)
    report = evaluator.evaluate_iot23_log(log_file)

    assert "total_windows" in report
    assert "malicious_windows" in report
    assert "benign_windows" in report
    assert "tpr" in report
    assert "fpr" in report
    assert "f1" in report
    assert 0.0 <= report["tpr"] <= 1.0
    assert 0.0 <= report["fpr"] <= 1.0


def test_load_labeled_iot23_capture(tmp_path: Path) -> None:
    """Task 42: Verify labeled IoT-23 capture loader separates unlabeled feature windows from evaluation-only labels."""
    from guardian.eval.external import load_labeled_iot23_capture

    log_file = tmp_path / "sample_conn.log"
    log_file.write_text(SAMPLE_ZEEK_CONN_LOG, encoding="utf-8")
    ds = load_labeled_iot23_capture(log_file, window_size_s=5.0, stride_s=5.0)
    assert len(ds.feature_dicts) == len(ds.eval_only_labels)
    assert len(ds.feature_dicts) >= 2
    assert 0 in ds.eval_only_labels and 1 in ds.eval_only_labels
    assert "PartOfAHorizontalPortScan" in ds.eval_only_attack_families
    assert all("label" not in f and "is_malicious" not in f for f in ds.feature_dicts)


def test_external_attack_detection_report_labels_for_scoring_only(tmp_path: Path) -> None:
    """Task 43: Verify external attack detection report computes CIs and per-family TPR using labels only at scoring time."""
    from guardian.eval.external import (
        generate_external_attack_detection_report,
        load_labeled_iot23_capture,
    )

    log_file = tmp_path / "sample_conn.log"
    log_file.write_text(SAMPLE_ZEEK_CONN_LOG, encoding="utf-8")
    ds = load_labeled_iot23_capture(log_file, window_size_s=5.0, stride_s=5.0)
    rep = generate_external_attack_detection_report(ds, alert_threshold=35.0)
    assert rep["labels_used_for_training"] is False
    assert rep["malicious_windows"] >= 1
    assert rep["benign_windows"] >= 1
    assert "PartOfAHorizontalPortScan" in rep["per_attack_family"]
    assert len(rep["tpr_ci_95"]) == 2
    assert len(rep["fpr_ci_95"]) == 2


def test_external_track_never_uses_labels_for_training(tmp_path: Path) -> None:
    """Task 44: Verify external track feature extraction and scoring never access ground-truth labels."""
    import inspect
    from dataclasses import replace

    from guardian.eval.external import IoT23Adapter, IoT23Window, score_unlabeled_feature_windows

    ext_src = inspect.getsource(IoT23Adapter.extract_features)
    score_src = inspect.getsource(score_unlabeled_feature_windows)
    for forbidden in (".label", ".detailed_label", ".is_malicious", ".has_attack", "eval_only_labels"):
        assert forbidden not in ext_src, f"extract_features must never reference {forbidden}"
        assert forbidden not in score_src, f"score_unlabeled_feature_windows must never reference {forbidden}"

    log_file = tmp_path / "sample_conn.log"
    log_file.write_text(SAMPLE_ZEEK_CONN_LOG, encoding="utf-8")
    adapter = IoT23Adapter()
    records = adapter.parse_file(log_file)
    flipped_records = [
        replace(r, label="Malicious" if r.label == "Benign" else "Benign", detailed_label="Flipped")
        for r in records
    ]
    w_orig = IoT23Window(device_id="192.168.1.101", window_start=0.0, window_end=10.0, records=records, has_attack=False)
    w_flip = IoT23Window(
        device_id="192.168.1.101", window_start=0.0, window_end=10.0, records=flipped_records, has_attack=True
    )
    f_orig = adapter.extract_features(w_orig)
    f_flip = adapter.extract_features(w_flip)
    assert f_orig == f_flip
    assert score_unlabeled_feature_windows([f_orig]) == score_unlabeled_feature_windows([f_flip])


def test_dataset_license_and_checksum_registry() -> None:
    """Task 45: Verify dataset, license, and SHA-256 checksum registry matches docs/DATASET_REGISTRY.md."""
    from guardian.eval.external import EXTERNAL_DATASET_REGISTRY, generate_dataset_registry_markdown

    assert len(EXTERNAL_DATASET_REGISTRY) >= 3
    for entry in EXTERNAL_DATASET_REGISTRY:
        assert len(entry["sha256"]) == 64
        assert "CC BY 4.0" in entry["license"]
        assert entry["size_bytes"] > 0

    doc_path = Path(__file__).resolve().parent.parent.parent / "docs" / "DATASET_REGISTRY.md"
    assert doc_path.exists()
    assert doc_path.read_text(encoding="utf-8") == generate_dataset_registry_markdown()
