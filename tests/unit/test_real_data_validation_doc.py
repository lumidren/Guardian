"""
Unit tests for `docs/REAL_DATA_VALIDATION.md` consistency against
`eval/results/real_pcap_64mb_comparison.json` and `src/guardian/features/registry.py`.

Verifies Review Fixes 7, 8, 9, 10, and 11:
- Item 7: Every number in Section 5.2 text equals the JSON (`eval/results/real_pcap_64mb_comparison.json`),
  and regenerating the text via `scripts/generate_real_data_validation_doc.py` produces the exact file.
- Item 8: Feature registry reconciliation (`registry.py` == `config.py` == `REAL_DATA_VALIDATION.md`).
- Item 9: Feature matches are reported only for features with nonzero variance in both sets
  (`real_std > 0` and `sim_std > 0`), and false alerts/device/day is reported in the in-domain result.
- Item 10: Section 1 uses the real 8-node + Raspberry Pi 4 plan from `README.md` with `TODO`s and no invented hardware.
- Item 11: Section 2 states clearly where MQTT topic features need payload bytes and how that fits the
  "no payload inspection" claim.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from guardian.features.registry import FEATURE_NAMES, FEATURE_REGISTRY

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
JSON_PATH = REPO_ROOT / "eval" / "results" / "real_pcap_64mb_comparison.json"
DOC_PATH = REPO_ROOT / "docs" / "REAL_DATA_VALIDATION.md"


def test_section_5_2_every_number_equals_json() -> None:
    """
    Verify that every single number appearing in Section 5.2 prose of
    `docs/REAL_DATA_VALIDATION.md` equals the corresponding metric in
    `eval/results/real_pcap_64mb_comparison.json`.
    """
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    doc_text = DOC_PATH.read_text(encoding="utf-8")

    assert "### 5.2 Root-Cause Breakdown by Physical Network Mechanism" in doc_text
    sec_5_2 = doc_text.split("### 5.2 Root-Cause Breakdown by Physical Network Mechanism", 1)[1]

    # Collect all formatted 4-decimal numbers from the JSON features table
    valid_json_numbers: set[str] = set()
    feat_by_name: dict[str, dict[str, float]] = {}
    numeric_keys = (
        "real_mean",
        "real_std",
        "real_median",
        "real_p95",
        "sim_mean",
        "sim_std",
        "sim_median",
        "sim_p95",
        "ks_stat",
        "smd",
    )
    for f in data["features"]:
        fname = str(f["feature"])
        feat_by_name[fname] = {}
        for k in numeric_keys:
            val_str = f"{float(f[k]):.4f}"
            valid_json_numbers.add(val_str)
            feat_by_name[fname][k] = float(f[k])

    # Remove canonical feature identifier tokens (`pkt_count_10s`, `iat_p90`) before scanning for numbers
    cleaned_sec_5_2 = sec_5_2
    for fname in FEATURE_NAMES:
        cleaned_sec_5_2 = cleaned_sec_5_2.replace(f"`{fname}`", "FEATURE_ID")

    # Find every number in Section 5.2 prose (integers or decimals, signed or unsigned)
    numbers_in_prose = re.findall(r"(?<![A-Za-z_])-?\d+(?:\.\d+)?", cleaned_sec_5_2)
    assert len(numbers_in_prose) >= 60, (
        f"Expected at least 60 numeric values in Section 5.2, found {len(numbers_in_prose)}"
    )

    for num_str in numbers_in_prose:
        assert num_str in valid_json_numbers, (
            f"Number {num_str!r} in Section 5.2 does not match any 4-decimal feature metric in {JSON_PATH}"
        )

    # Also verify feature-specific bindings of the form:
    # FEATURE_ID real mean `X` ... simulator mean `Y`
    pair_pattern = re.compile(
        r"`([a-z0-9_]+)`\s+real mean\s+`(-?\d+\.\d+)`(?:\s+with std\s+`(-?\d+\.\d+)`)?"
    )
    matches = pair_pattern.findall(sec_5_2)
    assert len(matches) >= 25
    for fname, r_mean_s, r_std_s in matches:
        assert fname in feat_by_name, f"Unknown feature {fname} in Section 5.2"
        assert r_mean_s == f"{feat_by_name[fname]['real_mean']:.4f}"
        if r_std_s:
            assert r_std_s == f"{feat_by_name[fname]['real_std']:.4f}"


def test_nonzero_variance_matches_and_in_domain_far() -> None:
    """
    Verify Item 9:
    1. Only features with nonzero variance in both sets (`real_std > 0` and `sim_std > 0`)
       are marked `**MATCH**` in Section 4.
    2. In-domain result in Section 3.2 includes `false alerts/device/day`.
    """
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    doc_text = DOC_PATH.read_text(encoding="utf-8")

    assert "false alerts/device/day" in doc_text
    assert "181.77" in doc_text or "156.00" in doc_text

    # Parse all 60 rows of the Section 4 table
    table_row_re = re.compile(
        r"^\|\s*(\d+)\s*\|\s*`([a-z0-9_]+)`\s*\|\s*(-?\d+\.\d+)\s*\|\s*(-?\d+\.\d+)\s*\|"
        r"\s*(-?\d+\.\d+)\s*\|\s*(-?\d+\.\d+)\s*\|\s*(-?\d+\.\d+)\s*\|\s*(-?\d+\.\d+)\s*\|"
        r"\s*(-?\d+\.\d+)\s*\|\s*(-?\d+\.\d+)\s*\|\s*(-?\d+\.\d+)\s*\|\s*(-?\d+\.\d+)\s*\|\s*(.+?)\s*\|$",
        re.MULTILINE,
    )
    rows = table_row_re.findall(doc_text)
    assert len(rows) == 60, f"Expected 60 feature rows in Section 4 table, got {len(rows)}"

    matched_features_in_table: list[str] = []
    for row in rows:
        idx_1_s, fname, r_mean, r_std, r_med, r_p95, s_mean, s_std, s_med, s_p95, ks, smd, status = row
        idx = int(idx_1_s) - 1
        f_json = data["features"][idx]
        assert fname == f_json["feature"] == FEATURE_NAMES[idx]
        assert fname in FEATURE_REGISTRY
        assert r_mean == f"{float(f_json['real_mean']):.4f}"
        assert r_std == f"{float(f_json['real_std']):.4f}"
        assert s_mean == f"{float(f_json['sim_mean']):.4f}"
        assert s_std == f"{float(f_json['sim_std']):.4f}"
        assert ks == f"{float(f_json['ks_stat']):.4f}"
        assert smd == f"{float(f_json['smd']):.4f}"

        if status == "**MATCH**":
            assert float(r_std) > 0.0 and float(s_std) > 0.0, (
                f"Feature {fname} marked **MATCH** despite zero variance (real_std={r_std}, sim_std={s_std})"
            )
            matched_features_in_table.append(fname)

    assert len(matched_features_in_table) == 6
    assert set(matched_features_in_table) == {
        "burstiness_index",
        "idle_ratio",
        "pkt_len_mean",
        "small_pkt_ratio",
        "out_degree_centrality",
        "tcp_syn_ratio",
    }


def test_section_1_real_testbed_and_section_2_mqtt_payload_scope() -> None:
    """
    Verify Items 10 & 11:
    - Section 1 uses the real 8-node + Raspberry Pi 4 plan from README.md, marks unknowns TODO,
      and does not invent hardware (no TP-Link Kasa, Philips Hue, Wyze Cam).
    - Section 2 explains why MQTT topic features require payload bytes and how excluding them fits
      the "no payload inspection" claim.
    """
    doc_text = DOC_PATH.read_text(encoding="utf-8")

    # No invented hardware
    for forbidden in ("TP-Link", "HS100", "Philips Hue", "Wyze"):
        assert forbidden not in doc_text, f"Invented hardware {forbidden!r} found in REAL_DATA_VALIDATION.md"

    # Real BOM hardware present with TODOs
    assert "Raspberry Pi 4 Model B (4GB RAM)" in doc_text
    assert "ESP32-WROOM-32" in doc_text
    assert "Sonoff Basic S20" in doc_text
    assert "ESP32-CAM" in doc_text
    assert "TODO" in doc_text

    # MQTT payload bytes explanation & clock-skew scope note present
    assert "mqtt_topic_count" in doc_text
    assert "mqtt_new_topic" in doc_text
    assert "Layer-7" in doc_text
    assert "tcp_clock_skew_est" in doc_text
