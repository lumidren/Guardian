"""
Guardrail tests ensuring absence of hardcoded or fabricated empirical metrics (Milestone P2-9).

Static and dynamic verification ensuring that all evaluation modules in `src/guardian/eval`
compute metrics strictly via live algorithmic pipelines, preventing regressions into
synthetic constants or unmeasured claims.
"""

import re
from pathlib import Path

from guardian.eval.report import generate_full_evaluation_report


def test_static_guardrail_no_hardcoded_metric_constants() -> None:
    """
    Static code analysis over src/guardian/eval/ to detect forbidden hardcoded constants
    from legacy Phase 1 artifacts (e.g. unmeasured Snort tables, hardcoded FPR baselines).
    """
    eval_dir = Path(__file__).resolve().parent.parent.parent / "src" / "guardian" / "eval"
    assert eval_dir.exists() and eval_dir.is_dir(), f"Evaluation directory missing: {eval_dir}"

    forbidden_patterns = [
        re.compile(r"Simulated Signature NIDS", re.IGNORECASE),
        re.compile(r"\[25,\s*15,\s*35,\s*20,\s*10,\s*5\]"),
        re.compile(r"\[75,\s*68,\s*72,\s*65,\s*58,\s*62\]"),
        re.compile(r"sub-millisecond kernel containment", re.IGNORECASE),
    ]

    for py_file in eval_dir.glob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for pattern in forbidden_patterns:
            match = pattern.search(content)
            assert match is None, (
                f"Violation of Scientific Prime Directive in {py_file.name}: "
                f"found forbidden pattern '{pattern.pattern}' at position {match.start() if match else 0}"
            )


def test_dynamic_guardrail_report_integrity_and_provenance() -> None:
    """
    Dynamic verification that evaluation report produces exact mathematical means
    and complete provenance metadata (run_id, git_sha, timestamp).
    """
    report = generate_full_evaluation_report(seed=123, quick_mode=True)

    # 1. Provenance
    assert report["run_id"].startswith("eval_")
    assert len(report["git_sha"]) >= 4
    assert "T" in report["timestamp"]

    # 2. Arithmetic consistency of macro averages
    det = report["detection"]
    rows = det["rows"]
    assert len(rows) == 6, "Expected exactly 6 attack classes in detection rows"

    tpr_sum = sum(r["guardian_tpr"] for r in rows)
    expected_macro = round(tpr_sum / len(rows), 2)
    assert abs(det["macro_average_tpr"] - expected_macro) < 1e-4

    pooled_sum = sum(r["pooled_if_tpr"] for r in rows)
    expected_pooled = round(pooled_sum / len(rows), 2)
    assert abs(det["macro_average_pooled"] - expected_pooled) < 1e-4

    static_sum = sum(r["static_rules_tpr"] for r in rows)
    expected_static = round(static_sum / len(rows), 2)
    assert abs(det["macro_average_static"] - expected_static) < 1e-4

    zscore_sum = sum(r["zscore_tpr"] for r in rows)
    expected_zscore = round(zscore_sum / len(rows), 2)
    assert abs(det["macro_average_zscore"] - expected_zscore) < 1e-4

    # 3. Disaggregated latencies are present and numeric
    lat = report["latencies"]
    assert lat["compute_latency_ms"]["mean"] > 0
    assert lat["enforcement_latency_ms"]["mean"] > 0
    assert "time_to_detect_s" in lat


def test_readme_and_results_md_tables_match() -> None:
    """
    Verifies that the core empirical tables in README.md (Zero-Day Detection, Baselines,
    Ablations, and Adversarial Evasion) match eval/RESULTS.md exactly without manual manipulation.
    """
    root_dir = Path(__file__).resolve().parent.parent.parent
    results_path = root_dir / "eval" / "RESULTS.md"
    readme_path = root_dir / "README.md"
    assert results_path.exists() and readme_path.exists()

    results_content = results_path.read_text(encoding="utf-8")
    readme_content = readme_path.read_text(encoding="utf-8")

    # Match all rows from tables 1 through 4 in RESULTS.md
    for line in results_content.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("| **") and not any(
            ignored in trimmed
            for ignored in [
                "Latency",
                "Time-to-Detect",
                "Offered Packets",
                "Processed Packets",
                "Dropped Packets",
                "Packet Drop Rate",
                "Peak Queue Depth",
                "Packet Ingestion Throughput",
            ]
        ):
            assert trimmed in readme_content, (
                f"Empirical metric mismatch between eval/RESULTS.md and README.md!\n"
                f"Missing or modified row: {trimmed}"
            )

