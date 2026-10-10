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


def test_no_cross_table_cell_assignment_or_overwrite() -> None:
    """
    Task 14: Fails if any table row/cell in src/guardian/eval/report.py is assigned or overwritten
    from another table (e.g., assigning ablation_dict_list[0]['tpr'] = macro_guardian or
    copying a cell from detection_rows into ablation_rows), or if
    check_evaluation_cross_table_consistency compares a variable against itself.
    """
    import ast

    import pytest

    protected_table_vars = {
        "ablation_dict_list",
        "ablation_results",
        "ablation_rows",
        "ablations_data",
        "detection_rows",
        "detection_data",
        "per_cell_rows",
        "baselines_data",
        "adv_rows",
        "adversarial_rows",
        "adversarial_data",
        "scalability_data",
    }

    def _assert_ast_has_no_cross_table_copy(tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                rhs_names = {
                    n.id for n in ast.walk(node.value) if isinstance(n, ast.Name) and n.id in protected_table_vars
                }
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        root = target.value
                        while isinstance(root, ast.Subscript):
                            root = root.value
                        if isinstance(root, ast.Name) and root.id in protected_table_vars:
                            raise AssertionError(
                                f"Forbidden post-hoc table cell overwrite detected at line {node.lineno}: "
                                f"mutating '{root.id}[...]' after runner computation."
                            )
                        if isinstance(root, ast.Name) and rhs_names:
                            raise AssertionError(
                                f"Forbidden cross-table cell copy detected at line {node.lineno}: "
                                f"assigning '{root.id}[...]' from {sorted(rhs_names)}."
                            )

            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "check_evaluation_cross_table_consistency":
                    kw_map = {kw.arg: ast.dump(kw.value) for kw in node.keywords if kw.arg}
                    if "main_fpr" in kw_map and "ablation_fpr" in kw_map:
                        assert kw_map["main_fpr"] != kw_map["ablation_fpr"], (
                            f"Tautological cross-table consistency check at line {node.lineno}: "
                            "main_fpr and ablation_fpr pass the exact same expression!"
                        )

    report_py = Path(__file__).resolve().parent.parent.parent / "src" / "guardian" / "eval" / "report.py"
    source = report_py.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(report_py))
    _assert_ast_has_no_cross_table_copy(tree)

    # Negative check: synthetic cross-table cell copy must fail
    bad_tree = ast.parse('ablation_rows[0]["tpr"] = detection_rows[0]["guardian_tpr"]\n')
    with pytest.raises(AssertionError, match="Forbidden post-hoc table cell overwrite"):
        _assert_ast_has_no_cross_table_copy(bad_tree)
