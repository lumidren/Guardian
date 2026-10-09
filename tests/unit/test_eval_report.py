"""
Unit tests for Evaluation Report & Paper Assets Generator (Milestone P2-8).
Tests automated execution of full evaluation battery, mathematical consistency of macro averages,
and LaTeX asset generation.
"""

from pathlib import Path

from guardian.eval.report import (
    export_paper_assets,
    generate_full_evaluation_report,
)


def test_generate_full_evaluation_report_fast() -> None:
    report = generate_full_evaluation_report(seed=42, quick_mode=True)

    assert "run_id" in report
    assert "timestamp" in report
    assert "detection" in report
    assert "baselines" in report
    assert "ablations" in report
    assert "adversarial" in report
    assert "resources" in report
    assert "latencies" in report
    assert "scalability" in report

    # Verify mathematical integrity: macro average MUST equal exact mean of attack rows
    det_rows = report["detection"]["rows"]
    rates = [row["guardian_tpr"] for row in det_rows]
    expected_macro = round(sum(rates) / len(rates), 2)
    assert abs(report["detection"]["macro_average_tpr"] - expected_macro) < 1e-4


def test_export_paper_assets_latex(tmp_path: Path) -> None:
    report = generate_full_evaluation_report(seed=42, quick_mode=True)
    export_paper_assets(report, output_dir=tmp_path)

    expected_files = [
        tmp_path / "table_detection.tex",
        tmp_path / "table_baselines.tex",
        tmp_path / "table_ablations.tex",
        tmp_path / "table_adversarial.tex",
        tmp_path / "table_scalability.tex",
    ]
    for f in expected_files:
        assert f.exists(), f"Missing expected LaTeX asset: {f}"
        content = f.read_text(encoding="utf-8")
        assert "\\begin{tabular}" in content
        assert "\\end{tabular}" in content
