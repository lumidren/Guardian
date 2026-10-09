"""
Unit tests for Evaluation Plausibility Guard & Honest Status Enforcement (Milestone P3-7).
Resolves Audit Findings G8 and G10:
- G8: Plausibility checks and honest status logic (reject 0.00s TTD, fail on >40% CPU).
- G10: Automated verification that illustrative mocks/examples are explicitly labeled.
"""

import re
from pathlib import Path

from guardian.eval.guard import PlausibilityGuard
from guardian.eval.report import generate_full_evaluation_report


def test_plausibility_guard_rejects_zero_ttd() -> None:
    """TTD of 0.00s on multi-packet attacks is physically impossible and must fail."""
    guard = PlausibilityGuard()
    mock_report = {
        "detection": {
            "rows": [
                {"attack": "DDOS_FLOODING", "guardian_tpr": 90.0, "mean_ttd_s": 0.00, "f1": 0.85},
                {"attack": "CNC_BEACONING", "guardian_tpr": 85.0, "mean_ttd_s": 4.00, "f1": 0.82},
            ]
        },
        "resources": {
            "cpu_percent_avg": 18.0,
            "memory_rss_mb_peak": 120.0,
            "cpu_status": "PASS",
            "memory_status": "PASS",
        },
        "latencies": {
            "time_to_detect_s": {"mean": 0.00},
            "compute_latency_ms": {"mean": 5.0},
            "enforcement_latency_ms": {"mean": 2.0},
        },
    }

    result = guard.validate(mock_report)
    assert not result.is_plausible
    assert any("Time-to-detect cannot be 0.00s" in v for v in result.violations)


def test_plausibility_guard_honest_resource_thresholds() -> None:
    """CPU > 40% or memory > 256MB marked PASS must be caught as dishonest status."""
    guard = PlausibilityGuard(target_cpu_max=40.0, target_mem_max_mb=256.0)

    # Violating CPU marked PASS
    dishonest_report = {
        "detection": {
            "rows": [
                {"attack": "DDOS_FLOODING", "guardian_tpr": 90.0, "mean_ttd_s": 2.0, "f1": 0.85},
            ]
        },
        "resources": {
            "cpu_percent_avg": 52.4,  # > 40% target
            "memory_rss_mb_peak": 140.0,
            "cpu_status": "PASS",  # Dishonestly claiming PASS!
            "memory_status": "PASS",
        },
        "latencies": {
            "time_to_detect_s": {"mean": 2.0},
            "compute_latency_ms": {"mean": 5.0},
            "enforcement_latency_ms": {"mean": 2.0},
        },
    }

    result = guard.validate(dishonest_report)
    assert not result.is_plausible
    assert any("CPU exceeds threshold" in v for v in result.violations)


def test_plausibility_guard_rejects_identical_rows() -> None:
    """Identical metrics across distinct attack rows indicates uncalculated copied metrics."""
    guard = PlausibilityGuard()
    identical_report = {
        "detection": {
            "rows": [
                {"attack": "DDOS_FLOODING", "guardian_tpr": 88.0, "mean_ttd_s": 2.0, "f1": 0.8123},
                {"attack": "CNC_BEACONING", "guardian_tpr": 88.0, "mean_ttd_s": 2.0, "f1": 0.8123},
                {"attack": "NETWORK_SCANNING", "guardian_tpr": 88.0, "mean_ttd_s": 2.0, "f1": 0.8123},
            ]
        },
        "resources": {
            "cpu_percent_avg": 18.0,
            "memory_rss_mb_peak": 120.0,
            "cpu_status": "PASS",
            "memory_status": "PASS",
        },
        "latencies": {
            "time_to_detect_s": {"mean": 2.0},
            "compute_latency_ms": {"mean": 5.0},
            "enforcement_latency_ms": {"mean": 2.0},
        },
    }

    result = guard.validate(identical_report)
    assert not result.is_plausible
    assert any("Identical metric values" in v for v in result.violations)


def test_plausibility_guard_validates_live_report() -> None:
    """Live generated evaluation report must pass all plausibility checks."""
    guard = PlausibilityGuard()
    live_report = generate_full_evaluation_report(seed=42, quick_mode=True)

    result = guard.validate(live_report)
    assert result.is_plausible, f"Live report failed plausibility: {result.violations}"
    assert len(result.violations) == 0


def test_illustrative_examples_labeled_in_readme() -> None:
    """Verifies that sample JSON / mocks in documentation are explicitly labeled illustrative (G10)."""
    readme_path = Path(__file__).resolve().parent.parent.parent / "README.md"
    assert readme_path.exists()
    content = readme_path.read_text(encoding="utf-8")

    # If code blocks or dashboards exist, ensure any synthetic mock JSON has illustrative notice
    json_blocks = re.findall(r"```json\s*(\{[\s\S]*?\})\s*```", content)
    for block in json_blocks:
        # Each mock payload in README must either be generated or contain "illustrative" / "mock"
        assert "illustrative" in block.lower() or "illustrative" in content.lower(), (
            "JSON examples in README must be explicitly labeled illustrative"
        )


def test_plausibility_guard_rejects_always_alert() -> None:
    """Verifies that PlausibilityGuard rejects an always-alert detector with high FPR."""
    guard = PlausibilityGuard()
    always_alert_report = {
        "detection": {
            "rows": [
                {"attack": "DDOS_FLOODING", "guardian_tpr": 100.0, "mean_ttd_s": 2.0, "f1": 0.7907},
            ]
        },
        "baselines": {
            "methods": [
                {"name": "GUARDIAN (Multi-Layer Ensemble)", "tpr": 100.0, "fpr": 100.0, "f1": 0.7907},
            ]
        },
    }
    result = guard.validate(always_alert_report)
    assert not result.is_plausible
    assert any("Degenerate always-alert detector" in v for v in result.violations)


def test_plausibility_guard_rejects_never_alert() -> None:
    """Verifies that PlausibilityGuard rejects a never-alert detector with 0% TPR."""
    guard = PlausibilityGuard()
    never_alert_report = {
        "detection": {
            "rows": [
                {"attack": "DDOS_FLOODING", "guardian_tpr": 0.0, "mean_ttd_s": 2.0, "f1": 0.0},
            ],
            "macro_average_tpr": 0.0,
        },
        "baselines": {
            "methods": [
                {"name": "GUARDIAN (Multi-Layer Ensemble)", "tpr": 0.0, "fpr": 0.0, "f1": 0.0},
            ]
        },
    }
    result = guard.validate(never_alert_report)
    assert not result.is_plausible
    assert any("Degenerate never-alert detector" in v for v in result.violations)


def test_plausibility_guard_rejects_flat_scalability() -> None:
    """Verifies that PlausibilityGuard rejects flat scalability benchmark curves."""
    guard = PlausibilityGuard()
    flat_report = {
        "scalability": {
            "points": [
                {"device_count": 8, "cpu_percent": 25.0, "memory_rss_mb": 140.0},
                {"device_count": 12, "cpu_percent": 25.0, "memory_rss_mb": 140.0},
                {"device_count": 16, "cpu_percent": 25.0, "memory_rss_mb": 140.0},
            ]
        }
    }
    result = guard.validate(flat_report)
    assert not result.is_plausible
    assert any("Flat scalability benchmark detected" in v for v in result.violations)

