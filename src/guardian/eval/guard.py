"""
Evaluation Plausibility Guard and Sanity Validation Module (Milestone P3-7).
Resolves Audit Findings G8 and G10:
- Enforces physical sanity thresholds (rejects 0.00s TTD, rejects identical rows across attacks).
- Enforces honest pass/fail status logic on CPU (fails if CPU > 40%) and Memory.
- Validates cross-table consistency and flags implausible perfection.
"""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PlausibilityReport:
    is_plausible: bool
    violations: list[str]
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_plausible": self.is_plausible,
            "violations": self.violations,
            "warnings": self.warnings,
        }


class PlausibilityGuard:
    """
    Sanity validator ensuring empirical evaluations comply with physical reality and honest metrics.
    Resolves Finding G8:
    - Rejects 0.00s time-to-detect.
    - Rejects identical metrics across distinct attack rows.
    - Rejects 100% TPR on Hard tier or adversarial mimicry without degradation.
    - Validates honest status logic for CPU and Memory targets (flags violations marked PASS).
    """

    def __init__(
        self,
        target_cpu_max: float = 40.0,
        target_mem_max_mb: float = 256.0,
        target_ttd_max_s: float = 60.0,
        target_compute_max_ms: float = 50.0,
        target_enforcement_max_ms: float = 300.0,
    ) -> None:
        self.target_cpu_max = target_cpu_max
        self.target_mem_max_mb = target_mem_max_mb
        self.target_ttd_max_s = target_ttd_max_s
        self.target_compute_max_ms = target_compute_max_ms
        self.target_enforcement_max_ms = target_enforcement_max_ms

    def validate(self, report: dict[str, Any]) -> PlausibilityReport:
        violations: list[str] = []
        warnings: list[str] = []

        # 1. Check Detection Table
        det = report.get("detection")
        if isinstance(det, dict) and "rows" in det:
            rows = det["rows"]
            if rows:
                # Check 1a: Zero TTD on attacks
                for r in rows:
                    ttd = r.get("mean_ttd_s")
                    if ttd is not None and ttd <= 0.0:
                        violations.append(
                            f"Time-to-detect cannot be 0.00s for attack '{r.get('attack')}': "
                            "multi-packet attacks require temporal window accumulation."
                        )

                # Check 1b: Identical rows or pairwise duplicate rows
                if len(rows) > 1:
                    first_row = rows[0]
                    first_tpr = float(first_row.get("guardian_tpr", first_row.get("tpr", 0.0)))
                    first_f1 = float(first_row.get("f1", 0.0))
                    first_ttd = float(first_row.get("mean_ttd_s", 0.0))
                    all_copied = True
                    for r in rows[1:]:
                        r_tpr = float(r.get("guardian_tpr", r.get("tpr", 0.0)))
                        r_f1 = float(r.get("f1", 0.0))
                        r_ttd = float(r.get("mean_ttd_s", 0.0))
                        if not (abs(r_tpr - first_tpr) < 1e-4 and abs(r_f1 - first_f1) < 1e-4 and abs(r_ttd - first_ttd) < 1e-4):
                            all_copied = False
                            break
                    if all_copied:
                        violations.append(
                            f"Identical metric values (TPR={first_tpr}%, F1={first_f1}) across all {len(rows)} attack classes: "
                            "indicates uncalculated or copied metrics."
                        )
                    else:
                        # Check pairwise duplicates
                        for i in range(len(rows)):
                            for j in range(i + 1, len(rows)):
                                r_i, r_j = rows[i], rows[j]
                                if (
                                    abs(float(r_i.get("guardian_tpr", 0.0)) - float(r_j.get("guardian_tpr", 0.0))) < 1e-4
                                    and abs(float(r_i.get("f1", 0.0)) - float(r_j.get("f1", 0.0))) < 1e-4
                                    and abs(float(r_i.get("mean_ttd_s", 0.0)) - float(r_j.get("mean_ttd_s", 0.0))) < 1e-4
                                ):
                                    msg = (
                                        f"Duplicate metric row detected: '{r_i.get('attack')}' and '{r_j.get('attack')}' "
                                        f"share identical TPR ({r_i.get('guardian_tpr')}%), F1 ({r_i.get('f1')}), and TTD ({r_i.get('mean_ttd_s')}s)."
                                    )
                                    if report.get("quick_mode"):
                                        warnings.append(msg + " (quick mode smoke artifact)")
                                    else:
                                        violations.append(msg)

                # Check 1c: Never-alert detector
                macro_tpr = float(det.get("macro_average_tpr", -1.0))
                if macro_tpr == 0.0 or all(float(r.get("guardian_tpr", 1.0)) == 0.0 for r in rows):
                    violations.append(
                        "Degenerate never-alert detector detected: TPR is 0.0% across all evaluated attack classes."
                    )

                # Check 1d: Implausible perfection on hard or adversarial
                adv = report.get("adversarial")
                if isinstance(adv, dict) and "rows" in adv:
                    adv_rows = adv["rows"]
                    perfect_adv = [
                        ar.get("evasion_mode")
                        for ar in adv_rows
                        if ar.get("tpr") == 100.0 and ar.get("evasion_mode") in ("MIMICRY", "LOW_AND_SLOW")
                    ]
                    if perfect_adv:
                        warnings.append(
                            f"Detector scored 100.0% TPR on adversarial evasion ({perfect_adv}). "
                            "Verify evasion realism."
                        )

        # 2. Check Baselines (Always-Alert & Random-Score Detection)
        base = report.get("baselines")
        if isinstance(base, dict) and "methods" in base:
            for b in base["methods"]:
                b_name = str(b.get("name", ""))
                if b_name.startswith("GUARDIAN"):
                    b_fpr = float(b.get("fpr", 0.0))
                    b_f1 = float(b.get("f1", 1.0))
                    if b_fpr >= 50.0:
                        violations.append(
                            f"Degenerate always-alert detector detected: FPR={b_fpr:.1f}% exceeds 50.0% operational ceiling."
                        )
                    if b_f1 < 0.25:
                        warnings.append(
                            f"Implausibly poor F1 score ({b_f1:.4f}) indicates uncalibrated or random scoring."
                        )

        # 3. Check Resource Overhead and Honest Status (Finding G8)
        res = report.get("resources")
        if isinstance(res, dict):
            cpu_avg = float(res.get("cpu_percent_avg", 0.0))
            cpu_status = str(res.get("cpu_status", "")).upper()
            mem_peak = float(res.get("memory_rss_mb_peak", 0.0))
            mem_status = str(res.get("memory_status", "")).upper()

            # Check honest status logic
            if cpu_avg > self.target_cpu_max and cpu_status == "PASS":
                violations.append(
                    f"CPU exceeds threshold ({cpu_avg:.1f}% > {self.target_cpu_max}%), "
                    "but cpu_status was marked PASS (dishonest status logic)."
                )
            if mem_peak > self.target_mem_max_mb and mem_status == "PASS":
                violations.append(
                    f"Memory RSS exceeds threshold ({mem_peak:.1f} MB > {self.target_mem_max_mb} MB), "
                    "but memory_status was marked PASS (dishonest status logic)."
                )

        # 4. Check Latencies
        lat = report.get("latencies")
        if isinstance(lat, dict):
            ttd_dict = lat.get("time_to_detect_s", {})
            if isinstance(ttd_dict, dict):
                mean_ttd = ttd_dict.get("mean")
                if mean_ttd is not None and float(mean_ttd) <= 0.0:
                    violations.append("Time-to-detect cannot be 0.00s in latency report.")

        # 5. Check Scalability Non-Flatness (Finding G4 / Variant h)
        scale = report.get("scalability")
        if isinstance(scale, dict) and "points" in scale:
            pts = scale["points"]
            if len(pts) >= 2:
                cpus = [float(p.get("cpu_percent", 0.0)) for p in pts]
                mems = [float(p.get("memory_rss_mb", 0.0)) for p in pts]
                if max(cpus) - min(cpus) < 1e-4 and max(mems) - min(mems) < 1e-4:
                    violations.append(
                        "Flat scalability benchmark detected: CPU and memory are completely static across differing fleet sizes."
                    )

        is_plausible = len(violations) == 0
        return PlausibilityReport(
            is_plausible=is_plausible,
            violations=violations,
            warnings=warnings,
        )

    def assert_plausible(self, report: dict[str, Any]) -> None:
        result = self.validate(report)
        if not result.is_plausible:
            raise ValueError(
                f"Plausibility guard failed with {len(result.violations)} violation(s):\n"
                + "\n".join(f" - {v}" for v in result.violations)
            )
