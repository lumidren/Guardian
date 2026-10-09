"""
Automated Academic Evaluation and Verification Suite for GUARDIAN.

Thin wrapper executing the Phase 2 Evaluation Framework (guardian.eval).
Ensures all metrics are computed dynamically with strict provenance tracking.
"""

import argparse
import json
import sys
from pathlib import Path

# Ensure project root is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from guardian.eval.runner import EvaluationRunner  # noqa: E402
from guardian.eval.scenario import ScenarioBuilder  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="GUARDIAN Phase 2 Evaluation Runner")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic replay")
    parser.add_argument("--days", type=int, default=14, help="Total simulation days")
    parser.add_argument(
        "--episodes",
        type=int,
        default=5,
        help="Episodes per attack type (smoke default: 5, full: 50)",
    )
    parser.add_argument(
        "--device",
        type=str,
        default="dev_01_temp",
        help="Target device ID for slice evaluation",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(ROOT_DIR / "benchmarks" / "results" / "evaluation_report.json"),
    )
    args = parser.parse_args()

    print("=" * 80)
    print(" GUARDIAN IoT Security Framework - Phase 2 Evaluation Suite")
    print(f" Seed: {args.seed} | Days: {args.days} | Episodes/Attack: {args.episodes}")
    print("=" * 80)

    runner = EvaluationRunner(seed=args.seed, total_days=args.days)
    builder = ScenarioBuilder(seed=args.seed, total_days=args.days)
    episodes = builder.generate_ground_truth_schedule(episodes_per_attack=args.episodes)

    # Time boundaries (Day 8+ test split)
    test_start = 8.0 * 86400.0
    test_end = float(args.days) * 86400.0

    print(f"[Evaluation] Running live stream pipeline for {args.device} across scheduled episodes...")
    report = runner.evaluate_device_slice(
        device_id=args.device,
        start_time=test_start,
        end_time=min(test_end, test_start + 7200.0),  # Slice window for fast benchmark
        episodes=[ep for ep in episodes if ep.device_id == args.device],
    )

    report_dict = report.to_dict()
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)

    print("\n[Results Summary]")
    print(
        f" Total Windows: {report.total_windows} "
        f"(Normal: {report.normal_windows}, Attack: {report.attack_windows})"
    )
    print(
        f" Window TPR: {report.window_metrics.tpr * 100:.2f}% | "
        f"FPR: {report.window_metrics.fpr * 100:.2f}%"
    )
    print(f" ROC-AUC: {report.roc_auc:.4f} | PR-AUC: {report.pr_auc:.4f}")
    print(f" Episode Detection Rate: {report.episode_detection_rate * 100:.2f}%")
    print(f" False Alerts / Device / Day: {report.false_alert_rate_per_device_day:.4f}")
    print(f" Saved full report to: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
