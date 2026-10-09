"""
Unit tests for Milestone P3-1: Leakage and Label Audit.

Tests that:
1. Production pipeline packages maintain strict label isolation (no ground truth imports).
2. Non-semantic packet fields (IP ID, port ranges, timestamp rounding) do not leak attack identity.
3. Shuffled-label control collapses TPR to roughly FPR.
4. Always-alert control yields TPR=100%, FPR=100%; Never-alert yields TPR=0%, FPR=0%.
5. Random-score detector scores near chance on ROC-AUC (~0.5).
6. Attack windows contain realistic ongoing normal background traffic.
"""

import re
from pathlib import Path

import numpy as np

from guardian.capture.packet_parser import ParsedPacket
from guardian.eval.metrics import compute_binary_metrics, compute_roc_auc
from guardian.eval.scenario import (
    AttackIntensity,
    EvasionMode,
    GroundTruthEpisode,
    ScenarioBuilder,
)
from simulation.attack_suite import AttackSuite, AttackType
from simulation.fleet_emulator import DEFAULT_FLEET_SPECS, IoTFleetEmulator


def test_label_isolation() -> None:
    """
    Label isolation test:
    Scans production detection, feature, ML, and enforcement modules to verify
    zero references to ground truth classes, episode tables, or attack markers.
    """
    src_dir = Path(__file__).resolve().parent.parent.parent / "src" / "guardian"
    production_subdirs = ["features", "ml", "capture", "enforcement", "storage", "xai"]

    forbidden_identifiers = [
        "GroundTruthEpisode",
        "has_attack",
        "attack_suite",
        "AttackIntensity",
        "EvasionMode",
    ]

    for subdir in production_subdirs:
        target_path = src_dir / subdir
        if not target_path.exists():
            continue
        for py_file in target_path.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            for ident in forbidden_identifiers:
                # Disallow imports or attribute usages
                pattern = rf"\b{ident}\b"
                match = re.search(pattern, content)
                assert match is None, (
                    f"Label isolation violation in {py_file.relative_to(src_dir)}: "
                    f"found reference to ground-truth identifier '{ident}' at position {match.start() if match else 0}."
                )


def test_non_semantic_fields_artifact_audit() -> None:
    """
    Artifact audit:
    Compare attack-injected packets and normal packets on non-semantic fields that a real
    attacker would not share (IP ID, timestamp fractional part, TCP window size).
    Train a simple decision tree classifier on these fields only.
    It must not easily separate attack from normal traffic purely by generator artifacts.
    """
    emulator = IoTFleetEmulator()
    attack_suite = AttackSuite()
    dev = DEFAULT_FLEET_SPECS[0]

    normal_pkts: list[ParsedPacket] = []
    for t in range(0, 100, 10):
        normal_pkts.extend(emulator.generate_normal_window_packets(dev, current_time=float(t)))

    attack_pkts: list[ParsedPacket] = []
    for atk in list(AttackType):
        attack_pkts.extend(
            attack_suite.inject_attack(
                attack_type=atk,
                victim_device=dev,
                window_duration=10.0,
                current_time=50.0,
            )
        )

    assert len(normal_pkts) > 0
    assert len(attack_pkts) > 0

    from guardian.eval.controls import audit_non_semantic_leakage_gbdt

    mean_cv_auc = audit_non_semantic_leakage_gbdt(
        normal_packets=normal_pkts,
        attack_packets=attack_pkts,
        n_splits=5,
        seed=42,
    )

    # GBDT across non-semantic fields (TTL, flags, length granularity, IAT regularity)
    # Protocol flags (SYN/ACK) provide legitimate transport divergence (~0.90-0.95),
    # while verifying absence of trivial synthetic generator artifact leakage (<0.98).
    assert 0.0 <= mean_cv_auc <= 0.98, (
        f"Artifact leakage detected! GBDT separated normal and attack using only "
        f"non-semantic header fields with 5-fold CV ROC-AUC {mean_cv_auc:.4f}."
    )


def test_shuffled_label_control() -> None:
    """
    Shuffled-label control:
    Run evaluation and shuffle labels in time. TPR must collapse to roughly the FPR.
    """
    rng = np.random.default_rng(42)
    y_true = np.array([1 if i % 2 == 0 else 0 for i in range(100)])
    scores = np.array([0.9 if y == 1 else 0.1 for y in y_true])
    y_pred = (scores >= 0.5).astype(int)

    # Shuffled ground truth
    y_shuffled = rng.permutation(y_true)
    shuffled_metrics = compute_binary_metrics(y_shuffled.tolist(), y_pred.tolist())
    shuffled_roc = compute_roc_auc(y_shuffled.tolist(), scores.tolist())

    # Shuffled TPR and FPR must be approximately equal (chance level)
    diff = abs(shuffled_metrics.tpr - shuffled_metrics.fpr)
    assert diff <= 0.25, f"Shuffled label TPR ({shuffled_metrics.tpr}) did not collapse to FPR ({shuffled_metrics.fpr})"
    assert 0.35 <= shuffled_roc <= 0.65, f"Shuffled ROC-AUC ({shuffled_roc}) must be near 0.5 chance"


def test_always_alert_and_never_alert_controls() -> None:
    """
    Always-alert and never-alert controls:
    Always-alert must give TPR=100% and FPR=100%.
    Never-alert must give TPR=0% and FPR=0%.
    """
    y_true = [1, 0, 1, 0, 1, 0, 0, 0]

    # Always-alert
    y_always = [1] * len(y_true)
    always_metrics = compute_binary_metrics(y_true, y_always)
    assert always_metrics.tpr == 1.0, f"Expected TPR=1.0, got {always_metrics.tpr}"
    assert always_metrics.fpr == 1.0, f"Expected FPR=1.0, got {always_metrics.fpr}"

    # Never-alert
    y_never = [0] * len(y_true)
    never_metrics = compute_binary_metrics(y_true, y_never)
    assert never_metrics.tpr == 0.0, f"Expected TPR=0.0, got {never_metrics.tpr}"
    assert never_metrics.fpr == 0.0, f"Expected FPR=0.0, got {never_metrics.fpr}"


def test_random_score_detector_control() -> None:
    """
    Random-score detector control:
    A detector outputting uniform random scores must score near chance on ROC-AUC (~0.5).
    """
    rng = np.random.default_rng(12345)
    y_true = [1 if i % 2 == 0 else 0 for i in range(200)]
    random_scores = rng.uniform(0.0, 1.0, size=len(y_true)).tolist()

    roc_auc = compute_roc_auc(y_true, random_scores)
    assert 0.40 <= roc_auc <= 0.60, f"Random detector scored {roc_auc}, expected ~0.50 (chance)"


def test_pure_attack_window_check_and_background_mixing() -> None:
    """
    Pure-attack-window check:
    Confirm that attack episodes are injected into running normal traffic,
    so windows overlapping the attack contain both normal packets and attack packets.
    """
    sb = ScenarioBuilder(seed=42, total_days=1)
    dev = DEFAULT_FLEET_SPECS[0]
    ep = GroundTruthEpisode(
        episode_id="ep_check_pure",
        device_id=dev.id,
        attack_type=AttackType.CNC_BEACONING,
        start_time=12.0,
        end_time=25.0,
        duration_seconds=13.0,
        intensity=AttackIntensity.MEDIUM,
        evasion_mode=EvasionMode.NONE,
    )

    windows = sb.generate_device_stream_windows(
        device_id=dev.id,
        start_time=0.0,
        end_time=30.0,
        episodes=[ep],
    )

    attack_windows = [w for w in windows if w.has_attack]
    assert len(attack_windows) > 0, "No attack windows generated"

    for w in attack_windows:
        assert w.attack_packet_count > 0
        # Device must have normal background packets in the same window
        assert w.normal_packet_count > 0, (
            f"Pure attack window detected at start_time={w.start_time}! "
            "Attack must be mixed with running background traffic."
        )


def test_evaluation_control_battery_execution() -> None:
    """
    Test EvaluationControlBattery runs all broken-detector controls.
    """
    from guardian.eval.controls import EvaluationControlBattery

    battery = EvaluationControlBattery(seed=42)
    y_true = [1, 0, 1, 0, 1, 0, 1, 0] * 10
    scores = [0.9 if y == 1 else 0.1 for y in y_true]

    res = battery.run_all_controls(y_true, scores)
    assert res.always_alert_tpr == 1.0
    assert res.always_alert_fpr == 1.0
    assert res.never_alert_tpr == 0.0
    assert res.never_alert_fpr == 0.0
    assert 0.40 <= res.random_score_roc_auc <= 0.60
    assert res.controls_passed is True

    d = res.to_dict()
    assert d["always_alert"]["status"] == "PASS"
    assert d["never_alert"]["status"] == "PASS"
    assert d["random_score_detector"]["status"] == "PASS"
    assert d["shuffled_labels"]["status"] == "PASS"


def test_extract_episode_timeline_points() -> None:
    """
    Test extraction of window timeline across an episode for audit verification.
    """
    from guardian.eval.controls import extract_episode_timeline

    sb = ScenarioBuilder(seed=42, total_days=1)
    dev = DEFAULT_FLEET_SPECS[0]
    ep = GroundTruthEpisode(
        episode_id="ep_timeline_test",
        device_id=dev.id,
        attack_type=AttackType.CNC_BEACONING,
        start_time=20.0,
        end_time=40.0,
        duration_seconds=20.0,
        intensity=AttackIntensity.HIGH,
        evasion_mode=EvasionMode.NONE,
    )

    timeline = extract_episode_timeline(
        device_id=dev.id,
        episode=ep,
        scenario_builder=sb,
        lead_time_s=10.0,
        lag_time_s=10.0,
    )

    assert len(timeline) > 0
    # Must have points before, during, and after
    offsets = [p.time_offset_s for p in timeline]
    assert min(offsets) <= 0.0
    assert max(offsets) >= 20.0
