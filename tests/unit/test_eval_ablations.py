"""
Unit tests for Ablation Studies (Milestone P2-4).
Tests detector ablations (Layer 1 only, Layer 2 only) and component ablations
(with/without hysteresis, with/without calibration).
"""

from guardian.eval.ablations import (
    AblationConfig,
    AblationRunner,
    get_standard_ablation_battery,
)
from guardian.eval.scenario import AttackIntensity, EvasionMode, GroundTruthEpisode
from simulation.attack_suite import AttackType
from simulation.fleet_emulator import DEFAULT_FLEET_SPECS


def test_standard_ablation_battery_configs() -> None:
    battery = get_standard_ablation_battery()
    names = [c.name for c in battery]
    assert "Full GUARDIAN" in names
    # Detectors cleanly ablated (resolving G5)
    assert any("Statistical" in n and "Detector" in n or "Statistical" in n for n in names)
    assert any("Isolation Forest" in n for n in names)
    # Feature layers cleanly ablated (resolving G5)
    assert any("Layer 1" in n and "Volumetric" in n for n in names)
    assert any("Layer 2" in n and "Network" in n for n in names)
    assert any("Layer 3" in n for n in names)
    assert "No Hysteresis (Instantaneous)" in names
    assert "Uncalibrated (Fixed Threshold)" in names

    full = next(c for c in battery if c.name == "Full GUARDIAN")
    assert full.enable_statistical is True
    assert full.enable_ml is True
    assert full.enable_layer1_volumetric is True
    assert full.enable_layer2_network is True
    assert full.enable_layer3_metadata is True

    no_l2 = next(c for c in battery if "Layer 2" in c.name and "Network" in c.name)
    assert no_l2.enable_layer2_network is False

    no_hyst = next(c for c in battery if c.name == "No Hysteresis (Instantaneous)")
    assert no_hyst.enable_hysteresis is False


def test_ablation_runner_executes_isolated_layers() -> None:
    # 2-day simulation with 1 attack episode
    devices = [DEFAULT_FLEET_SPECS[0]]

    ep = GroundTruthEpisode(
        episode_id="ep_ablation_test",
        device_id=devices[0].id,
        attack_type=AttackType.CNC_BEACONING,
        start_time=100.0,
        end_time=130.0,
        duration_seconds=30.0,
        intensity=AttackIntensity.HIGH,
        evasion_mode=EvasionMode.NONE,
    )

    runner = AblationRunner(seed=42, devices=devices)

    cfg_full = AblationConfig(name="Full", enable_layer1=True, enable_layer2=True)
    res_full = runner.run_ablation(
        config=cfg_full,
        device_id=devices[0].id,
        start_time=0.0,
        end_time=300.0,
        episodes=[ep],
    )
    assert res_full.total_windows > 0
    assert 0.0 <= res_full.tpr <= 1.0

    cfg_l1 = AblationConfig(name="L1_Only", enable_layer1=True, enable_layer2=False)
    res_l1 = runner.run_ablation(
        config=cfg_l1,
        device_id=devices[0].id,
        start_time=0.0,
        end_time=300.0,
        episodes=[ep],
    )
    assert res_l1.config_name == "L1_Only"
    assert res_l1.total_windows > 0


def test_ablation_battery_execution() -> None:
    devices = [DEFAULT_FLEET_SPECS[0]]

    ep = GroundTruthEpisode(
        episode_id="ep_battery_test",
        device_id=devices[0].id,
        attack_type=AttackType.NETWORK_SCANNING,
        start_time=50.0,
        end_time=90.0,
        duration_seconds=40.0,
        intensity=AttackIntensity.MEDIUM,
        evasion_mode=EvasionMode.NONE,
    )

    runner = AblationRunner(seed=123, devices=devices)
    results = runner.run_battery(
        device_id=devices[0].id,
        start_time=0.0,
        end_time=200.0,
        episodes=[ep],
    )

    assert len(results) >= 5
    for r in results:
        assert r.f1 >= 0.0
        assert r.roc_auc >= 0.0
        assert r.false_alerts_per_device_day >= 0.0


def test_no_ablation_row_has_zero_tpr_with_high_auc() -> None:
    """
    Verify that no ablation row exhibits the contradictory combination of
    TPR == 0.0 and ROC-AUC > 0.9 in the same row across protocol schedule execution.
    """
    from guardian.eval.runner import EvaluationRunner
    from guardian.eval.scenario import DifficultyTier

    devices = DEFAULT_FLEET_SPECS[:2]
    eval_runner = EvaluationRunner(seed=42, total_days=14, devices=devices)
    op = eval_runner.calibrate_operating_point(target_fpr=0.05, duration_per_device_s=20.0)
    episodes = eval_runner.scenario_builder.generate_ground_truth_schedule(
        tiers=[DifficultyTier.EASY, DifficultyTier.MEDIUM],
        episodes_per_tier=1,
    )
    ablation_runner = AblationRunner(
        seed=42,
        devices=devices,
        total_days=14,
        operating_point=op,
        models=eval_runner._models,
        baselines=eval_runner._baselines,
    )
    results = ablation_runner.run_protocol_schedule_battery(
        episodes=episodes[:4],
        operating_point=op,
        pre_buffer_s=10.0,
        post_buffer_s=5.0,
    )
    assert len(results) == 8
    for r in results:
        assert not (r.tpr == 0.0 and r.roc_auc > 0.9), (
            f"Contradictory ablation row {r.config_name}: TPR={r.tpr} == 0.0 while ROC-AUC={r.roc_auc} > 0.9"
        )
        assert not (r.recall == 0.0 and r.roc_auc > 0.9), (
            f"Contradictory ablation row {r.config_name}: Recall={r.recall} == 0.0 while ROC-AUC={r.roc_auc} > 0.9"
        )
