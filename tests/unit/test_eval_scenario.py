"""
Unit tests for evaluation scenario builder and ground truth schedule.
Verifies seed determinism, strict time-ordered splits (Days 1-7 Train, Day 8 Cal, Days 9-14 Test),
and proves that attack windows contain normal traffic as well (F5 fix).
"""


from guardian.eval.scenario import (
    AttackIntensity,
    EvasionMode,
    GroundTruthEpisode,
    ScenarioBuilder,
    SplitType,
)
from simulation.attack_suite import AttackType


def test_scenario_builder_seed_determinism() -> None:
    builder1 = ScenarioBuilder(seed=42, total_days=14)
    episodes1 = builder1.generate_ground_truth_schedule(episodes_per_attack=5)

    builder2 = ScenarioBuilder(seed=42, total_days=14)
    episodes2 = builder2.generate_ground_truth_schedule(episodes_per_attack=5)

    assert len(episodes1) == len(episodes2)
    for ep1, ep2 in zip(episodes1, episodes2, strict=True):
        assert ep1.episode_id == ep2.episode_id
        assert ep1.device_id == ep2.device_id
        assert ep1.attack_type == ep2.attack_type
        assert ep1.start_time == ep2.start_time
        assert ep1.end_time == ep2.end_time
        assert ep1.intensity == ep2.intensity
        assert ep1.evasion_mode == ep2.evasion_mode


def test_time_ordered_splits_contain_no_training_attacks() -> None:
    builder = ScenarioBuilder(seed=123, total_days=14)
    episodes = builder.generate_ground_truth_schedule(episodes_per_attack=6)

    # Days 1-7: Train (0 to 7 * 86400s)
    # Day 8: Calibration (7 * 86400s to 8 * 86400s)
    # Days 9-14: Test (8 * 86400s to 14 * 86400s)
    train_end = 7 * 86400.0
    cal_end = 8 * 86400.0
    assert train_end < cal_end

    for ep in episodes:
        # Ground truth attacks MUST only exist in the test split
        assert ep.start_time >= cal_end, f"Attack scheduled before test split: {ep}"
        assert ep.end_time <= 14 * 86400.0

    assert builder.get_split(0.0) == SplitType.TRAIN
    assert builder.get_split(6 * 86400.0 + 3600.0) == SplitType.TRAIN
    assert builder.get_split(7 * 86400.0 + 10.0) == SplitType.CALIBRATION
    assert builder.get_split(8 * 86400.0 + 10.0) == SplitType.TEST


def test_attack_windows_contain_normal_traffic() -> None:
    """
    CRITICAL ACCEPTANCE TEST (fixes F5):
    Proves that attack traffic is injected into the running normal stream,
    so every attack window contains both normal packets and attack packets.
    """
    builder = ScenarioBuilder(seed=999, total_days=14)
    test_episode = GroundTruthEpisode(
        episode_id="ep_test_001",
        device_id="dev_01_temp",
        attack_type=AttackType.DDOS_FLOODING,
        start_time=8 * 86400.0 + 300.0,
        end_time=8 * 86400.0 + 360.0,
        duration_seconds=60.0,
        intensity=AttackIntensity.MEDIUM,
        evasion_mode=EvasionMode.NONE,
    )

    windows = builder.generate_device_stream_windows(
        device_id="dev_01_temp",
        start_time=8 * 86400.0 + 290.0,
        end_time=8 * 86400.0 + 370.0,
        episodes=[test_episode],
    )

    attack_windows = [w for w in windows if w.has_attack]
    assert len(attack_windows) > 0, "No attack windows generated"

    for w in attack_windows:
        # Every attack window MUST contain normal packets mixed in
        assert w.normal_packet_count > 0, (
            f"Attack window at {w.start_time} has 0 normal packets (unmixed traffic bug)"
        )
        assert w.attack_packet_count > 0, (
            f"Attack window at {w.start_time} has 0 attack packets"
        )
        assert len(w.packets) == w.normal_packet_count + w.attack_packet_count
        # Packets in window must be strictly monotonically sorted by timestamp
        timestamps = [p.timestamp for p in w.packets]
        assert timestamps == sorted(timestamps)


def test_ground_truth_covers_all_attack_types_and_intensities() -> None:
    builder = ScenarioBuilder(seed=777, total_days=14)
    episodes = builder.generate_ground_truth_schedule(episodes_per_attack=12)

    found_attacks = {ep.attack_type for ep in episodes}
    found_intensities = {ep.intensity for ep in episodes}

    assert AttackType.DDOS_FLOODING in found_attacks
    assert AttackType.CNC_BEACONING in found_attacks
    assert AttackType.NETWORK_SCANNING in found_attacks
    assert AttackType.DATA_EXFILTRATION in found_attacks
    assert AttackType.CRYPTOMINING in found_attacks
    assert AttackType.ZERO_DAY_HYBRID in found_attacks

    assert AttackIntensity.LOW in found_intensities
    assert AttackIntensity.MEDIUM in found_intensities
    assert AttackIntensity.HIGH in found_intensities
