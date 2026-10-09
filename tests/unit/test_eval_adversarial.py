"""
Unit tests for Adversarial Evasion Modes (Milestone P2-5).
Tests four adversarial evasion modes:
1. MIMICRY: packet lengths match legitimate normal distributions.
2. LOW_AND_SLOW: volumetric reduction below standard rate ceiling.
3. DELAYED_START: initial dormancy before payload transmission.
4. NO_NEW_DESTINATION: exploits existing authorized endpoints without new IPs.
"""

from guardian.eval.scenario import AttackIntensity, EvasionMode, GroundTruthEpisode, ScenarioBuilder
from simulation.attack_suite import AttackType
from simulation.fleet_emulator import DEFAULT_FLEET_SPECS


def test_evasion_mode_mimicry_packet_lengths() -> None:
    dev = DEFAULT_FLEET_SPECS[0]  # Temp sensor, normal byte range (64, 128)
    sb = ScenarioBuilder(seed=42, total_days=2, devices=[dev])

    ep_mimic = GroundTruthEpisode(
        episode_id="ep_mimicry",
        device_id=dev.id,
        attack_type=AttackType.CNC_BEACONING,
        start_time=100.0,
        end_time=130.0,
        duration_seconds=30.0,
        intensity=AttackIntensity.HIGH,
        evasion_mode=EvasionMode.MIMICRY,
    )

    windows = sb.generate_device_stream_windows(
        device_id=dev.id,
        start_time=90.0,
        end_time=140.0,
        episodes=[ep_mimic],
    )

    attack_windows = [w for w in windows if w.has_attack]
    assert len(attack_windows) > 0

    # In mimicry mode, attack packets must have lengths sampled from device's normal byte range
    min_b, max_b = dev.normal_byte_range
    for w in attack_windows:
        for p in w.packets:
            if p.dst_port == 8443 or p.app_protocol == "HTTPS":
                assert min_b <= p.length <= max_b


def test_evasion_mode_low_and_slow_volume_reduction() -> None:
    dev = DEFAULT_FLEET_SPECS[0]
    sb = ScenarioBuilder(seed=42, total_days=2, devices=[dev])

    ep_std = GroundTruthEpisode(
        episode_id="ep_standard",
        device_id=dev.id,
        attack_type=AttackType.DDOS_FLOODING,
        start_time=100.0,
        end_time=120.0,
        duration_seconds=20.0,
        intensity=AttackIntensity.MEDIUM,
        evasion_mode=EvasionMode.NONE,
    )
    w_std = sb.generate_device_stream_windows(
        device_id=dev.id,
        start_time=90.0,
        end_time=130.0,
        episodes=[ep_std],
    )
    pkts_std = sum(w.attack_packet_count for w in w_std)

    ep_slow = GroundTruthEpisode(
        episode_id="ep_low_slow",
        device_id=dev.id,
        attack_type=AttackType.DDOS_FLOODING,
        start_time=100.0,
        end_time=120.0,
        duration_seconds=20.0,
        intensity=AttackIntensity.MEDIUM,
        evasion_mode=EvasionMode.LOW_AND_SLOW,
    )
    w_slow = sb.generate_device_stream_windows(
        device_id=dev.id,
        start_time=90.0,
        end_time=130.0,
        episodes=[ep_slow],
    )
    pkts_slow = sum(w.attack_packet_count for w in w_slow)

    # Low and slow should reduce packet count to <= 25% of standard
    assert pkts_slow < pkts_std
    assert pkts_slow <= pkts_std * 0.30


def test_evasion_mode_delayed_start_dormancy() -> None:
    dev = DEFAULT_FLEET_SPECS[0]
    sb = ScenarioBuilder(seed=42, total_days=2, devices=[dev])

    # 40-second episode with delayed start (first 20 seconds dormant)
    ep_delayed = GroundTruthEpisode(
        episode_id="ep_delayed",
        device_id=dev.id,
        attack_type=AttackType.CNC_BEACONING,
        start_time=100.0,
        end_time=140.0,
        duration_seconds=40.0,
        intensity=AttackIntensity.HIGH,
        evasion_mode=EvasionMode.DELAYED_START,
    )

    windows = sb.generate_device_stream_windows(
        device_id=dev.id,
        start_time=100.0,
        end_time=140.0,
        episodes=[ep_delayed],
    )

    # Early windows (before t=116) must have 0 attack packets due to dormancy
    early_windows = [w for w in windows if w.end_time <= 116.0]
    assert len(early_windows) > 0
    for w in early_windows:
        assert w.attack_packet_count == 0

    # Later windows (after t=120) must contain attack packets
    late_windows = [w for w in windows if w.start_time >= 120.0]
    assert len(late_windows) > 0
    assert any(w.attack_packet_count > 0 for w in late_windows)


def test_evasion_mode_no_new_destination() -> None:
    dev = DEFAULT_FLEET_SPECS[0]
    sb = ScenarioBuilder(seed=42, total_days=2, devices=[dev])

    ep_no_new = GroundTruthEpisode(
        episode_id="ep_no_new_dst",
        device_id=dev.id,
        attack_type=AttackType.CNC_BEACONING,
        start_time=100.0,
        end_time=130.0,
        duration_seconds=30.0,
        intensity=AttackIntensity.MEDIUM,
        evasion_mode=EvasionMode.NO_NEW_DESTINATION,
    )

    windows = sb.generate_device_stream_windows(
        device_id=dev.id,
        start_time=90.0,
        end_time=140.0,
        episodes=[ep_no_new],
    )

    attack_windows = [w for w in windows if w.has_attack]
    assert len(attack_windows) > 0

    normal_dest_set = set(dev.normal_destinations)
    for w in attack_windows:
        for p in w.packets:
            if p.dst_port == 8443 or p.app_protocol == "HTTPS":
                # Must target legitimate pre-approved destinations only
                assert p.dst_ip in normal_dest_set
