"""
Unit tests for Milestone P3-2: Simulator Realism v2.

Tests:
1. Difficulty tiers (Easy, Medium, Hard) across all attack vectors.
2. True mimicry: two-sample statistical test between mimicry and normal traffic distributions.
3. Mimicry sub-modes (reuse known destinations vs novel destinations).
4. Low-and-slow exfiltration with tunable bytes per hour.
5. Delayed start after quiet observation period.
6. Adaptive attacker score-observation backoff.
7. Hard negatives: benign anomalies that must not cause false alarms.
8. Heterogeneity and per-device parameter variation.
"""

import numpy as np

from guardian.eval.scenario import (
    AttackIntensity,
    DifficultyTier,
    EvasionMode,
    GroundTruthEpisode,
    HardNegativeType,
    ScenarioBuilder,
)
from simulation.attack_suite import AttackSuite, AttackType
from simulation.fleet_emulator import DEFAULT_FLEET_SPECS, IoTFleetEmulator


def test_difficulty_tiers_scaling() -> None:
    """
    Verify that Easy, Medium, and Hard tiers scale packet volume and stealth appropriately.
    Hard tier must stay significantly closer to normal baseline rates than Easy tier.
    """
    attack_suite = AttackSuite()
    dev = DEFAULT_FLEET_SPECS[0]  # Temperature sensor

    easy_pkts = attack_suite.inject_attack(
        attack_type=AttackType.DDOS_FLOODING,
        victim_device=dev,
        tier=DifficultyTier.EASY,
    )
    medium_pkts = attack_suite.inject_attack(
        attack_type=AttackType.DDOS_FLOODING,
        victim_device=dev,
        tier=DifficultyTier.MEDIUM,
    )
    hard_pkts = attack_suite.inject_attack(
        attack_type=AttackType.DDOS_FLOODING,
        victim_device=dev,
        tier=DifficultyTier.HARD,
    )

    assert len(easy_pkts) > len(medium_pkts) > len(hard_pkts), (
        f"Tier scaling violated: easy={len(easy_pkts)}, med={len(medium_pkts)}, hard={len(hard_pkts)}"
    )
    # Hard tier should be at least 5x smaller than Easy tier for DDoS
    assert len(easy_pkts) >= 5 * len(hard_pkts)


def test_true_mimicry_distribution_test() -> None:
    """
    True mimicry test:
    Two-sample statistical comparison between normal traffic and mimicry traffic.
    First and second order statistics of packet length must show minimal difference.
    """
    emulator = IoTFleetEmulator()
    attack_suite = AttackSuite()
    dev = DEFAULT_FLEET_SPECS[0]

    normal_pkts = emulator.generate_normal_window_packets(dev, window_duration=30.0)
    mimic_pkts = attack_suite.inject_mimicry_attack(
        victim_device=dev,
        window_duration=30.0,
        reuse_destinations=True,
    )

    normal_lens = np.array([p.length for p in normal_pkts], dtype=float)
    mimic_lens = np.array([p.length for p in mimic_pkts], dtype=float)

    assert len(normal_lens) > 0
    assert len(mimic_lens) > 0

    # First order: mean packet length difference must be small (< 25 bytes)
    mean_diff = abs(float(np.mean(normal_lens)) - float(np.mean(mimic_lens)))
    assert mean_diff < 25.0, f"Mimicry failed first-order mean test: diff={mean_diff:.2f}"

    # Second order: std deviation difference must be small (< 25 bytes)
    std_diff = abs(float(np.std(normal_lens)) - float(np.std(mimic_lens)))
    assert std_diff < 25.0, f"Mimicry failed second-order std test: diff={std_diff:.2f}"


def test_mimicry_destination_submodes() -> None:
    """
    Test two mimicry sub-modes:
    1. reuse_destinations: traffic sent only to pre-approved device normal destinations.
    2. novel_destinations: traffic sent to external IP, but with matched rates/sizes.
    """
    attack_suite = AttackSuite()
    dev = DEFAULT_FLEET_SPECS[0]

    pkts_reuse = attack_suite.inject_mimicry_attack(
        victim_device=dev,
        window_duration=10.0,
        reuse_destinations=True,
    )
    for p in pkts_reuse:
        assert p.dst_ip in dev.normal_destinations, f"Expected normal destination, got {p.dst_ip}"

    pkts_novel = attack_suite.inject_mimicry_attack(
        victim_device=dev,
        window_duration=10.0,
        reuse_destinations=False,
    )
    has_novel = any(p.dst_ip not in dev.normal_destinations for p in pkts_novel)
    assert has_novel, "Expected novel destination in novel_destinations mode"


def test_low_and_slow_exfiltration_rate() -> None:
    """
    Verify low-and-slow exfiltration generates minimal, stealthy byte volume.
    """
    attack_suite = AttackSuite()
    dev = DEFAULT_FLEET_SPECS[0]

    pkts = attack_suite.inject_low_and_slow_attack(
        victim_device=dev,
        window_duration=10.0,
        bytes_per_hour=360,
    )
    total_bytes = sum(p.length for p in pkts)
    # In a 10s slice, 360 bytes/hour is ~1 byte/sec -> ~10 bytes on average
    assert total_bytes <= 150, f"Low-and-slow volume too high: {total_bytes} bytes in 10s"


def test_delayed_start_dormancy() -> None:
    """
    Verify delayed start produces zero attack packets during initial dormant window.
    """
    sb = ScenarioBuilder(seed=42, total_days=1)
    dev = DEFAULT_FLEET_SPECS[0]
    ep = GroundTruthEpisode(
        episode_id="ep_test_delayed",
        device_id=dev.id,
        attack_type=AttackType.CNC_BEACONING,
        start_time=10.0,
        end_time=50.0,
        duration_seconds=40.0,
        intensity=AttackIntensity.MEDIUM,
        evasion_mode=EvasionMode.DELAYED_START,
        tier=DifficultyTier.MEDIUM,
    )

    windows = sb.generate_device_stream_windows(
        device_id=dev.id,
        start_time=0.0,
        end_time=60.0,
        episodes=[ep],
    )

    # Windows overlapping start_time=10.0 to 20.0 should be dormant (0 attack packets)
    dormant_windows = [w for w in windows if 10.0 <= w.start_time < 20.0]
    assert len(dormant_windows) > 0
    for w in dormant_windows:
        assert w.attack_packet_count == 0, (
            f"Attack packets found during delayed-start dormant period at {w.start_time}"
        )


def test_adaptive_attacker_backoff() -> None:
    """
    Test adaptive attacker backs off when threat score exceeds threshold.
    """
    attack_suite = AttackSuite()
    dev = DEFAULT_FLEET_SPECS[0]

    # When score is low (20), attacker injects traffic
    pkts_active = attack_suite.inject_adaptive_attack(
        victim_device=dev,
        current_threat_score=20.0,
        backoff_threshold=45.0,
    )
    assert len(pkts_active) > 0

    # When score is high (65), attacker backs off completely (0 packets)
    pkts_backed_off = attack_suite.inject_adaptive_attack(
        victim_device=dev,
        current_threat_score=65.0,
        backoff_threshold=45.0,
    )
    assert len(pkts_backed_off) == 0


def test_hard_negatives_generation() -> None:
    """
    Verify benign hard negatives (firmware updates, reboot storms, toggles) generate
    valid benign packet profiles matching authorized destinations.
    """
    emulator = IoTFleetEmulator()
    dev = DEFAULT_FLEET_SPECS[0]

    fw_pkts = emulator.generate_hard_negative_packets(
        device=dev,
        negative_type=HardNegativeType.FIRMWARE_UPDATE,
        window_duration=10.0,
    )
    assert len(fw_pkts) > 0
    # Firmware download uses HTTPS port 443
    assert any(p.dst_port == 443 for p in fw_pkts)

    reboot_pkts = emulator.generate_hard_negative_packets(
        device=dev,
        negative_type=HardNegativeType.REBOOT_STORM,
        window_duration=10.0,
    )
    assert len(reboot_pkts) > 0
    # Reboot storm emits broadcast ARP / DHCP
    assert any("255" in p.dst_ip or "192.168.1.1" in p.dst_ip for p in reboot_pkts)


def test_fleet_heterogeneity_specs() -> None:
    """
    Verify heterogeneity and per-device parameter variation in simulated IoT fleet.
    """
    emulator = IoTFleetEmulator()
    assert len(emulator.specs) >= 8
    rates = [s.normal_packet_rate for s in emulator.specs]
    assert len(set(rates)) >= 4
    byte_ranges = [s.normal_byte_range for s in emulator.specs]
    assert len(set(byte_ranges)) >= 4

