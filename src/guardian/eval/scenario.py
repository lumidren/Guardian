"""
Evaluation Scenario Builder and Ground Truth Stream Generator.

Produces seeded multi-day synthetic streams with time-ordered splits:
- Days 1 to 7: TRAIN (baseline and model training)
- Day 8: CALIBRATION (operating point threshold selection)
- Days 9 to 14: TEST (attack episodes and clean stretches)

Crucially fixes audit finding F5 by injecting attack packets directly into
the running normal traffic stream, ensuring attack windows always contain
realistic background normal traffic.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum

import numpy as np

from ..capture.packet_parser import ParsedPacket


class SplitType(StrEnum):
    TRAIN = "TRAIN"
    CALIBRATION = "CALIBRATION"
    TEST = "TEST"


class AttackIntensity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class DifficultyTier(StrEnum):
    EASY = "EASY"
    MEDIUM = "MEDIUM"
    HARD = "HARD"


class EvasionMode(StrEnum):
    NONE = "NONE"
    MIMICRY = "MIMICRY"
    LOW_AND_SLOW = "LOW_AND_SLOW"
    DELAYED_START = "DELAYED_START"
    NO_NEW_DESTINATION = "NO_NEW_DESTINATION"
    ADAPTIVE = "ADAPTIVE"


class HardNegativeType(StrEnum):
    FIRMWARE_UPDATE = "FIRMWARE_UPDATE"
    USER_TOGGLING = "USER_TOGGLING"
    REBOOT_STORM = "REBOOT_STORM"
    DNS_RETRY_STORM = "DNS_RETRY_STORM"
    NTP_BURSTS = "NTP_BURSTS"
    MQTT_RECONNECT_FLOOD = "MQTT_RECONNECT_FLOOD"
    CAMERA_MOTION_BURST = "CAMERA_MOTION_BURST"
    ROUTER_REBOOT = "ROUTER_REBOOT"
    NEW_CLOUD_ENDPOINT = "NEW_CLOUD_ENDPOINT"
    DST_CHANGE = "DST_CHANGE"


from simulation.attack_suite import AttackSuite, AttackType  # noqa: E402
from simulation.fleet_emulator import (  # noqa: E402
    DEFAULT_FLEET_SPECS,
    IoTDeviceSpec,
    IoTFleetEmulator,
)


@dataclass(frozen=True)
class GroundTruthEpisode:
    episode_id: str
    device_id: str
    attack_type: AttackType
    start_time: float
    end_time: float
    duration_seconds: float
    intensity: AttackIntensity
    evasion_mode: EvasionMode
    tier: DifficultyTier = DifficultyTier.MEDIUM


@dataclass
class StreamWindow:
    device_id: str
    start_time: float
    end_time: float
    packets: list[ParsedPacket] = field(default_factory=list)
    has_attack: bool = False
    active_episode_ids: list[str] = field(default_factory=list)
    normal_packet_count: int = 0
    attack_packet_count: int = 0


def calculate_sub_window_offset(stride_s: float = 2.0, rng: np.random.Generator | None = None) -> float:
    """
    Computes a random sub-window offset delta in (0.2, stride_s - 0.2) seconds.
    Ensures that attack episode start times do not fall precisely on window stride
    boundaries, making time-to-detect (TTD) strictly non-zero by physical construction.
    """
    generator = rng if rng is not None else np.random.default_rng()
    min_off = min(0.2, stride_s * 0.1)
    max_off = max(min_off + 0.1, stride_s - min_off)
    return float(generator.uniform(min_off, max_off))


class ScenarioBuilder:
    """
    Constructs deterministic multi-day network streams and ground truth attack schedules.
    """

    SECONDS_PER_DAY = 86400.0

    def __init__(
        self,
        seed: int = 42,
        total_days: int = 14,
        window_size_s: float = 10.0,
        stride_s: float = 2.0,
        devices: Sequence[IoTDeviceSpec] | None = None,
    ) -> None:
        self.seed = seed
        self.total_days = total_days
        self.window_size_s = window_size_s
        self.stride_s = stride_s
        self.devices = list(devices or DEFAULT_FLEET_SPECS)
        self.emulator = IoTFleetEmulator()
        self.attack_suite = AttackSuite()

    def get_split(self, timestamp: float) -> SplitType:
        """Map simulation timestamp to strict time-ordered split."""
        day = timestamp / self.SECONDS_PER_DAY
        if day < 7.0:
            return SplitType.TRAIN
        if day < 8.0:
            return SplitType.CALIBRATION
        return SplitType.TEST

    def generate_ground_truth_schedule(
        self,
        episodes_per_attack: int = 50,
        min_gap_seconds: float = 120.0,
        attack_types: Sequence[AttackType] | None = None,
        tiers: Sequence[DifficultyTier] | None = None,
        episodes_per_tier: int | None = None,
    ) -> list[GroundTruthEpisode]:
        """
        Generate deterministic ground truth schedule across test days (Days 9-14).
        Attacks are strictly barred from Train (Days 1-7) and Calibration (Day 8).
        Supports multi-tier schedules across all 6 attacks x 3 tiers (EASY, MEDIUM, HARD).
        """
        rng = np.random.default_rng(self.seed)
        attacks = list(attack_types or list(AttackType))
        intensities = [AttackIntensity.LOW, AttackIntensity.MEDIUM, AttackIntensity.HIGH]
        evasion_modes = [EvasionMode.NONE]  # Default standard attacks

        # Test phase boundary: Day 8.0 to Day total_days
        test_start_time = 8.0 * self.SECONDS_PER_DAY
        test_end_time = float(self.total_days) * self.SECONDS_PER_DAY

        episodes: list[GroundTruthEpisode] = []
        episode_idx = 0
        valid_devs = self.devices

        # Build list of planned episodes (balanced across attack types, tiers, and intensities)
        planned_runs: list[tuple[AttackType, AttackIntensity, EvasionMode, IoTDeviceSpec, DifficultyTier]] = []
        if tiers is not None:
            tier_list = list(tiers)
            target_eps = episodes_per_tier if episodes_per_tier is not None else max(1, episodes_per_attack // len(tier_list))
            for atk in attacks:
                for tier in tier_list:
                    for i in range(target_eps):
                        intensity = intensities[i % len(intensities)]
                        dev = valid_devs[(i + int(atk.value.__hash__())) % len(valid_devs)]
                        evasion = evasion_modes[0]
                        planned_runs.append((atk, intensity, evasion, dev, tier))
        else:
            for atk in attacks:
                for i in range(episodes_per_attack):
                    intensity = intensities[i % len(intensities)]
                    dev = valid_devs[i % len(valid_devs)]
                    evasion = evasion_modes[0]
                    planned_runs.append((atk, intensity, evasion, dev, DifficultyTier.MEDIUM))

        # Shuffle planned runs deterministically
        shuffled_indices = rng.permutation(len(planned_runs))

        # Schedule episodes across available test time window with balanced gaps
        total_span = test_end_time - test_start_time - 600.0
        step_interval = total_span / max(1, len(planned_runs))
        current_time = test_start_time + 300.0

        for k, idx in enumerate(shuffled_indices):
            atk, intensity, evasion, dev, tier = planned_runs[idx]
            # Duration between 30s and 90s
            duration = 30.0 + (int(rng.integers(0, 7)) * 10.0)
            base_start = current_time + (k * step_interval) + float(rng.uniform(0.0, max(1.0, step_interval * 0.1)))
            aligned_base = float(np.floor(base_start / self.stride_s) * self.stride_s)
            # Apply random sub-window offset ensuring TTD cannot be 0.0s by design
            offset = calculate_sub_window_offset(stride_s=self.stride_s, rng=rng)
            start_t = round(aligned_base + offset, 3)
            end_t = round(start_t + duration, 3)

            if end_t >= test_end_time - 60.0:
                break

            episodes.append(
                GroundTruthEpisode(
                    episode_id=f"ep_{episode_idx:04d}_{atk.name.lower()}_{tier.value.lower()}",
                    device_id=dev.id,
                    attack_type=atk,
                    start_time=start_t,
                    end_time=end_t,
                    duration_seconds=duration,
                    intensity=intensity,
                    evasion_mode=evasion,
                    tier=tier,
                )
            )
            episode_idx += 1

        return episodes

    def create_offset_episode(
        self,
        episode_id: str,
        device_id: str,
        attack_type: AttackType,
        base_start_time: float,
        duration_seconds: float,
        intensity: AttackIntensity = AttackIntensity.MEDIUM,
        evasion_mode: EvasionMode = EvasionMode.NONE,
        tier: DifficultyTier = DifficultyTier.MEDIUM,
        rng: np.random.Generator | None = None,
    ) -> GroundTruthEpisode:
        """Helper to create an episode with a guaranteed sub-window start offset."""
        offset = calculate_sub_window_offset(stride_s=self.stride_s, rng=rng)
        aligned_base = float(np.floor(base_start_time / self.stride_s) * self.stride_s)
        start_t = round(aligned_base + offset, 3)
        end_t = round(start_t + duration_seconds, 3)
        return GroundTruthEpisode(
            episode_id=episode_id,
            device_id=device_id,
            attack_type=attack_type,
            start_time=start_t,
            end_time=end_t,
            duration_seconds=duration_seconds,
            intensity=intensity,
            evasion_mode=evasion_mode,
            tier=tier,
        )

    def generate_device_stream_windows(
        self,
        device_id: str,
        start_time: float,
        end_time: float,
        episodes: Sequence[GroundTruthEpisode],
    ) -> list[StreamWindow]:
        """
        Generate continuous stream windows for a device, injecting attack packets
        into the live normal stream whenever an episode is active.
        """
        dev = next((d for d in self.devices if d.id == device_id or d.ip_address == device_id), None)
        if not dev:
            raise ValueError(f"Unknown device: {device_id}")

        # Filter episodes applicable to this device and time span
        dev_episodes = [
            ep
            for ep in episodes
            if ep.device_id == dev.id and not (ep.end_time < start_time or ep.start_time > end_time)
        ]

        windows: list[StreamWindow] = []
        cur_t = start_time

        while cur_t + self.window_size_s <= end_time:
            w_start = cur_t
            w_end = cur_t + self.window_size_s

            # 1. Generate normal background traffic for this window
            normal_pkts = self.emulator.generate_normal_window_packets(
                device=dev,
                window_duration=self.window_size_s,
                current_time=w_end,
            )

            # 2. Check for active attack episodes overlapping with this window
            active_eps = [
                ep for ep in dev_episodes if not (ep.end_time <= w_start or ep.start_time >= w_end)
            ]

            attack_pkts: list[ParsedPacket] = []
            if active_eps:
                for ep in active_eps:
                    # 1. Delayed start check: dormant initial phase
                    dormant_duration = (
                        min(30.0, ep.duration_seconds * 0.5)
                        if ep.evasion_mode == EvasionMode.DELAYED_START
                        else 0.0
                    )
                    active_start = ep.start_time + dormant_duration
                    if w_end <= active_start:
                        continue

                    raw_attack = self.attack_suite.inject_attack(
                        attack_type=ep.attack_type,
                        victim_device=dev,
                        tier=ep.tier,
                    )
                    # Scale packets by intensity and evasion mode
                    multiplier = (
                        0.5
                        if ep.intensity == AttackIntensity.LOW
                        else (2.0 if ep.intensity == AttackIntensity.HIGH else 1.0)
                    )
                    if ep.evasion_mode == EvasionMode.LOW_AND_SLOW:
                        multiplier *= 0.15

                    target_count = max(
                        2 if ep.evasion_mode == EvasionMode.LOW_AND_SLOW else 5,
                        int(len(raw_attack) * multiplier),
                    )
                    sample_attack = raw_attack[:target_count]

                    # Interpolate attack packet timestamps within overlapping active portion
                    overlap_start = max(w_start, active_start)
                    overlap_end = min(w_end, ep.end_time)
                    if overlap_end <= overlap_start:
                        continue
                    overlap_duration = max(0.1, overlap_end - overlap_start)

                    min_b, max_b = dev.normal_byte_range

                    for j, p in enumerate(sample_attack):
                        p.timestamp = overlap_start + (j / max(1, len(sample_attack))) * overlap_duration
                        if p.tcp_timestamp is not None:
                            p.tcp_timestamp = int(p.timestamp * 1000) % 4294967295

                        # Evasion Mode: Mimicry (match legitimate packet size distribution)
                        if ep.evasion_mode == EvasionMode.MIMICRY:
                            p.length = int(min_b + (j % (max(1, max_b - min_b + 1))))

                        # Evasion Mode: No New Destination (exploit legitimate approved endpoints)
                        if ep.evasion_mode == EvasionMode.NO_NEW_DESTINATION:
                            p.dst_ip = dev.normal_destinations[j % len(dev.normal_destinations)]

                        attack_pkts.append(p)

            # 3. Merge normal and attack packets and sort chronologically
            all_pkts = normal_pkts + attack_pkts
            all_pkts.sort(key=lambda p: p.timestamp)

            has_attack = len(attack_pkts) > 0
            windows.append(
                StreamWindow(
                    device_id=dev.id,
                    start_time=w_start,
                    end_time=w_end,
                    packets=all_pkts,
                    has_attack=has_attack,
                    active_episode_ids=[ep.episode_id for ep in active_eps if has_attack],
                    normal_packet_count=len(normal_pkts),
                    attack_packet_count=len(attack_pkts),
                )
            )

            cur_t += self.stride_s

        return windows
