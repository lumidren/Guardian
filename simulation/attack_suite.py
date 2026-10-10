"""
Adversarial attack generation suite for GUARDIAN (Table 8).
Injects 6 distinct attack vectors into the telemetry pipeline.
"""

import random
import time
from enum import StrEnum
from typing import Any

from guardian.capture.packet_parser import ParsedPacket

from .fleet_emulator import IoTDeviceSpec


class AttackType(StrEnum):
    DDOS_FLOODING = "DDOS_FLOODING"
    CNC_BEACONING = "CNC_BEACONING"
    NETWORK_SCANNING = "NETWORK_SCANNING"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    CRYPTOMINING = "CRYPTOMINING"
    ZERO_DAY_HYBRID = "ZERO_DAY_HYBRID"


# Principled a-priori HARD tier specification defined before evaluation:
# All 6 attacks on HARD tier reuse whitelisted device destinations, avoid high-risk ports,
# match the victim device's normal payload byte range (within byte_scale), and inject
# packets at a small fraction (rate_fraction) of the device's normal_packet_rate.
HARD_TIER_SPEC: dict[AttackType, dict[str, Any]] = {
    AttackType.DDOS_FLOODING: {
        "use_whitelisted_destinations": True,
        "byte_scale": (0.90, 1.05),
        "rate_fraction": 0.35,
        "min_pkts": 2,
        "max_pkts": 4,
    },
    AttackType.CNC_BEACONING: {
        "use_whitelisted_destinations": True,
        "byte_scale": (0.95, 1.05),
        "rate_fraction": 0.20,
        "min_pkts": 1,
        "max_pkts": 2,
    },
    AttackType.NETWORK_SCANNING: {
        "use_whitelisted_destinations": True,
        "byte_scale": (0.95, 1.05),
        "rate_fraction": 0.20,
        "min_pkts": 1,
        "max_pkts": 2,
    },
    AttackType.DATA_EXFILTRATION: {
        "use_whitelisted_destinations": True,
        "byte_scale": (1.00, 1.15),
        "rate_fraction": 0.30,
        "min_pkts": 1,
        "max_pkts": 3,
    },
    AttackType.CRYPTOMINING: {
        "use_whitelisted_destinations": True,
        "byte_scale": (0.95, 1.10),
        "rate_fraction": 0.25,
        "min_pkts": 1,
        "max_pkts": 2,
    },
    AttackType.ZERO_DAY_HYBRID: {
        "use_whitelisted_destinations": True,
        "byte_scale": (0.95, 1.05),
        "rate_fraction": 0.15,
        "min_pkts": 1,
        "max_pkts": 2,
    },
}


def _whitelisted_ports_for_device(victim_device: IoTDeviceSpec) -> list[int]:
    """Return the legitimate protocol ports for the victim device to avoid port-allowlist triggers."""
    app_proto = victim_device.primary_protocol
    if app_proto == "MQTT":
        return [1883]
    if app_proto == "HTTP":
        return [80, 443]
    if app_proto == "RTSP":
        return [554]
    if app_proto == "CoAP":
        return [5683]
    return [80, 443, 1883]


class AttackSuite:
    def __init__(self) -> None:
        pass

    def _inject_hard_tier_covert_packets(
        self,
        attack_type: AttackType,
        victim_device: IoTDeviceSpec,
        start_time: float,
        window_duration: float,
    ) -> list[ParsedPacket]:
        """
        Generate HARD-tier covert attack packets strictly adhering to HARD_TIER_SPEC:
        whitelisted destinations, matched payload size distribution, and matched rate.
        """
        spec = HARD_TIER_SPEC[attack_type]
        base_rate = float(victim_device.normal_packet_rate)
        raw_count = int(round(base_rate * float(spec["rate_fraction"])))
        pkt_count = max(int(spec["min_pkts"]), min(int(spec["max_pkts"]), raw_count))

        min_b, max_b = victim_device.normal_byte_range
        scale_low, scale_high = spec["byte_scale"]
        len_min = max(48, int(round(min_b * scale_low)))
        len_max = max(len_min + 4, int(round(max_b * scale_high)))

        app_proto = victim_device.primary_protocol
        allowed_ports = _whitelisted_ports_for_device(victim_device)

        packets: list[ParsedPacket] = []
        for i in range(pkt_count):
            jitter = random.uniform(-0.15, 0.15) * (window_duration / max(1, pkt_count))
            base_ts = start_time + ((i + 0.5) * (window_duration / max(1, pkt_count)))
            ts = max(start_time, min(start_time + window_duration, base_ts + jitter))
            dst_ip = victim_device.normal_destinations[i % len(victim_device.normal_destinations)]
            dst_port = allowed_ports[i % len(allowed_ports)]

            packets.append(
                ParsedPacket(
                    timestamp=ts,
                    src_ip=victim_device.ip_address,
                    dst_ip=dst_ip,
                    src_mac=victim_device.mac_address,
                    dst_mac="B8:27:EB:AA:BB:CC",
                    src_port=random.randint(49152, 65535),
                    dst_port=dst_port,
                    protocol="TCP",
                    app_protocol=app_proto,
                    length=random.randint(len_min, len_max),
                    ttl=64,
                    ip_id=random.randint(1000, 60000),
                    tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                    tcp_window=64240,
                    tcp_timestamp=int(ts * 1000) % 4294967295,
                    is_outbound=True,
                )
            )
        packets.sort(key=lambda p: p.timestamp)
        return packets

    def inject_attack(
        self,
        attack_type: AttackType,
        victim_device: IoTDeviceSpec,
        window_duration: float = 10.0,
        current_time: float | None = None,
        tier: Any = None,
    ) -> list[ParsedPacket]:
        """
        Generate attack packet stream for the victim device matching the selected threat profile
        and difficulty tier (Easy, Medium, Hard).
        """
        from guardian.eval.scenario import DifficultyTier

        if tier is None:
            tier = DifficultyTier.MEDIUM

        now = current_time or time.time()
        start_time = now - window_duration

        if tier == DifficultyTier.HARD or str(tier) == "HARD":
            return self._inject_hard_tier_covert_packets(
                attack_type=attack_type,
                victim_device=victim_device,
                start_time=start_time,
                window_duration=window_duration,
            )

        packets: list[ParsedPacket] = []

        if attack_type == AttackType.DDOS_FLOODING:
            if tier == DifficultyTier.EASY:
                pkt_count = random.randint(950, 1300)
                len_min, len_max = 54, 80
            else:  # MEDIUM
                pkt_count = random.randint(300, 420)
                len_min, len_max = 60, 120

            target_ip = "203.0.113.50"
            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(ParsedPacket(
                    timestamp=ts,
                    src_ip=victim_device.ip_address,
                    dst_ip=target_ip,
                    src_mac=victim_device.mac_address,
                    dst_mac="B8:27:EB:AA:BB:CC",
                    src_port=random.randint(1024, 65535),
                    dst_port=80,
                    protocol="TCP",
                    app_protocol="HTTP",
                    length=random.randint(len_min, len_max),
                    ttl=64,
                    ip_id=random.randint(1, 65535),
                    tcp_flags={"SYN": True, "ACK": False, "PSH": False, "RST": False, "FIN": False, "URG": False},
                    tcp_window=1024,
                    tcp_timestamp=int(ts * 1000) % 4294967295,
                    is_outbound=True,
                ))

        elif attack_type == AttackType.CNC_BEACONING:
            if tier == DifficultyTier.EASY:
                c2_ip = "91.240.118.52"
                pkt_count = random.randint(25, 40)
                dst_port = 8443
                app_proto = "HTTPS"
                len_min, len_max = 180, 240
            else:  # MEDIUM
                c2_ip = "91.240.118.52"
                pkt_count = random.randint(8, 14)
                dst_port = 8443
                app_proto = "HTTPS"
                len_min, len_max = 180, 240

            for i in range(pkt_count):
                ts = start_time + (i * (window_duration / max(1, pkt_count)))
                packets.append(ParsedPacket(
                    timestamp=ts,
                    src_ip=victim_device.ip_address,
                    dst_ip=c2_ip,
                    src_mac=victim_device.mac_address,
                    dst_mac="B8:27:EB:AA:BB:CC",
                    src_port=random.randint(49152, 65535),
                    dst_port=dst_port,
                    protocol="TCP",
                    app_protocol=app_proto,
                    length=random.randint(len_min, len_max),
                    ttl=64,
                    ip_id=random.randint(1, 65535),
                    tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                    tcp_window=64240,
                    tcp_timestamp=int(ts * 1000) % 4294967295,
                    is_outbound=True,
                ))

        elif attack_type == AttackType.NETWORK_SCANNING:
            if tier == DifficultyTier.EASY:
                pkt_count = 120
            else:  # MEDIUM
                pkt_count = 35

            for i in range(pkt_count):
                ts = start_time + (i * (window_duration / max(1, pkt_count)))
                target_ip = f"192.168.1.{random.randint(2, 250)}"
                target_port = random.choice([21, 22, 23, 80, 443, 445, 8080, 5555])
                packets.append(ParsedPacket(
                    timestamp=ts,
                    src_ip=victim_device.ip_address,
                    dst_ip=target_ip,
                    src_mac=victim_device.mac_address,
                    dst_mac="B8:27:EB:AA:BB:CC",
                    src_port=random.randint(40000, 60000),
                    dst_port=target_port,
                    protocol="TCP",
                    app_protocol="OTHER",
                    length=60,
                    ttl=64,
                    ip_id=random.randint(1, 65535),
                    tcp_flags={"SYN": True, "ACK": False, "PSH": False, "RST": False, "FIN": False, "URG": False},
                    tcp_window=1024,
                    tcp_timestamp=int(ts * 1000) % 4294967295,
                    is_outbound=True,
                ))

        elif attack_type == AttackType.DATA_EXFILTRATION:
            exfil_ip = "198.51.100.89"
            if tier == DifficultyTier.EASY:
                pkt_count = random.randint(400, 600)
                len_min, len_max = 1420, 1500
            else:  # MEDIUM
                pkt_count = random.randint(100, 140)
                len_min, len_max = 480, 560

            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(ParsedPacket(
                    timestamp=ts,
                    src_ip=victim_device.ip_address,
                    dst_ip=exfil_ip,
                    src_mac=victim_device.mac_address,
                    dst_mac="B8:27:EB:AA:BB:CC",
                    src_port=52344,
                    dst_port=443,
                    protocol="TCP",
                    app_protocol="HTTPS",
                    length=random.randint(len_min, len_max),
                    ttl=64,
                    ip_id=random.randint(1, 65535),
                    tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                    tcp_window=65535,
                    tcp_timestamp=int(ts * 1000) % 4294967295,
                    is_outbound=True,
                ))

        elif attack_type == AttackType.CRYPTOMINING:
            pool_ip = "144.76.12.18"
            if tier == DifficultyTier.EASY:
                pkt_count = random.randint(80, 120)
            else:  # MEDIUM
                pkt_count = random.randint(25, 35)

            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(ParsedPacket(
                    timestamp=ts,
                    src_ip=victim_device.ip_address,
                    dst_ip=pool_ip,
                    src_mac=victim_device.mac_address,
                    dst_mac="B8:27:EB:AA:BB:CC",
                    src_port=55123,
                    dst_port=4444,
                    protocol="TCP",
                    app_protocol="OTHER",
                    length=random.randint(300, 700),
                    ttl=64,
                    ip_id=random.randint(1, 65535),
                    tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                    tcp_window=29200,
                    tcp_timestamp=int(ts * 1000) % 4294967295,
                    is_outbound=True,
                ))

        elif attack_type == AttackType.ZERO_DAY_HYBRID:
            moscow_ip = "185.220.101.47"
            if tier == DifficultyTier.EASY:
                pkt_count = random.randint(800, 900)
            else:  # MEDIUM
                pkt_count = random.randint(180, 240)
            dst_port = 80
            app_proto = "HTTP"
            len_min, len_max = 1200, 1480

            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(ParsedPacket(
                    timestamp=ts,
                    src_ip=victim_device.ip_address,
                    dst_ip=moscow_ip,
                    src_mac=victim_device.mac_address,
                    dst_mac="B8:27:EB:AA:BB:CC",
                    src_port=random.randint(50000, 60000),
                    dst_port=dst_port,
                    protocol="TCP",
                    app_protocol=app_proto,
                    length=random.randint(len_min, len_max),
                    ttl=64,
                    ip_id=random.randint(1, 65535),
                    tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                    tcp_window=64240,
                    tcp_timestamp=int(ts * 1000) % 4294967295,
                    is_outbound=True,
                ))

        packets.sort(key=lambda p: p.timestamp)
        return packets

    def inject_mimicry_attack(
        self,
        victim_device: IoTDeviceSpec,
        window_duration: float = 10.0,
        current_time: float | None = None,
        reuse_destinations: bool = True,
    ) -> list[ParsedPacket]:
        """
        Inject hardened mimicry traffic matching legitimate device byte distribution,
        whitelisted destinations, protocol ports, and covert fractional packet rate.
        - reuse_destinations: sends only to known authorized device destinations.
        - novel_destinations: sends to novel external IP while matching packet sizes and rates.
        """
        now = current_time or time.time()
        start_time = now - window_duration
        packets: list[ParsedPacket] = []

        base_rate = float(victim_device.normal_packet_rate)
        pkt_count = max(1, min(2, int(round(base_rate * 0.20))))
        allowed_ports = _whitelisted_ports_for_device(victim_device)
        min_b, max_b = victim_device.normal_byte_range

        for i in range(pkt_count):
            jitter = random.uniform(-0.10, 0.10) * (window_duration / max(1, pkt_count))
            base_ts = start_time + ((i + 0.5) * (window_duration / max(1, pkt_count)))
            ts = max(start_time, min(now, base_ts + jitter))
            if reuse_destinations:
                dst_ip = victim_device.normal_destinations[i % len(victim_device.normal_destinations)]
            else:
                dst_ip = "198.51.100.77"
            dst_port = allowed_ports[i % len(allowed_ports)]
            length = random.randint(min_b, max_b)
            pkt = ParsedPacket(
                timestamp=ts,
                src_ip=victim_device.ip_address,
                dst_ip=dst_ip,
                src_mac=victim_device.mac_address,
                dst_mac="B8:27:EB:AA:BB:CC",
                src_port=random.randint(49152, 65535),
                dst_port=dst_port,
                protocol="TCP",
                app_protocol=victim_device.primary_protocol,
                length=length,
                ttl=64,
                ip_id=random.randint(1000, 60000),
                tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                tcp_window=64240,
                tcp_timestamp=int(ts * 1000) % 4294967295,
                is_outbound=True,
            )
            packets.append(pkt)
        packets.sort(key=lambda p: p.timestamp)
        return packets

    def inject_low_and_slow_attack(
        self,
        victim_device: IoTDeviceSpec,
        window_duration: float = 10.0,
        current_time: float | None = None,
        bytes_per_hour: float = 360.0,
    ) -> list[ParsedPacket]:
        """
        Inject hardened low-and-slow stealth exfiltration staying within tight hourly byte budgets,
        reusing whitelisted destinations, legitimate protocol ports, and matched byte range.
        """
        now = current_time or time.time()
        start_time = now - window_duration
        packets: list[ParsedPacket] = []

        min_b, max_b = victim_device.normal_byte_range
        expected_bytes = (bytes_per_hour / 3600.0) * window_duration
        pkt_len = max(min_b, min(max_b, int(round(min_b + expected_bytes))))
        dst_ip = victim_device.normal_destinations[0]
        dst_port = _whitelisted_ports_for_device(victim_device)[0]
        ts = start_time + 0.5 * window_duration + random.uniform(-0.1, 0.1) * window_duration
        ts = max(start_time, min(now, ts))
        packets.append(
            ParsedPacket(
                timestamp=ts,
                src_ip=victim_device.ip_address,
                dst_ip=dst_ip,
                src_mac=victim_device.mac_address,
                dst_mac="B8:27:EB:AA:BB:CC",
                src_port=random.randint(49152, 65535),
                dst_port=dst_port,
                protocol="TCP",
                app_protocol=victim_device.primary_protocol,
                length=pkt_len,
                ttl=64,
                ip_id=random.randint(1000, 60000),
                tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                tcp_window=64240,
                tcp_timestamp=int(ts * 1000) % 4294967295,
                is_outbound=True,
            )
        )
        return packets

    def inject_delayed_start_attack(
        self,
        attack_type: AttackType,
        victim_device: IoTDeviceSpec,
        episode_start_time: float,
        episode_duration: float,
        window_start: float,
        window_end: float,
    ) -> list[ParsedPacket]:
        """
        Inject hardened delayed-start attack: remains completely dormant during the
        initial 50% of the episode (up to 30.0s) so baseline sliding windows remain
        unperturbed, then injects covert whitelisted HARD-tier packets.
        """
        dormant_duration = min(30.0, episode_duration * 0.5)
        active_start = episode_start_time + dormant_duration
        if window_end <= active_start:
            return []
        overlap_start = max(window_start, active_start)
        overlap_dur = max(0.1, window_end - overlap_start)
        raw = self._inject_hard_tier_covert_packets(
            attack_type=attack_type,
            victim_device=victim_device,
            start_time=overlap_start,
            window_duration=overlap_dur,
        )
        return raw[: max(1, int(len(raw) * 0.65))]

    def inject_no_new_destination_attack(
        self,
        attack_type: AttackType,
        victim_device: IoTDeviceSpec,
        window_duration: float = 10.0,
        current_time: float | None = None,
    ) -> list[ParsedPacket]:
        """
        Inject hardened no-new-destination attack: strictly reuses pre-approved
        victim_device.normal_destinations and whitelisted protocol ports with matched
        payload sizes so new_dst_ip_flag == 0 and high_risk_port_flag == 0.
        """
        now = current_time or time.time()
        start_time = now - window_duration
        raw = self._inject_hard_tier_covert_packets(
            attack_type=attack_type,
            victim_device=victim_device,
            start_time=start_time,
            window_duration=window_duration,
        )
        allowed_ports = _whitelisted_ports_for_device(victim_device)
        for idx, p in enumerate(raw):
            p.dst_ip = victim_device.normal_destinations[idx % len(victim_device.normal_destinations)]
            p.dst_port = allowed_ports[idx % len(allowed_ports)]
            p.app_protocol = victim_device.primary_protocol
        return raw[: max(1, int(len(raw) * 0.65))]

    def inject_adaptive_attack(
        self,
        victim_device: IoTDeviceSpec,
        current_threat_score: float,
        backoff_threshold: float = 45.0,
        window_duration: float = 10.0,
        current_time: float | None = None,
        attack_type: AttackType = AttackType.CNC_BEACONING,
    ) -> list[ParsedPacket]:
        """
        Adaptive attacker with closed-loop threat score feedback:
        - Ceases transmission completely when current_threat_score > backoff_threshold.
        - Throttles to a single covert whitelisted packet when score > 0.6 * backoff_threshold.
        - Otherwise injects covert HARD-tier whitelisted packets.
        """
        if current_threat_score > backoff_threshold:
            return []

        now = current_time or time.time()
        start_time = now - window_duration
        raw = self._inject_hard_tier_covert_packets(
            attack_type=attack_type,
            victim_device=victim_device,
            start_time=start_time,
            window_duration=window_duration,
        )
        if current_threat_score > 0.6 * backoff_threshold:
            return raw[:1]
        return raw[: max(1, int(len(raw) * 0.65))]
