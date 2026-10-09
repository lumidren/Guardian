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


class AttackSuite:
    def __init__(self) -> None:
        pass

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
        packets: list[ParsedPacket] = []

        if attack_type == AttackType.DDOS_FLOODING:
            # Scaled across tiers: Easy (volumetric flood), Medium (intermittent), Hard (stealthy)
            if tier == DifficultyTier.EASY:
                pkt_count = random.randint(950, 1300)
                len_min, len_max = 54, 80
            elif tier == DifficultyTier.MEDIUM:
                pkt_count = random.randint(300, 420)
                len_min, len_max = 60, 120
            else:  # HARD
                pkt_count = random.randint(35, 48)
                len_min, len_max = 64, 128

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
            c2_ip = "91.240.118.52"
            if tier == DifficultyTier.EASY:
                pkt_count = random.randint(25, 40)
            elif tier == DifficultyTier.MEDIUM:
                pkt_count = random.randint(8, 14)
            else:  # HARD
                pkt_count = random.randint(2, 4)

            for i in range(pkt_count):
                ts = start_time + (i * (window_duration / max(1, pkt_count)))
                packets.append(ParsedPacket(
                    timestamp=ts,
                    src_ip=victim_device.ip_address,
                    dst_ip=c2_ip,
                    src_mac=victim_device.mac_address,
                    dst_mac="B8:27:EB:AA:BB:CC",
                    src_port=random.randint(49152, 65535),
                    dst_port=8443,
                    protocol="TCP",
                    app_protocol="HTTPS",
                    length=random.randint(180, 240),
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
            elif tier == DifficultyTier.MEDIUM:
                pkt_count = 35
            else:  # HARD
                pkt_count = 8

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
            elif tier == DifficultyTier.MEDIUM:
                pkt_count = random.randint(100, 140)
                len_min, len_max = 480, 560
            else:  # HARD
                pkt_count = random.randint(12, 18)
                len_min, len_max = 100, 150

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
            elif tier == DifficultyTier.MEDIUM:
                pkt_count = random.randint(25, 35)
            else:  # HARD
                pkt_count = random.randint(6, 10)

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
            elif tier == DifficultyTier.MEDIUM:
                pkt_count = random.randint(180, 240)
            else:  # HARD
                pkt_count = random.randint(20, 30)

            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(ParsedPacket(
                    timestamp=ts,
                    src_ip=victim_device.ip_address,
                    dst_ip=moscow_ip,
                    src_mac=victim_device.mac_address,
                    dst_mac="B8:27:EB:AA:BB:CC",
                    src_port=random.randint(50000, 60000),
                    dst_port=80,
                    protocol="TCP",
                    app_protocol="HTTP",
                    length=random.randint(1200, 1480),
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
        Inject traffic matching legitimate device byte distribution and timing.
        - reuse_destinations: sends only to known authorized device destinations.
        - novel_destinations: sends to novel external IP while matching packet sizes and rates.
        """
        now = current_time or time.time()
        start_time = now - window_duration
        packets: list[ParsedPacket] = []

        base_rate = victim_device.normal_packet_rate
        pkt_count = max(2, int(random.gauss(base_rate, max(1.0, base_rate * 0.15))))
        timestamps = sorted([random.uniform(start_time, now) for _ in range(pkt_count)])

        if reuse_destinations:
            dst_ip = random.choice(victim_device.normal_destinations)
        else:
            dst_ip = "198.51.100.77"

        is_mqtt = victim_device.primary_protocol == "MQTT"
        dst_port = 1883 if is_mqtt else (80 if victim_device.primary_protocol == "HTTP" else 53)

        for ts in timestamps:
            length = random.randint(victim_device.normal_byte_range[0], victim_device.normal_byte_range[1])
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
        return packets

    def inject_low_and_slow_attack(
        self,
        victim_device: IoTDeviceSpec,
        window_duration: float = 10.0,
        current_time: float | None = None,
        bytes_per_hour: float = 360.0,
    ) -> list[ParsedPacket]:
        """
        Inject low-and-slow stealth exfiltration staying within tight hourly byte budgets.
        """
        now = current_time or time.time()
        start_time = now - window_duration
        packets: list[ParsedPacket] = []

        expected_bytes = (bytes_per_hour / 3600.0) * window_duration
        pkt_len = max(54, min(100, int(expected_bytes) + 54))
        ts = random.uniform(start_time, now)
        packets.append(ParsedPacket(
            timestamp=ts,
            src_ip=victim_device.ip_address,
            dst_ip="198.51.100.89",
            src_mac=victim_device.mac_address,
            dst_mac="B8:27:EB:AA:BB:CC",
            src_port=random.randint(49152, 65535),
            dst_port=443,
            protocol="TCP",
            app_protocol="HTTPS",
            length=pkt_len,
            ttl=64,
            ip_id=random.randint(1000, 60000),
            tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
            tcp_window=64240,
            tcp_timestamp=int(ts * 1000) % 4294967295,
            is_outbound=True,
        ))
        return packets

    def inject_adaptive_attack(
        self,
        victim_device: IoTDeviceSpec,
        current_threat_score: float,
        backoff_threshold: float = 45.0,
        window_duration: float = 10.0,
        current_time: float | None = None,
    ) -> list[ParsedPacket]:
        """
        Adaptive attacker: observes current threat score and ceases transmission when
        score exceeds backoff_threshold.
        """
        if current_threat_score > backoff_threshold:
            return []

        return self.inject_attack(
            attack_type=AttackType.CNC_BEACONING,
            victim_device=victim_device,
            window_duration=window_duration,
            current_time=current_time,
            tier="MEDIUM",
        )
