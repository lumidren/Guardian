"""
Adversarial attack generation suite for GUARDIAN (Table 8).
Injects 6 distinct attack vectors into the telemetry pipeline.
"""

import random
import time
from enum import Enum
from typing import Dict, List, Optional
from ..capture.packet_parser import ParsedPacket
from .fleet_emulator import IoTDeviceSpec


class AttackType(str, Enum):
    DDOS_FLOODING = "DDOS_FLOODING"
    CNC_BEACONING = "CNC_BEACONING"
    NETWORK_SCANNING = "NETWORK_SCANNING"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    CRYPTOMINING = "CRYPTOMINING"
    ZERO_DAY_HYBRID = "ZERO_DAY_HYBRID"


class AttackSuite:
    def __init__(self):
        pass

    def inject_attack(
        self,
        attack_type: AttackType,
        victim_device: IoTDeviceSpec,
        window_duration: float = 10.0,
        current_time: Optional[float] = None
    ) -> List[ParsedPacket]:
        """
        Generate attack packet stream for the victim device matching the selected threat profile.
        """
        now = current_time or time.time()
        start_time = now - window_duration
        packets: List[ParsedPacket] = []

        if attack_type == AttackType.DDOS_FLOODING:
            # 800-1500 SYN packets in 10 seconds targeting external victim
            pkt_count = random.randint(850, 1400)
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
                    length=random.randint(54, 80),
                    ttl=64,
                    ip_id=random.randint(1, 65535),
                    tcp_flags={"SYN": True, "ACK": False, "PSH": False, "RST": False, "FIN": False, "URG": False},
                    tcp_window=1024,
                    tcp_timestamp=int(ts * 1000) % 4294967295,
                    is_outbound=True
                ))

        elif attack_type == AttackType.CNC_BEACONING:
            # Periodic beaconing to unknown foreign C2 endpoint (every 1s)
            c2_ip = "91.240.118.52"
            pkt_count = random.randint(25, 40)
            for i in range(pkt_count):
                ts = start_time + (i * (window_duration / pkt_count))
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
                    is_outbound=True
                ))

        elif attack_type == AttackType.NETWORK_SCANNING:
            # Internal lateral reconnaissance probing 25 distinct subnet IPs and ports
            pkt_count = 120
            for i in range(pkt_count):
                ts = start_time + (i * (window_duration / pkt_count))
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
                    is_outbound=True
                ))

        elif attack_type == AttackType.DATA_EXFILTRATION:
            # Sustained bulk transfer of large video/sensor data to external cloud drop
            exfil_ip = "198.51.100.89"
            pkt_count = random.randint(400, 600)
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
                    length=random.randint(1420, 1500), # Full MTU
                    ttl=64,
                    ip_id=random.randint(1, 65535),
                    tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                    tcp_window=65535,
                    tcp_timestamp=int(ts * 1000) % 4294967295,
                    is_outbound=True
                ))

        elif attack_type == AttackType.CRYPTOMINING:
            # Connection to Stratum mining pool on high-risk port 4444
            pool_ip = "144.76.12.18"
            pkt_count = random.randint(80, 120)
            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(ParsedPacket(
                    timestamp=ts,
                    src_ip=victim_device.ip_address,
                    dst_ip=pool_ip,
                    src_mac=victim_device.mac_address,
                    dst_mac="B8:27:EB:AA:BB:CC",
                    src_port=55123,
                    dst_port=4444, # High-risk mining port
                    protocol="TCP",
                    app_protocol="OTHER",
                    length=random.randint(300, 700),
                    ttl=64,
                    ip_id=random.randint(1, 65535),
                    tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                    tcp_window=29200,
                    tcp_timestamp=int(ts * 1000) % 4294967295,
                    is_outbound=True
                ))

        elif attack_type == AttackType.ZERO_DAY_HYBRID:
            # The 7,000 Robot Vacuums Real-World Breach (Section 2.2.3 & 4.3.3)
            # 3:47 AM, Moscow IP 185.220.101.47, 850 packets in 10s, 100% HTTP video stream
            pkt_count = 850
            moscow_ip = "185.220.101.47"
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
                    app_protocol="HTTP", # Protocol switch from MQTT -> HTTP
                    length=random.randint(1200, 1480), # Heavy video chunks
                    ttl=64,
                    ip_id=random.randint(1, 65535),
                    tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                    tcp_window=64240,
                    tcp_timestamp=int(ts * 1000) % 4294967295,
                    is_outbound=True
                ))

        packets.sort(key=lambda p: p.timestamp)
        return packets
