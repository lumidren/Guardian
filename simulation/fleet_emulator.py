"""
Virtual IoT Fleet Emulator for GUARDIAN.
Emulates 8 protected IoT devices generating realistic, continuous network telemetry (Section 4.1.1).
"""

import random
import time
from dataclasses import dataclass
from typing import Any

from guardian.capture.packet_parser import ParsedPacket


@dataclass
class IoTDeviceSpec:
    id: str
    name: str
    device_type: str
    ip_address: str
    mac_address: str
    hardware: str
    primary_protocol: str
    normal_destinations: list[str]
    normal_packet_rate: float       # pkts per 10s
    normal_byte_range: tuple        # (min_bytes, max_bytes)
    active_hours_range: tuple       # (start_hour, end_hour) 0-24


DEFAULT_FLEET_SPECS: list[IoTDeviceSpec] = [
    IoTDeviceSpec(
        id="dev_01_temp",
        name="Temperature Sensor 01",
        device_type="Environmental Sensor",
        ip_address="192.168.1.101",
        mac_address="30:AE:A4:00:01:01",
        hardware="ESP32",
        primary_protocol="MQTT",
        normal_destinations=["192.168.1.1"],
        normal_packet_rate=8.0,
        normal_byte_range=(64, 128),
        active_hours_range=(0, 24)
    ),
    IoTDeviceSpec(
        id="dev_02_motion",
        name="PIR Motion Sensor 02",
        device_type="Security Sensor",
        ip_address="192.168.1.102",
        mac_address="30:AE:A4:00:01:02",
        hardware="ESP32",
        primary_protocol="MQTT",
        normal_destinations=["192.168.1.1"],
        normal_packet_rate=5.0,
        normal_byte_range=(54, 96),
        active_hours_range=(0, 24)
    ),
    IoTDeviceSpec(
        id="dev_03_env",
        name="Air Quality / CO2 03",
        device_type="Environmental Sensor",
        ip_address="192.168.1.103",
        mac_address="30:AE:A4:00:01:03",
        hardware="ESP32",
        primary_protocol="MQTT",
        normal_destinations=["192.168.1.1"],
        normal_packet_rate=10.0,
        normal_byte_range=(70, 140),
        active_hours_range=(0, 24)
    ),
    IoTDeviceSpec(
        id="dev_04_plug",
        name="Smart Plug Living Room",
        device_type="Smart Plug",
        ip_address="192.168.1.104",
        mac_address="5C:CF:7F:00:02:01",
        hardware="ESP8266",
        primary_protocol="MQTT",
        normal_destinations=["192.168.1.1", "54.210.10.45"], # Local broker + vendor cloud sync
        normal_packet_rate=6.0,
        normal_byte_range=(60, 110),
        active_hours_range=(0, 24)
    ),
    IoTDeviceSpec(
        id="dev_05_relay",
        name="HVAC Relay Actuator",
        device_type="Relay Controller",
        ip_address="192.168.1.105",
        mac_address="5C:CF:7F:00:02:02",
        hardware="ESP8266",
        primary_protocol="MQTT",
        normal_destinations=["192.168.1.1"],
        normal_packet_rate=4.0,
        normal_byte_range=(50, 90),
        active_hours_range=(0, 24)
    ),
    IoTDeviceSpec(
        id="dev_06_compute1",
        name="RPi Compute Node 01",
        device_type="Edge Compute",
        ip_address="192.168.1.106",
        mac_address="B8:27:EB:00:03:01",
        hardware="Raspberry Pi Zero",
        primary_protocol="HTTP",
        normal_destinations=["192.168.1.1", "129.6.15.28"], # Local gateway + NTP
        normal_packet_rate=12.0,
        normal_byte_range=(100, 350),
        active_hours_range=(0, 24)
    ),
    IoTDeviceSpec(
        id="dev_07_compute2",
        name="RPi Compute Node 02",
        device_type="Edge Compute",
        ip_address="192.168.1.107",
        mac_address="B8:27:EB:00:03:02",
        hardware="Raspberry Pi Zero",
        primary_protocol="HTTP",
        normal_destinations=["192.168.1.1"],
        normal_packet_rate=12.0,
        normal_byte_range=(100, 350),
        active_hours_range=(0, 24)
    ),
    IoTDeviceSpec(
        id="dev_08_camera",
        name="Smart Security Camera",
        device_type="Smart Camera",
        ip_address="192.168.1.108",
        mac_address="30:AE:A4:00:04:01",
        hardware="ESP32-CAM",
        primary_protocol="MQTT",
        normal_destinations=["192.168.1.1", "192.168.1.50"], # Local broker + NVR storage
        normal_packet_rate=25.0, # Normal ~100-150 packets/min
        normal_byte_range=(200, 1400),
        active_hours_range=(6, 23) # Active 6:00 AM - 11:00 PM (Section 3.1.1)
    ),
]


class IoTFleetEmulator:
    def __init__(self, specs: list[IoTDeviceSpec] | None = None):
        self.specs = specs or DEFAULT_FLEET_SPECS
        self.specs_by_ip = {s.ip_address: s for s in self.specs}
        self.specs_by_id = {s.id: s for s in self.specs}

    def generate_normal_window_packets(
        self,
        device: IoTDeviceSpec,
        window_duration: float = 10.0,
        current_time: float | None = None,
        hour_override: int | None = None
    ) -> list[ParsedPacket]:
        """
        Generate a batch of normal benign packets for a single device over a 10s window.
        """
        now = current_time or time.time()
        start_time = now - window_duration
        packets: list[ParsedPacket] = []

        # Check circadian schedule (e.g. camera quiet at night)
        hr = hour_override if hour_override is not None else time.localtime(now).tm_hour
        start_hr, end_hr = device.active_hours_range

        # Normal packet count with small Gaussian jitter
        base_rate = device.normal_packet_rate
        if start_hr != 0 or end_hr != 24:
            if not (start_hr <= hr <= end_hr):
                # Night sleep mode: low keepalive only
                base_rate = max(1.0, base_rate * 0.1)

        pkt_count = max(2, int(random.gauss(base_rate, max(1.0, base_rate * 0.15))))

        # Generate timestamps spaced throughout window
        timestamps = sorted([random.uniform(start_time, now) for _ in range(pkt_count)])

        dst_ip = random.choice(device.normal_destinations)
        is_mqtt = device.primary_protocol == "MQTT"
        dst_port = 1883 if is_mqtt else (80 if device.primary_protocol == "HTTP" else 53)

        for ts in timestamps:
            length = random.randint(device.normal_byte_range[0], device.normal_byte_range[1])
            is_syn = (random.random() < 0.05)
            tcp_flags = {
                "SYN": is_syn,
                "ACK": True,
                "PSH": random.random() < 0.35,
                "RST": False,
                "FIN": False,
                "URG": False
            }
            pkt = ParsedPacket(
                timestamp=ts,
                src_ip=device.ip_address,
                dst_ip=dst_ip,
                src_mac=device.mac_address,
                dst_mac="B8:27:EB:AA:BB:CC",
                src_port=random.randint(49152, 65535),
                dst_port=dst_port,
                protocol="TCP",
                app_protocol=device.primary_protocol,
                length=length,
                ttl=64,
                ip_id=random.randint(1000, 60000),
                tcp_flags=tcp_flags,
                tcp_window=64240,
                tcp_timestamp=int(ts * 1000) % 4294967295,
                is_outbound=True
            )
            packets.append(pkt)

        return packets

    def generate_bidirectional_window_packets(
        self,
        device: IoTDeviceSpec,
        window_duration: float = 10.0,
        current_time: float | None = None,
        upstream_pkt_ratio: float = 0.4851,
        outbound_ttl: int = 64,
        inbound_wan_ttl: int = 171,
    ) -> list[ParsedPacket]:
        """Generate calibrated bidirectional (outbound + inbound response) packets for a 10s window."""
        now = current_time or time.time()
        start_time = now - window_duration
        pkt_count = max(4, int(round(device.normal_packet_rate * 2.0)))
        timestamps = sorted([random.uniform(start_time, now) for _ in range(pkt_count)])
        peer_ip = device.normal_destinations[0]
        is_mqtt = device.primary_protocol == "MQTT"
        service_port = 1883 if is_mqtt else (443 if device.primary_protocol == "HTTPS" else 80)
        client_port = random.randint(49152, 65535)

        n_outbound = max(1, min(pkt_count - 1, int(round(pkt_count * upstream_pkt_ratio))))
        directions = [True] * n_outbound + [False] * (pkt_count - n_outbound)
        random.shuffle(directions)

        packets: list[ParsedPacket] = []
        for ts, is_outbound in zip(timestamps, directions, strict=True):
            if is_outbound:
                src_ip, dst_ip = device.ip_address, peer_ip
                src_mac, dst_mac = device.mac_address, "B8:27:EB:AA:BB:CC"
                src_port, dst_port = client_port, service_port
                ttl = outbound_ttl
                length = random.randint(device.normal_byte_range[0], device.normal_byte_range[1])
            else:
                src_ip, dst_ip = peer_ip, device.ip_address
                src_mac, dst_mac = "B8:27:EB:AA:BB:CC", device.mac_address
                src_port, dst_port = service_port, client_port
                ttl = inbound_wan_ttl
                length = max(66, int(random.randint(device.normal_byte_range[0], device.normal_byte_range[1]) * 1.12))

            packets.append(
                ParsedPacket(
                    timestamp=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_mac=src_mac,
                    dst_mac=dst_mac,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol="TCP",
                    app_protocol=device.primary_protocol,
                    length=length,
                    ttl=ttl,
                    ip_id=random.randint(1000, 60000),
                    tcp_flags={"SYN": False, "ACK": True, "PSH": random.random() < 0.53, "RST": False, "FIN": False, "URG": False},
                    tcp_window=37166,
                    tcp_timestamp=int(ts * 1000) % 4294967295,
                    is_outbound=is_outbound,
                )
            )
        return self.apply_ack_psh_pattern(packets)

    def apply_ack_psh_pattern(
        self,
        packets: list[ParsedPacket],
        psh_ratio: float = 0.5325,
        ack_mean_bytes: float = 66.0,
        psh_mean_bytes: float = 140.5,
    ) -> list[ParsedPacket]:
        """Assign calibrated ACK-only vs PSH-ACK flags and bimodal packet lengths to TCP packets."""
        tcp_indices = [i for i, p in enumerate(packets) if p.protocol == "TCP"]
        if not tcp_indices:
            return packets
        n_psh = max(1, min(len(tcp_indices), int(round(len(tcp_indices) * psh_ratio))))
        psh_flags = [True] * n_psh + [False] * (len(tcp_indices) - n_psh)
        random.shuffle(psh_flags)
        for idx, is_psh in zip(tcp_indices, psh_flags, strict=True):
            pkt = packets[idx]
            pkt.tcp_flags = {
                "SYN": False,
                "ACK": True,
                "PSH": is_psh,
                "RST": False,
                "FIN": False,
                "URG": False,
            }
            if is_psh:
                pkt.length = max(72, int(round(random.gauss(psh_mean_bytes, 14.0))))
            else:
                pkt.length = max(54, min(74, int(round(random.gauss(ack_mean_bytes, 2.0)))))
        return packets

    def generate_tls_keepalive_burst_packets(
        self,
        device: IoTDeviceSpec,
        window_duration: float = 10.0,
        current_time: float | None = None,
        inter_burst_interval_s: float = 1.35,
        intra_burst_iat_ms: float = 5.0,
    ) -> list[ParsedPacket]:
        """Generate calibrated TLS/HTTPS keepalive micro-bursts (PSH-ACK + rapid ACK/response pairs)."""
        now = current_time or time.time()
        start_time = now - window_duration
        peer_ip = device.normal_destinations[-1]
        client_port = random.randint(49152, 65535)
        packets: list[ParsedPacket] = []

        cursor = start_time + random.uniform(0.05, 0.25)
        while cursor < now:
            # Outbound TLS application/keepalive record (PSH+ACK)
            packets.append(
                ParsedPacket(
                    timestamp=cursor,
                    src_ip=device.ip_address,
                    dst_ip=peer_ip,
                    src_mac=device.mac_address,
                    dst_mac="B8:27:EB:AA:BB:CC",
                    src_port=client_port,
                    dst_port=443,
                    protocol="TCP",
                    app_protocol="HTTPS",
                    length=max(85, int(round(random.gauss(140.5, 12.0)))),
                    ttl=64,
                    ip_id=random.randint(1000, 60000),
                    tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                    tcp_window=37166,
                    tcp_timestamp=int(cursor * 1000) % 4294967295,
                    is_outbound=True,
                )
            )
            # Inbound rapid ACK / keepalive response within intra_burst_iat_ms
            resp_ts = min(now, cursor + max(0.0005, random.gauss(intra_burst_iat_ms, 1.2) / 1000.0))
            packets.append(
                ParsedPacket(
                    timestamp=resp_ts,
                    src_ip=peer_ip,
                    dst_ip=device.ip_address,
                    src_mac="B8:27:EB:AA:BB:CC",
                    dst_mac=device.mac_address,
                    src_port=443,
                    dst_port=client_port,
                    protocol="TCP",
                    app_protocol="HTTPS",
                    length=66,
                    ttl=171,
                    ip_id=random.randint(1000, 60000),
                    tcp_flags={"SYN": False, "ACK": True, "PSH": False, "RST": False, "FIN": False, "URG": False},
                    tcp_window=37166,
                    tcp_timestamp=int(resp_ts * 1000) % 4294967295,
                    is_outbound=False,
                )
            )
            cursor += max(0.3, random.gauss(inter_burst_interval_s, inter_burst_interval_s * 0.25))

        return packets

    def generate_hard_negative_packets(
        self,
        device: IoTDeviceSpec,
        negative_type: Any,
        window_duration: float = 10.0,
        current_time: float | None = None,
    ) -> list[ParsedPacket]:
        """
        Generate packets for 10 benign hard negative scenarios (normal operational bursts).
        """
        from guardian.eval.scenario import HardNegativeType

        now = current_time or time.time()
        start_time = now - window_duration
        packets: list[ParsedPacket] = []

        if negative_type == HardNegativeType.FIRMWARE_UPDATE:
            # High-throughput OTA download from authorized vendor CDN
            pkt_count = 25
            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(
                    ParsedPacket(
                        timestamp=ts,
                        src_ip=device.ip_address,
                        dst_ip="54.210.10.45",
                        src_mac=device.mac_address,
                        dst_mac="B8:27:EB:AA:BB:CC",
                        src_port=random.randint(49152, 65535),
                        dst_port=443,
                        protocol="TCP",
                        app_protocol="HTTPS",
                        length=1460,
                        ttl=64,
                        ip_id=random.randint(1000, 60000),
                        tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                        tcp_window=64240,
                        tcp_timestamp=int(ts * 1000) % 4294967295,
                        is_outbound=True,
                    )
                )

        elif negative_type == HardNegativeType.REBOOT_STORM:
            # Fleet reboot storm: broadcast DHCP / ARP / NTP sync
            pkt_count = 15
            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(
                    ParsedPacket(
                        timestamp=ts,
                        src_ip=device.ip_address,
                        dst_ip="255.255.255.255",
                        src_mac=device.mac_address,
                        dst_mac="FF:FF:FF:FF:FF:FF",
                        src_port=68,
                        dst_port=67,
                        protocol="UDP",
                        app_protocol="OTHER",
                        length=342,
                        ttl=64,
                        ip_id=random.randint(1000, 60000),
                        tcp_flags={"SYN": False, "ACK": False, "PSH": False, "RST": False, "FIN": False, "URG": False},
                        tcp_window=0,
                        tcp_timestamp=0,
                        is_outbound=False,
                    )
                )

        elif negative_type == HardNegativeType.USER_TOGGLING:
            # Rapid app toggling: burst of MQTT publish packets to local broker
            pkt_count = 18
            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(
                    ParsedPacket(
                        timestamp=ts,
                        src_ip=device.ip_address,
                        dst_ip="192.168.1.1",
                        src_mac=device.mac_address,
                        dst_mac="B8:27:EB:AA:BB:CC",
                        src_port=random.randint(49152, 65535),
                        dst_port=1883,
                        protocol="TCP",
                        app_protocol="MQTT",
                        length=85,
                        ttl=64,
                        ip_id=random.randint(1000, 60000),
                        tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                        tcp_window=64240,
                        tcp_timestamp=int(ts * 1000) % 4294967295,
                        is_outbound=False,
                    )
                )

        elif negative_type == HardNegativeType.DNS_RETRY_STORM:
            # DNS upstream timeout causing retransmissions
            pkt_count = 25
            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(
                    ParsedPacket(
                        timestamp=ts,
                        src_ip=device.ip_address,
                        dst_ip="192.168.1.1",
                        src_mac=device.mac_address,
                        dst_mac="B8:27:EB:AA:BB:CC",
                        src_port=random.randint(49152, 65535),
                        dst_port=53,
                        protocol="UDP",
                        app_protocol="DNS",
                        length=68,
                        ttl=64,
                        ip_id=random.randint(1000, 60000),
                        tcp_flags={"SYN": False, "ACK": False, "PSH": False, "RST": False, "FIN": False, "URG": False},
                        tcp_window=0,
                        tcp_timestamp=0,
                        is_outbound=False,
                    )
                )

        elif negative_type == HardNegativeType.NTP_BURSTS:
            # NTP clock synchronization burst
            pkt_count = 6
            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(
                    ParsedPacket(
                        timestamp=ts,
                        src_ip=device.ip_address,
                        dst_ip="129.6.15.28",
                        src_mac=device.mac_address,
                        dst_mac="B8:27:EB:AA:BB:CC",
                        src_port=123,
                        dst_port=123,
                        protocol="UDP",
                        app_protocol="NTP",
                        length=76,
                        ttl=64,
                        ip_id=random.randint(1000, 60000),
                        tcp_flags={"SYN": False, "ACK": False, "PSH": False, "RST": False, "FIN": False, "URG": False},
                        tcp_window=0,
                        tcp_timestamp=0,
                        is_outbound=True,
                    )
                )

        elif negative_type == HardNegativeType.MQTT_RECONNECT_FLOOD:
            # Local broker reconnection burst
            pkt_count = 45
            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(
                    ParsedPacket(
                        timestamp=ts,
                        src_ip=device.ip_address,
                        dst_ip="192.168.1.1",
                        src_mac=device.mac_address,
                        dst_mac="B8:27:EB:AA:BB:CC",
                        src_port=random.randint(49152, 65535),
                        dst_port=1883,
                        protocol="TCP",
                        app_protocol="MQTT",
                        length=74,
                        ttl=64,
                        ip_id=random.randint(1000, 60000),
                        tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                        tcp_window=64240,
                        tcp_timestamp=int(ts * 1000) % 4294967295,
                        is_outbound=False,
                    )
                )

        elif negative_type == HardNegativeType.CAMERA_MOTION_BURST:
            # Camera streaming frame burst
            pkt_count = 60
            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(
                    ParsedPacket(
                        timestamp=ts,
                        src_ip=device.ip_address,
                        dst_ip="192.168.1.50",
                        src_mac=device.mac_address,
                        dst_mac="B8:27:EB:AA:BB:CC",
                        src_port=random.randint(49152, 65535),
                        dst_port=1883,
                        protocol="TCP",
                        app_protocol="MQTT",
                        length=1200,
                        ttl=64,
                        ip_id=random.randint(1000, 60000),
                        tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                        tcp_window=64240,
                        tcp_timestamp=int(ts * 1000) % 4294967295,
                        is_outbound=False,
                    )
                )

        elif negative_type == HardNegativeType.ROUTER_REBOOT:
            # Transient router disconnect/reconnect ARP
            pkt_count = 12
            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(
                    ParsedPacket(
                        timestamp=ts,
                        src_ip=device.ip_address,
                        dst_ip="192.168.1.1",
                        src_mac=device.mac_address,
                        dst_mac="B8:27:EB:AA:BB:CC",
                        src_port=random.randint(49152, 65535),
                        dst_port=1883,
                        protocol="TCP",
                        app_protocol="MQTT",
                        length=60,
                        ttl=64,
                        ip_id=random.randint(1000, 60000),
                        tcp_flags={"SYN": True, "ACK": False, "PSH": False, "RST": False, "FIN": False, "URG": False},
                        tcp_window=1024,
                        tcp_timestamp=int(ts * 1000) % 4294967295,
                        is_outbound=False,
                    )
                )

        elif negative_type == HardNegativeType.NEW_CLOUD_ENDPOINT:
            # Authorized vendor cloud migration
            pkt_count = 15
            for _ in range(pkt_count):
                ts = random.uniform(start_time, now)
                packets.append(
                    ParsedPacket(
                        timestamp=ts,
                        src_ip=device.ip_address,
                        dst_ip="52.84.12.34",
                        src_mac=device.mac_address,
                        dst_mac="B8:27:EB:AA:BB:CC",
                        src_port=random.randint(49152, 65535),
                        dst_port=443,
                        protocol="TCP",
                        app_protocol="HTTPS",
                        length=450,
                        ttl=64,
                        ip_id=random.randint(1000, 60000),
                        tcp_flags={"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
                        tcp_window=64240,
                        tcp_timestamp=int(ts * 1000) % 4294967295,
                        is_outbound=True,
                    )
                )

        elif negative_type == HardNegativeType.DST_CHANGE:
            # Daylight saving time shift: normal window packets with hour override
            packets = self.generate_normal_window_packets(
                device=device,
                window_duration=window_duration,
                current_time=now,
                hour_override=12,
            )

        packets.sort(key=lambda p: p.timestamp)
        return packets

