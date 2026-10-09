"""
Virtual IoT Fleet Emulator for GUARDIAN.
Emulates 8 protected IoT devices generating realistic, continuous network telemetry (Section 4.1.1).
"""

import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
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
    normal_destinations: List[str]
    normal_packet_rate: float       # pkts per 10s
    normal_byte_range: tuple        # (min_bytes, max_bytes)
    active_hours_range: tuple       # (start_hour, end_hour) 0-24


DEFAULT_FLEET_SPECS: List[IoTDeviceSpec] = [
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
    def __init__(self, specs: Optional[List[IoTDeviceSpec]] = None):
        self.specs = specs or DEFAULT_FLEET_SPECS
        self.specs_by_ip = {s.ip_address: s for s in self.specs}
        self.specs_by_id = {s.id: s for s in self.specs}

    def generate_normal_window_packets(
        self,
        device: IoTDeviceSpec,
        window_duration: float = 10.0,
        current_time: Optional[float] = None,
        hour_override: Optional[int] = None
    ) -> List[ParsedPacket]:
        """
        Generate a batch of normal benign packets for a single device over a 10s window.
        """
        now = current_time or time.time()
        start_time = now - window_duration
        packets: List[ParsedPacket] = []

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
