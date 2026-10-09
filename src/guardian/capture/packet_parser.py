"""
Lightweight, metadata-focused packet parser for IoT traffic.
Extracts Layer 2, Layer 3, and Layer 4 header fields without inspecting encrypted payloads.
"""

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedPacket:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_mac: str = "00:00:00:00:00:00"
    dst_mac: str = "00:00:00:00:00:00"
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "OTHER"  # TCP, UDP, ICMP, etc.
    app_protocol: str = "OTHER"  # MQTT, HTTP, HTTPS, DNS, COAP, NTP, OTHER
    length: int = 0
    ttl: int = 64
    ip_id: int = 0
    tcp_flags: dict[str, bool] = field(default_factory=lambda: {
        "SYN": False, "ACK": False, "PSH": False,
        "RST": False, "FIN": False, "URG": False
    })
    tcp_window: int = 0
    tcp_timestamp: int | None = None
    is_outbound: bool = True


def infer_app_protocol(port: int, transport_proto: str) -> str:
    """Infer application protocol by port heuristics."""
    if port in (1883, 8883):
        return "MQTT"
    elif port in (80, 8080, 8000, 8008):
        return "HTTP"
    elif port in (443, 8443):
        return "HTTPS"
    elif port == 53:
        return "DNS"
    elif port in (5683, 5684):
        return "COAP"
    elif port == 123:
        return "NTP"
    return transport_proto


def parse_raw_packet(pkt: Any, local_subnet_prefix: str = "192.168.1.") -> ParsedPacket | None:
    """
    Parses a Scapy packet or custom dict-based packet representation.
    Extracts all metadata required for the 60 GUARDIAN behavioral features.
    """
    # If already a ParsedPacket
    if isinstance(pkt, ParsedPacket):
        return pkt

    # If it is a dictionary (from simulated fleet or generator)
    if isinstance(pkt, dict):
        ts = pkt.get("timestamp", time.time())
        src_ip = pkt.get("src_ip", "0.0.0.0")
        dst_ip = pkt.get("dst_ip", "0.0.0.0")
        src_port = pkt.get("src_port", 0)
        dst_port = pkt.get("dst_port", 0)
        proto = pkt.get("protocol", "TCP")
        app_proto = pkt.get("app_protocol", infer_app_protocol(dst_port, proto))
        length = pkt.get("length", 64)
        ttl = pkt.get("ttl", 64)
        ip_id = pkt.get("ip_id", 0)
        tcp_flags = pkt.get("tcp_flags", {
            "SYN": False, "ACK": False, "PSH": False,
            "RST": False, "FIN": False, "URG": False
        })
        tcp_window = pkt.get("tcp_window", 64240)
        tcp_timestamp = pkt.get("tcp_timestamp", None)
        src_mac = pkt.get("src_mac", "00:00:00:00:00:00")
        dst_mac = pkt.get("dst_mac", "00:00:00:00:00:00")
        is_outbound = src_ip.startswith(local_subnet_prefix)

        return ParsedPacket(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            app_protocol=app_proto,
            length=length,
            ttl=ttl,
            ip_id=ip_id,
            tcp_flags=tcp_flags,
            tcp_window=tcp_window,
            tcp_timestamp=tcp_timestamp,
            is_outbound=is_outbound
        )

    # Scapy packet handling (checked lazily to avoid hard dependency on scapy import)
    try:
        ts = float(getattr(pkt, "time", time.time()))
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        src_mac = getattr(pkt, "src", "00:00:00:00:00:00")
        dst_mac = getattr(pkt, "dst", "00:00:00:00:00:00")
        src_port = 0
        dst_port = 0
        proto = "OTHER"
        ttl = 64
        ip_id = 0
        length = len(pkt)
        tcp_flags = {"SYN": False, "ACK": False, "PSH": False, "RST": False, "FIN": False, "URG": False}
        tcp_window = 0
        tcp_timestamp = None

        if hasattr(pkt, "haslayer") and pkt.haslayer("IP"):
            ip_layer = pkt.getlayer("IP")
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ttl = ip_layer.ttl
            ip_id = ip_layer.id

            if pkt.haslayer("TCP"):
                tcp_layer = pkt.getlayer("TCP")
                proto = "TCP"
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                tcp_window = tcp_layer.window
                flags = str(tcp_layer.flags)
                tcp_flags["SYN"] = "S" in flags
                tcp_flags["ACK"] = "A" in flags
                tcp_flags["PSH"] = "P" in flags
                tcp_flags["RST"] = "R" in flags
                tcp_flags["FIN"] = "F" in flags
                tcp_flags["URG"] = "U" in flags

                # Parse TCP options for timestamp if available
                if hasattr(tcp_layer, "options"):
                    for opt in tcp_layer.options:
                        if opt[0] == "Timestamp":
                            tcp_timestamp = opt[1][0]
            elif pkt.haslayer("UDP"):
                udp_layer = pkt.getlayer("UDP")
                proto = "UDP"
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
            elif pkt.haslayer("ICMP"):
                proto = "ICMP"

        app_proto = infer_app_protocol(dst_port, proto)
        is_outbound = src_ip.startswith(local_subnet_prefix)

        return ParsedPacket(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            app_protocol=app_proto,
            length=length,
            ttl=ttl,
            ip_id=ip_id,
            tcp_flags=tcp_flags,
            tcp_window=tcp_window,
            tcp_timestamp=tcp_timestamp,
            is_outbound=is_outbound
        )
    except Exception:
        return None
