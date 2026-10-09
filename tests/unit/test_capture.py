"""Unit tests for src/guardian/capture module."""

import time

from guardian.capture.flow_tracker import FlowTracker
from guardian.capture.packet_parser import ParsedPacket, parse_raw_packet
from guardian.capture.sniffer import TrafficSniffer


def test_parsed_packet_creation() -> None:
    now = time.time()
    pkt = ParsedPacket(
        timestamp=now,
        src_ip="192.168.1.10",
        dst_ip="1.1.1.1",
        src_port=12345,
        dst_port=53,
        protocol="UDP",
        length=64,
        is_outbound=True,
    )
    assert pkt.src_ip == "192.168.1.10"
    assert pkt.is_outbound is True
    assert pkt.protocol == "UDP"


def test_parse_raw_packet_dict() -> None:
    pkt_dict = {
        "timestamp": 1000.0,
        "src_ip": "192.168.1.50",
        "dst_ip": "8.8.8.8",
        "src_port": 5000,
        "dst_port": 443,
        "protocol": "TCP",
        "length": 128,
        "payload_len": 64,
        "tcp_flags": {"SYN": True},
    }
    parsed = parse_raw_packet(pkt_dict)
    assert parsed is not None
    assert parsed.src_ip == "192.168.1.50"
    assert parsed.is_outbound is True
    assert parsed.tcp_flags["SYN"] is True


def test_flow_tracker_window_aggregation() -> None:
    tracker = FlowTracker(window_size_seconds=10.0)
    now = time.time()
    for i in range(5):
        pkt = ParsedPacket(
            timestamp=now + (i * 0.5),
            src_ip="192.168.1.20",
            dst_ip="93.184.216.34",
            src_port=40000 + i,
            dst_port=80,
            protocol="TCP",
            length=100,
            is_outbound=True,
        )
        tracker.ingest_packet(pkt)

    summary = tracker.get_window_summary("192.168.1.20", current_timestamp=now + 2.5)
    assert summary is not None
    assert len(summary.packets) == 5
    assert sum(p.length for p in summary.packets) == 500
    assert summary.duration > 0
    assert "192.168.1.20" in tracker.get_all_active_devices()


def test_traffic_sniffer_synthetic_injection() -> None:
    tracker = FlowTracker()
    sniffer = TrafficSniffer(flow_tracker=tracker)
    received: list[ParsedPacket] = []
    sniffer.register_callback(lambda p: received.append(p))

    pkt = ParsedPacket(
        timestamp=time.time(),
        src_ip="192.168.1.30",
        dst_ip="192.168.1.1",
        src_port=1883,
        dst_port=1883,
        protocol="TCP",
        length=80,
        is_outbound=False,
    )
    sniffer.inject_packet(pkt)
    assert len(received) == 1
    assert received[0].src_ip == "192.168.1.30"
