"""
Unit tests for Real-Device PCAP Importer and Ingestion Tools (Milestone P3-8).
Verifies:
1. Binary PCAP packet parsing (Ethernet, IPv4, TCP, UDP, ICMP).
2. Streaming PCAP ingestion into FlowTracker and FeatureExtractor.
3. Chronological sliding window aggregation from real/synthetic PCAP files.
4. Graceful handling of corrupted or truncated PCAP captures.
"""

import struct
import tempfile
from pathlib import Path

import pytest
from guardian.capture.pcap_importer import InvalidPCAPError, PCAPImporter

from guardian.capture.flow_tracker import FlowTracker
from guardian.capture.packet_parser import ParsedPacket
from guardian.features.extractor import FeatureExtractor


def _create_sample_pcap(filepath: Path) -> list[dict]:
    """Helper to generate a valid binary PCAP file with synthetic IPv4 frames."""
    importer = PCAPImporter()
    sample_packets = [
        {
            "timestamp": 1700000000.100,
            "src_ip": "192.168.1.105",
            "dst_ip": "192.168.1.1",
            "src_port": 45210,
            "dst_port": 1883,
            "protocol": "TCP",
            "tcp_flags": {"SYN": False, "ACK": True, "PSH": True, "RST": False, "FIN": False, "URG": False},
            "length": 128,
        },
        {
            "timestamp": 1700000000.250,
            "src_ip": "192.168.1.105",
            "dst_ip": "8.8.8.8",
            "src_port": 53210,
            "dst_port": 53,
            "protocol": "UDP",
            "tcp_flags": {"SYN": False, "ACK": False, "PSH": False, "RST": False, "FIN": False, "URG": False},
            "length": 64,
        },
        {
            "timestamp": 1700000001.500,
            "src_ip": "192.168.1.105",
            "dst_ip": "192.168.1.1",
            "src_port": 45210,
            "dst_port": 1883,
            "protocol": "TCP",
            "tcp_flags": {"SYN": False, "ACK": True, "PSH": False, "RST": False, "FIN": False, "URG": False},
            "length": 96,
        },
    ]

    importer.write_pcap(filepath, sample_packets)
    return sample_packets


def test_pcap_write_and_read_roundtrip() -> None:
    """PCAP importer must write and parse valid binary PCAP captures accurately."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        pcap_file = Path(tmp_dir) / "test_capture.pcap"
        sample_packets = _create_sample_pcap(pcap_file)

        importer = PCAPImporter()
        parsed = importer.import_pcap(pcap_file)

        assert len(parsed) == len(sample_packets)

        # First packet: TCP to MQTT broker
        pkt1 = parsed[0]
        assert isinstance(pkt1, ParsedPacket)
        assert pkt1.src_ip == "192.168.1.105"
        assert pkt1.dst_ip == "192.168.1.1"
        assert pkt1.src_port == 45210
        assert pkt1.dst_port == 1883
        assert pkt1.protocol == "TCP"
        assert pkt1.tcp_flags["PSH"] is True
        assert pkt1.tcp_flags["ACK"] is True
        assert pkt1.length == 128

        # Second packet: UDP to DNS
        pkt2 = parsed[1]
        assert pkt2.src_ip == "192.168.1.105"
        assert pkt2.dst_ip == "8.8.8.8"
        assert pkt2.src_port == 53210
        assert pkt2.dst_port == 53
        assert pkt2.protocol == "UDP"
        assert pkt2.length == 64


def test_pcap_ingestion_into_flow_tracker_and_feature_extraction() -> None:
    """Parsed PCAP packets must stream directly into FlowTracker and FeatureExtractor."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        pcap_file = Path(tmp_dir) / "stream_test.pcap"
        _create_sample_pcap(pcap_file)

        importer = PCAPImporter()
        tracker = FlowTracker(window_size_seconds=10.0)
        extractor = FeatureExtractor()

        packet_count = importer.replay_to_tracker(
            pcap_path=pcap_file,
            tracker=tracker,
            target_ip="192.168.1.105",
        )
        assert packet_count == 3

        summary = tracker.get_window_summary("192.168.1.105")
        assert summary is not None
        assert summary.packet_count_out == 3
        assert summary.byte_count_out == 128 + 64 + 96

        features = extractor.extract(summary)
        vec = extractor.extract_vector(summary)
        assert len(vec) == 60
        assert features["packet_count_out"] == 3


def test_pcap_importer_handles_corrupt_files() -> None:
    """Corrupted PCAP files must raise InvalidPCAPError with informative diagnostics."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        bad_file = Path(tmp_dir) / "corrupt.pcap"
        # Write corrupted header (< 24 bytes)
        bad_file.write_bytes(b"\x00\x01\x02\x03")

        importer = PCAPImporter()
        with pytest.raises(InvalidPCAPError) as exc_info:
            importer.import_pcap(bad_file)
        assert "Invalid PCAP file header" in str(exc_info.value)


def test_pcap_importer_invalid_magic() -> None:
    """PCAP files with invalid magic numbers must be rejected."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        bad_file = Path(tmp_dir) / "bad_magic.pcap"
        bad_file.write_bytes(struct.pack("<IHHIIII", 0xDEADBEEF, 2, 4, 0, 0, 65535, 1))

        importer = PCAPImporter()
        with pytest.raises(InvalidPCAPError) as exc_info:
            importer.import_pcap(bad_file)
        assert "Unsupported PCAP magic number" in str(exc_info.value)
