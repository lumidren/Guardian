"""
Unit tests for Parser Fuzzing and Ingestion Robustness (Milestone P3-9).
Verifies:
1. Robustness against truncated, malformed, and corrupted network frames.
2. Resilience against out-of-bounds byte lengths, invalid IHL, and header length mismatches.
3. Non-crash guarantee: invalid frames are safely dropped or return None/raise handled exceptions.
"""

import random

from guardian.capture.packet_parser import parse_raw_packet
from guardian.capture.pcap_importer import PCAPImporter


def test_parser_fuzzing_truncated_frames() -> None:
    """Parser must safely reject frames of all truncated lengths without raising uncaught exceptions."""
    importer = PCAPImporter()

    # Ethernet frame parsing: truncated if < 34 bytes (14B eth + 20B IP)
    for length in range(0, 34):
        garbage = bytes([random.randint(0, 255) for _ in range(length)])
        res_eth = importer._parse_frame(garbage, timestamp=100.0, linktype=1)
        assert res_eth is None, f"Expected None on truncated Ethernet frame of length {length}"

    # Raw IP parsing: truncated if < 20 bytes (20B IP header)
    for length in range(0, 20):
        garbage = bytes([random.randint(0, 255) for _ in range(length)])
        res_raw = importer._parse_frame(garbage, timestamp=100.0, linktype=101)
        assert res_raw is None, f"Expected None on truncated Raw IP frame of length {length}"


def test_parser_fuzzing_corrupted_ip_headers() -> None:
    """Parser must reject invalid IPv4 versions, invalid IHL, and contradictory length fields."""
    importer = PCAPImporter()

    # Valid base Ethernet + IPv4 + UDP frame
    eth = b"\x00" * 14
    valid_ip = (
        b"\x45\x00\x00\x1c"  # Ver 4, IHL 5, Total Len 28
        b"\x12\x34\x00\x00"  # ID, Frag
        b"\x40\x11\x00\x00"  # TTL 64, Proto UDP (17), Csum
        b"\xc0\xa8\x01\x65"  # 192.168.1.101
        b"\xc0\xa8\x01\x01"  # 192.168.1.1
    )
    udp = b"\x12\x34\x00\x35\x00\x08\x00\x00"  # sport 4660, dport 53, len 8
    frame = eth + valid_ip + udp

    # Mutate 1: Invalid IP version (Version 6 in IPv4 parser)
    bad_ver = bytearray(frame)
    bad_ver[14] = 0x65  # Version 6, IHL 5
    assert importer._parse_frame(bytes(bad_ver), 100.0, 1) is None

    # Mutate 2: Invalid IHL (< 5, which is < 20 bytes)
    bad_ihl = bytearray(frame)
    bad_ihl[14] = 0x43  # Version 4, IHL 3 (12 bytes)
    assert importer._parse_frame(bytes(bad_ihl), 100.0, 1) is None

    # Mutate 3: Excessive IHL exceeding frame length
    big_ihl = bytearray(frame)
    big_ihl[14] = 0x4F  # Version 4, IHL 15 (60 bytes)
    assert importer._parse_frame(bytes(big_ihl), 100.0, 1) is None


def test_parser_fuzzing_random_mutations() -> None:
    """Random byte fuzzing across 200 iterations must never crash the parser."""
    importer = PCAPImporter()
    rng = random.Random(1337)

    for _ in range(200):
        frame_len = rng.randint(1, 1500)
        random_bytes = bytes([rng.randint(0, 255) for _ in range(frame_len)])

        # Neither linktype 1 (Ethernet) nor 101 (Raw IP) should crash
        res1 = importer._parse_frame(random_bytes, timestamp=100.0, linktype=1)
        assert res1 is None or hasattr(res1, "src_ip")

        res2 = importer._parse_frame(random_bytes, timestamp=100.0, linktype=101)
        assert res2 is None or hasattr(res2, "src_ip")


def test_parse_raw_packet_dict_fuzzing() -> None:
    """Dictionary-based parser must handle unexpected types, None values, and missing fields safely."""
    malformed_dicts = [
        {},
        {"timestamp": "not_a_float", "src_ip": None},
        {"protocol": 12345, "length": -50},
        {"tcp_flags": None, "src_port": "eighty"},
        {"dst_ip": 99999999},
    ]

    for d in malformed_dicts:
        try:
            res = parse_raw_packet(d)
            # If it succeeds, it must be a valid ParsedPacket
            if res is not None:
                assert hasattr(res, "src_ip")
        except Exception as e:
            # Type error or parsing exception is acceptable, but no system crash
            assert isinstance(e, (TypeError, ValueError, AttributeError))
