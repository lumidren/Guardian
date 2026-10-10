"""
Binary PCAP File Importer and Real-Device Ingestion Engine (Milestone P3-8).
Enables zero-dependency binary parsing of standard libpcap captures from IoT gateways,
streaming directly into FlowTracker, sliding-window aggregation, and feature extraction.
"""

import socket
import struct
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from .flow_tracker import FlowTracker
from .packet_parser import ParsedPacket, infer_app_protocol


class InvalidPCAPError(Exception):
    """Raised when encountering malformed or corrupted PCAP files."""


class PCAPImporter:
    """
    Parses libpcap packet capture files (.pcap) and bridges real network traffic
    into the GUARDIAN detection pipeline.
    """

    MAGIC_MICRO_LE = 0xA1B2C3D4
    MAGIC_MICRO_BE = 0xD4C3B2A1
    MAGIC_NANO_LE = 0xA1B23C4D
    MAGIC_NANO_BE = 0x4D3CB2A1

    def iter_pcap(
        self,
        filepath: str | Path,
        target_ips: Sequence[str] | None = None,
    ) -> Iterator[ParsedPacket]:
        """
        Streams standard binary PCAP records directly from disk into ParsedPacket objects
        with O(1) memory overhead per frame.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {path}")

        target_set = set(target_ips) if target_ips is not None else None

        with path.open("rb") as f:
            hdr_bytes = f.read(24)
            if len(hdr_bytes) < 24:
                raise InvalidPCAPError(
                    f"Invalid PCAP file header: expected at least 24 bytes, got {len(hdr_bytes)} bytes in {path.name}"
                )

            magic = struct.unpack("<I", hdr_bytes[:4])[0]
            endian = "<"
            is_nano = False

            if magic == self.MAGIC_MICRO_LE:
                endian = "<"
                is_nano = False
            elif magic == self.MAGIC_MICRO_BE:
                endian = ">"
                is_nano = False
            elif magic == self.MAGIC_NANO_LE:
                endian = "<"
                is_nano = True
            elif magic == self.MAGIC_NANO_BE:
                endian = ">"
                is_nano = True
            else:
                raise InvalidPCAPError(
                    f"Unsupported PCAP magic number: 0x{magic:08X} in {path.name}"
                )

            hdr_fmt = f"{endian}IHHiIII"
            _, ver_major, ver_minor, _, _, snaplen, linktype = struct.unpack(hdr_fmt, hdr_bytes)

            rec_hdr_fmt = f"{endian}IIII"
            rec_hdr_size = 16
            time_divisor = 1e9 if is_nano else 1e6

            while True:
                rec_hdr = f.read(rec_hdr_size)
                if len(rec_hdr) < rec_hdr_size:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(rec_hdr_fmt, rec_hdr)
                if incl_len > 262144:
                    break

                raw_frame = f.read(incl_len)
                if len(raw_frame) < incl_len:
                    break  # Truncated trailing record

                timestamp = float(ts_sec) + (float(ts_usec) / time_divisor)
                pkt = self._parse_frame(raw_frame, timestamp, linktype)
                if pkt is not None:
                    if target_set is None or pkt.src_ip in target_set or pkt.dst_ip in target_set:
                        yield pkt

    def import_pcap(
        self,
        filepath: str | Path,
        target_ips: Sequence[str] | None = None,
    ) -> list[ParsedPacket]:
        """
        Parses standard binary PCAP file into a list of chronologically ordered ParsedPacket objects.
        """
        return list(self.iter_pcap(filepath, target_ips=target_ips))

    def replay_to_tracker(
        self,
        pcap_path: str | Path,
        tracker: FlowTracker,
        target_ip: str | None = None,
    ) -> int:
        """
        Streams PCAP packets into a FlowTracker instance.
        Returns the number of matching ingested packets.
        """
        targets = [target_ip] if target_ip else None
        count = 0
        for pkt in self.iter_pcap(pcap_path, target_ips=targets):
            tracker.ingest_packet(pkt)
            count += 1
        return count

    def _parse_frame(
        self,
        frame: bytes,
        timestamp: float,
        linktype: int,
    ) -> ParsedPacket | None:
        """Parses Ethernet or Raw IP frame into ParsedPacket metadata."""
        ip_data = b""
        src_mac = "00:00:00:00:00:00"
        dst_mac = "00:00:00:00:00:00"

        # LinkType 1: Ethernet
        if linktype == 1:
            if len(frame) < 14:
                return None
            dst_mac = ":".join(f"{b:02X}" for b in frame[0:6])
            src_mac = ":".join(f"{b:02X}" for b in frame[6:12])
            ethertype = struct.unpack("!H", frame[12:14])[0]
            if ethertype != 0x0800:
                return None  # Only IPv4 handled currently
            ip_data = frame[14:]
        elif linktype in (101, 12):  # Raw IP
            ip_data = frame
        else:
            return None

        if len(ip_data) < 20:
            return None

        # IPv4 Header
        ver_ihl = ip_data[0]
        version = ver_ihl >> 4
        if version != 4:
            return None
        ihl = (ver_ihl & 0x0F) * 4
        if len(ip_data) < ihl:
            return None

        total_length = struct.unpack("!H", ip_data[2:4])[0]
        ip_id = struct.unpack("!H", ip_data[4:6])[0]
        ttl = ip_data[8]
        protocol_num = ip_data[9]
        src_ip = socket.inet_ntoa(ip_data[12:16])
        dst_ip = socket.inet_ntoa(ip_data[16:20])

        payload = ip_data[ihl:]
        src_port = 0
        dst_port = 0
        proto_str = "OTHER"
        tcp_flags = {
            "SYN": False,
            "ACK": False,
            "PSH": False,
            "RST": False,
            "FIN": False,
            "URG": False,
        }
        tcp_window = 0

        if protocol_num == 6:  # TCP
            proto_str = "TCP"
            if len(payload) >= 20:
                src_port, dst_port = struct.unpack("!HH", payload[0:4])
                offset_flags = struct.unpack("!H", payload[12:14])[0]
                flags_byte = offset_flags & 0x01FF
                tcp_flags = {
                    "FIN": bool(flags_byte & 0x01),
                    "SYN": bool(flags_byte & 0x02),
                    "RST": bool(flags_byte & 0x04),
                    "PSH": bool(flags_byte & 0x08),
                    "ACK": bool(flags_byte & 0x10),
                    "URG": bool(flags_byte & 0x20),
                }
                tcp_window = struct.unpack("!H", payload[14:16])[0]
        elif protocol_num == 17:  # UDP
            proto_str = "UDP"
            if len(payload) >= 8:
                src_port, dst_port = struct.unpack("!HH", payload[0:4])
        elif protocol_num == 1:  # ICMP
            proto_str = "ICMP"

        app_proto = infer_app_protocol(dst_port, proto_str)

        return ParsedPacket(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto_str,
            app_protocol=app_proto,
            length=max(total_length, len(frame)),
            ttl=ttl,
            ip_id=ip_id,
            tcp_flags=tcp_flags,
            tcp_window=tcp_window,
            tcp_timestamp=None,
            is_outbound=src_ip.startswith("192.168.1."),
        )

    def write_pcap(
        self,
        filepath: str | Path,
        packets: Sequence[dict[str, Any] | ParsedPacket],
    ) -> None:
        """Writes synthetic or recorded packets into a standard binary PCAP file."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        # 24-byte libpcap global header (little-endian microsecond, linktype 1 = Ethernet)
        hdr = struct.pack("<IHHiIII", self.MAGIC_MICRO_LE, 2, 4, 0, 0, 65535, 1)

        records = bytearray(hdr)

        for p in packets:
            if isinstance(p, ParsedPacket):
                ts = p.timestamp
                src_ip = p.src_ip
                dst_ip = p.dst_ip
                src_port = p.src_port
                dst_port = p.dst_port
                proto = p.protocol
                tcp_flags = p.tcp_flags
                length = p.length or 64
            else:
                ts = float(p.get("timestamp", 0.0))
                src_ip = str(p.get("src_ip", "192.168.1.100"))
                dst_ip = str(p.get("dst_ip", "192.168.1.1"))
                src_port = int(p.get("src_port", 12345))
                dst_port = int(p.get("dst_port", 80))
                proto = str(p.get("protocol", "TCP")).upper()
                tcp_flags = p.get("tcp_flags", {})
                length = int(p.get("length", 64))

            # Build Ethernet header (14 bytes)
            eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\x08\x00"

            # Build IP header (20 bytes)
            proto_num = 6 if proto == "TCP" else (17 if proto == "UDP" else 1)
            src_bytes = socket.inet_aton(src_ip)
            dst_bytes = socket.inet_aton(dst_ip)
            ip_hdr = struct.pack(
                "!BBHHHBBH4s4s",
                0x45,  # Version 4, IHL 5
                0,     # DSCP/ECN
                length,
                0x1234,
                0,
                64,    # TTL
                proto_num,
                0,     # Checksum
                src_bytes,
                dst_bytes,
            )

            # Build Transport header
            if proto == "TCP":
                flags_val = 0
                if tcp_flags.get("FIN"):
                    flags_val |= 0x01
                if tcp_flags.get("SYN"):
                    flags_val |= 0x02
                if tcp_flags.get("RST"):
                    flags_val |= 0x04
                if tcp_flags.get("PSH"):
                    flags_val |= 0x08
                if tcp_flags.get("ACK"):
                    flags_val |= 0x10
                if tcp_flags.get("URG"):
                    flags_val |= 0x20
                trans_hdr = struct.pack(
                    "!HHIIHHHH",
                    src_port,
                    dst_port,
                    1000,
                    2000,
                    (5 << 12) | flags_val,
                    64240,
                    0,
                    0,
                )
            else:
                trans_hdr = struct.pack("!HHHH", src_port, dst_port, max(8, length - 20), 0)

            frame = eth + ip_hdr + trans_hdr
            pad_len = max(0, length - len(frame))
            if pad_len > 0:
                frame += b"\x00" * pad_len

            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1e6)
            rec_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame))
            records.extend(rec_hdr)
            records.extend(frame)

        path.write_bytes(bytes(records))
