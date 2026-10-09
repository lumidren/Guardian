"""
Sliding-window flow tracker for IoT devices.
Aggregates packet streams by device identity (MAC or IP address) over a sliding time window.
"""

from collections import defaultdict, deque
from dataclasses import dataclass

from .packet_parser import ParsedPacket


@dataclass
class FlowSummary:
    device_id: str  # IP or MAC address
    window_start: float
    window_end: float
    duration: float
    packets: list[ParsedPacket]
    known_destinations: set[str]
    is_new_destination_seen: bool = False


class FlowTracker:
    def __init__(self, window_size_seconds: float = 10.0, max_packets_per_window: int = 50000):
        self.window_size_seconds = window_size_seconds
        self.max_packets_per_window = max_packets_per_window

        # device_id -> deque of ParsedPacket
        self.device_buffers: dict[str, deque] = defaultdict(deque)

        # device_id -> set of previously known destination IPs (Layer 2 Identity)
        self.known_destinations: dict[str, set[str]] = defaultdict(set)

        # device_id -> last window processed timestamp
        self.last_window_time: dict[str, float] = defaultdict(float)

    def register_known_destination(self, device_id: str, dest_ip: str):
        """Add an IP to the device's known historical communication whitelist."""
        self.known_destinations[device_id].add(dest_ip)

    def ingest_packet(self, packet: ParsedPacket, local_subnet_prefix: str = "192.168.1."):
        """
        Ingest a packet into the appropriate device's rolling buffer.
        Identifies which device (source or destination) belongs to the protected IoT fleet.
        """
        # Determine protected device identifier
        device_id = None
        if packet.src_ip.startswith(local_subnet_prefix):
            device_id = packet.src_ip
        elif packet.dst_ip.startswith(local_subnet_prefix):
            device_id = packet.dst_ip
        elif packet.src_mac != "00:00:00:00:00:00":
            device_id = packet.src_mac

        if not device_id:
            return

        buf = self.device_buffers[device_id]
        buf.append(packet)

        # Evict packets older than the sliding window
        current_time = packet.timestamp
        cutoff = current_time - self.window_size_seconds
        while buf and buf[0].timestamp < cutoff:
            buf.popleft()

        # Enforce max buffer size to avoid memory overflow on heavy DDoS attacks
        while len(buf) > self.max_packets_per_window:
            buf.popleft()

    def get_window_summary(self, device_id: str, current_timestamp: float | None = None) -> FlowSummary | None:
        """
        Extract the current sliding window summary for a specific device.
        """
        buf = self.device_buffers.get(device_id)
        if not buf or len(buf) == 0:
            return None

        packets = list(buf)
        start_time = packets[0].timestamp
        end_time = packets[-1].timestamp
        duration = max(0.001, end_time - start_time)

        # Check for novel destination IPs (Layer 2 novel destination detection)
        known = self.known_destinations[device_id]
        new_dest_seen = False
        for p in packets:
            if p.is_outbound and p.dst_ip not in known and not p.dst_ip.startswith("192.168.1.") and p.dst_ip != "255.255.255.255":
                new_dest_seen = True
                break

        return FlowSummary(
            device_id=device_id,
            window_start=start_time,
            window_end=end_time,
            duration=duration,
            packets=packets,
            known_destinations=set(known),
            is_new_destination_seen=new_dest_seen
        )

    def get_all_active_devices(self) -> list[str]:
        """Return list of active device identifiers."""
        return list(self.device_buffers.keys())

    def clear_device(self, device_id: str):
        """Reset buffer for a device."""
        if device_id in self.device_buffers:
            self.device_buffers[device_id].clear()
