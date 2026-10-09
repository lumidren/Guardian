"""
Unified traffic sniffer supporting live network capture, PCAP replay, and synthetic queue ingestion.
"""

import queue
import threading
import time
from typing import Callable, Optional
from .packet_parser import ParsedPacket, parse_raw_packet
from .flow_tracker import FlowTracker


class TrafficSniffer:
    def __init__(self, flow_tracker: FlowTracker, interface: Optional[str] = None):
        self.flow_tracker = flow_tracker
        self.interface = interface
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._synthetic_queue: queue.Queue = queue.Queue()
        self._on_packet_callbacks = []

    def register_callback(self, cb: Callable[[ParsedPacket], None]):
        """Register a subscriber callback for each parsed packet."""
        self._on_packet_callbacks.append(cb)

    def dispatch_packet(self, parsed_pkt: ParsedPacket):
        """Dispatch a parsed packet to the flow tracker and callbacks."""
        self.flow_tracker.ingest_packet(parsed_pkt)
        for cb in self._on_packet_callbacks:
            try:
                cb(parsed_pkt)
            except Exception:
                pass

    def inject_packet(self, packet_data: dict | ParsedPacket):
        """Inject a packet into the processing pipeline (for simulation/testing)."""
        parsed = parse_raw_packet(packet_data)
        if parsed:
            self.dispatch_packet(parsed)

    def _live_capture_worker(self):
        """Worker thread for live Scapy or raw socket packet sniffing."""
        try:
            from scapy.all import sniff
            def _scapy_cb(pkt):
                if not self.is_running:
                    return
                parsed = parse_raw_packet(pkt)
                if parsed:
                    self.dispatch_packet(parsed)

            sniff(
                iface=self.interface,
                prn=_scapy_cb,
                store=False,
                stop_filter=lambda p: not self.is_running
            )
        except Exception as e:
            # Fallback to simulated/queue mode if scapy live sniffing fails or lacks root/Npcap
            print(f"[Sniffer] Live capture unavailable ({e}); switching to synthetic queue mode.")
            while self.is_running:
                try:
                    raw = self._synthetic_queue.get(timeout=0.2)
                    parsed = parse_raw_packet(raw)
                    if parsed:
                        self.dispatch_packet(parsed)
                except queue.Empty:
                    continue

    def start(self, live: bool = False):
        """Start the sniffer thread."""
        if self.is_running:
            return
        self.is_running = True
        if live:
            self._thread = threading.Thread(target=self._live_capture_worker, daemon=True)
            self._thread.start()
        print("[Sniffer] Traffic sniffer started.")

    def stop(self):
        """Stop packet capture."""
        self.is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        print("[Sniffer] Traffic sniffer stopped.")
