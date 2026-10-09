"""
Unit tests for GUARDIAN 60-feature extraction pipeline.
"""

import time

import numpy as np

from guardian.capture.flow_tracker import FlowSummary
from guardian.capture.packet_parser import ParsedPacket
from guardian.features.extractor import FeatureExtractor


def test_60_features_extracted():
    extractor = FeatureExtractor(local_subnet_prefix="192.168.1.")

    # Create sample packets for a 10s window
    now = time.time()
    packets = [
        ParsedPacket(
            timestamp=now - 8.0 + (i * 0.5),
            src_ip="192.168.1.108",
            dst_ip="192.168.1.1",
            src_mac="30:AE:A4:00:04:01",
            dst_mac="B8:27:EB:AA:BB:CC",
            src_port=50000 + i,
            dst_port=1883,
            protocol="TCP",
            app_protocol="MQTT",
            length=120,
            ttl=64,
            ip_id=1000 + i,
            tcp_flags={"SYN": False, "ACK": True, "PSH": False, "RST": False, "FIN": False, "URG": False},
            tcp_window=64240,
            tcp_timestamp=100000 + (i * 500),
            is_outbound=True
        )
        for i in range(16)
    ]

    summary = FlowSummary(
        device_id="192.168.1.108",
        window_start=now - 8.0,
        window_end=now,
        duration=8.0,
        packets=packets,
        known_destinations={"192.168.1.1"},
        is_new_destination_seen=False
    )

    feat_dict = extractor.extract(summary)
    feat_vec = extractor.extract_vector(summary)

    assert len(feat_dict) == 60
    assert len(feat_vec) == 60
    assert not np.isnan(feat_vec).any()
    assert not np.isinf(feat_vec).any()
    assert feat_dict["protocol_mqtt_ratio"] == 1.0
    assert feat_dict["pkt_count_10s"] == 16.0
