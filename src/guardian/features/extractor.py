"""
High-performance 60-feature behavioral extraction pipeline for GUARDIAN.
Transforms raw packet streams into mathematical multi-layer identity vectors.
"""

import math
from collections import Counter
from datetime import datetime
from typing import Any

import numpy as np

from ..capture.flow_tracker import FlowSummary
from ..config import FEATURE_NAMES

HIGH_RISK_PORTS = {21, 22, 23, 2323, 3389, 4444, 5555, 6667, 8888, 9999, 1337, 31337}


def shannon_entropy(items: list[Any]) -> float:
    """Calculate Shannon entropy in bits for a sequence of values."""
    if not items:
        return 0.0
    n = len(items)
    counts = Counter(items).values()
    return -sum((c / n) * math.log2(c / n) for c in counts if c > 0)


class FeatureExtractor:
    def __init__(self, local_subnet_prefix: str = "192.168.1."):
        self.local_subnet_prefix = local_subnet_prefix

    def extract(self, summary: FlowSummary) -> dict[str, float]:
        """
        Extract all 60 behavioral features from a FlowSummary.
        Returns a dictionary mapping feature_name -> float value.
        """
        pkts = summary.packets
        n_pkts = len(pkts)
        if n_pkts == 0:
            return {name: 0.0 for name in FEATURE_NAMES}

        duration = max(0.001, summary.duration)

        # Timestamps & Inter-Arrival Times (IAT)
        timestamps = [p.timestamp for p in pkts]
        iats = [max(0.0, timestamps[i] - timestamps[i - 1]) for i in range(1, n_pkts)]
        if not iats:
            iats = [0.0]

        iat_arr = np.array(iats, dtype=np.float64)
        iat_mean = float(np.mean(iat_arr))
        iat_std = float(np.std(iat_arr))
        iat_min = float(np.min(iat_arr))
        iat_max = float(np.max(iat_arr))
        iat_median = float(np.median(iat_arr))
        iat_p90 = float(np.percentile(iat_arr, 90))

        # Skewness calculation
        if iat_std > 1e-6:
            iat_skew = float(np.mean(((iat_arr - iat_mean) / iat_std) ** 3))
        else:
            iat_skew = 0.0

        # Burstiness Index (Fano factor of arrivals binned per 1-second chunks)
        bins = max(1, int(math.ceil(duration)))
        hist, _ = np.histogram(timestamps, bins=bins)
        hist_mean = np.mean(hist)
        hist_var = np.var(hist)
        burstiness_index = float(hist_var / hist_mean) if hist_mean > 0 else 0.0

        # Idle ratio
        idle_threshold = max(0.5, iat_mean * 2.0)
        idle_time = sum(gap for gap in iats if gap > idle_threshold)
        idle_ratio = min(1.0, float(idle_time / duration))

        # Volumes & Directions
        byte_lengths = [p.length for p in pkts]
        total_bytes = sum(byte_lengths)
        pkt_rate = float(n_pkts / duration)
        byte_rate = float(total_bytes / duration)

        up_pkts = [p for p in pkts if p.is_outbound]
        down_pkts = [p for p in pkts if not p.is_outbound]
        up_bytes = sum(p.length for p in up_pkts)
        down_bytes = sum(p.length for p in down_pkts)

        upstream_pkt_ratio = float(len(up_pkts) / n_pkts)
        downstream_pkt_ratio = float(len(down_pkts) / n_pkts)
        upstream_byte_ratio = float(up_bytes / total_bytes) if total_bytes > 0 else 0.0
        downstream_byte_ratio = float(down_bytes / total_bytes) if total_bytes > 0 else 0.0

        # Packet Size Distribution
        len_arr = np.array(byte_lengths, dtype=np.float64)
        pkt_len_mean = float(np.mean(len_arr))
        pkt_len_std = float(np.std(len_arr))
        pkt_len_min = float(np.min(len_arr))
        pkt_len_max = float(np.max(len_arr))
        pkt_len_median = float(np.median(len_arr))

        # Discretize lengths for entropy
        length_bins = [min(15, int(b_len // 100)) for b_len in byte_lengths]
        pkt_len_entropy = shannon_entropy(length_bins)
        small_pkt_ratio = float(sum(1 for b_len in byte_lengths if b_len < 100) / n_pkts)

        # Application Protocols
        app_protos = [p.app_protocol for p in pkts]
        proto_counter = Counter(app_protos)
        protocol_mqtt_ratio = float(proto_counter.get("MQTT", 0) / n_pkts)
        protocol_http_ratio = float(proto_counter.get("HTTP", 0) / n_pkts)
        protocol_https_ratio = float(proto_counter.get("HTTPS", 0) / n_pkts)
        protocol_dns_ratio = float(proto_counter.get("DNS", 0) / n_pkts)
        protocol_coap_ratio = float(proto_counter.get("COAP", 0) / n_pkts)
        protocol_ntp_ratio = float(proto_counter.get("NTP", 0) / n_pkts)

        tcp_other = sum(1 for p in pkts if p.protocol == "TCP" and p.app_protocol in ("TCP", "OTHER"))
        udp_other = sum(1 for p in pkts if p.protocol == "UDP" and p.app_protocol in ("UDP", "OTHER"))
        protocol_tcp_other_ratio = float(tcp_other / n_pkts)
        protocol_udp_other_ratio = float(udp_other / n_pkts)
        protocol_entropy = shannon_entropy(app_protos)

        # Port Dynamics
        src_ports = [p.src_port for p in pkts if p.src_port > 0]
        dst_ports = [p.dst_port for p in pkts if p.dst_port > 0]
        src_port_entropy = shannon_entropy(src_ports)
        dst_port_entropy = shannon_entropy(dst_ports)
        unique_dst_ports = float(len(set(dst_ports)))
        wellknown_ports = sum(1 for pt in dst_ports if pt < 1024)
        ephemeral_ports = sum(1 for pt in dst_ports if pt >= 49152)
        n_dst_ports = len(dst_ports) or 1
        wellknown_port_ratio = float(wellknown_ports / n_dst_ports)
        ephemeral_port_ratio = float(ephemeral_ports / n_dst_ports)
        std_port_deviation = float(np.std(dst_ports)) if dst_ports else 0.0
        high_risk_port_flag = 1.0 if any(pt in HIGH_RISK_PORTS for pt in dst_ports) else 0.0

        # Layer 2: Network Identity & Destinations
        dst_ips = [p.dst_ip for p in pkts]
        unique_dst_ips = float(len(set(dst_ips)))
        dst_ip_entropy = shannon_entropy(dst_ips)

        external_pkts = sum(1 for p in pkts if not p.dst_ip.startswith(self.local_subnet_prefix) and p.dst_ip != "255.255.255.255")
        external_ip_ratio = float(external_pkts / n_pkts)
        new_dst_ip_flag = 1.0 if summary.is_new_destination_seen else 0.0
        out_degree_centrality = float(min(1.0, unique_dst_ips / max(1.0, n_pkts * 0.1)))

        cross_subnet_pkts = sum(1 for p in pkts if p.dst_ip.startswith("10.") or p.dst_ip.startswith("172.16."))
        cross_subnet_ratio = float(cross_subnet_pkts / n_pkts)
        dns_query_frequency = float(proto_counter.get("DNS", 0) / duration)
        dns_failure_ratio = 0.0  # Derived from DNS NXDOMAIN if parsed

        # Flow State & TCP Flags
        tcp_pkts = [p for p in pkts if p.protocol == "TCP"]
        n_tcp = len(tcp_pkts)
        if n_tcp > 0:
            tcp_syn_ratio = float(sum(1 for p in tcp_pkts if p.tcp_flags.get("SYN", False)) / n_tcp)
            tcp_ack_ratio = float(sum(1 for p in tcp_pkts if p.tcp_flags.get("ACK", False)) / n_tcp)
            tcp_psh_ratio = float(sum(1 for p in tcp_pkts if p.tcp_flags.get("PSH", False)) / n_tcp)
            tcp_rst_ratio = float(sum(1 for p in tcp_pkts if p.tcp_flags.get("RST", False)) / n_tcp)
            tcp_fin_ratio = float(sum(1 for p in tcp_pkts if p.tcp_flags.get("FIN", False)) / n_tcp)
            tcp_win_mean = float(np.mean([p.tcp_window for p in tcp_pkts]))
        else:
            tcp_syn_ratio = tcp_ack_ratio = tcp_psh_ratio = tcp_rst_ratio = tcp_fin_ratio = 0.0
            tcp_win_mean = 0.0

        # Layer 3: Physical & Heuristic Signatures
        ttls = [p.ttl for p in pkts]
        ip_ttl_variance = float(np.var(ttls)) if len(ttls) > 1 else 0.0

        # TCP Clock Skew Estimation (gradient of TCP timestamps over actual arrival time)
        ts_pairs = [(p.timestamp, p.tcp_timestamp) for p in tcp_pkts if p.tcp_timestamp is not None]
        if len(ts_pairs) >= 2:
            dt = ts_pairs[-1][0] - ts_pairs[0][0]
            d_ts = ts_pairs[-1][1] - ts_pairs[0][1]
            tcp_clock_skew_est = float(abs((d_ts / max(0.001, dt)) - 1000.0) / 1000.0) if dt > 0 else 0.0
        else:
            tcp_clock_skew_est = 0.0

        # IP ID sequence monotonicity check
        ip_ids = [p.ip_id for p in pkts if p.ip_id > 0]
        if len(ip_ids) >= 2:
            diffs = [ip_ids[i] - ip_ids[i - 1] for i in range(1, len(ip_ids))]
            monotonic = sum(1 for d in diffs if 0 < d < 1000)
            ip_id_monotonicity = float(monotonic / len(diffs))
        else:
            ip_id_monotonicity = 1.0

        # Circadian & Temporal Consistency (Hour of day sinusoidal projection)
        dt_obj = datetime.fromtimestamp(summary.window_end)
        hour_fraction = dt_obj.hour + (dt_obj.minute / 60.0)
        hour_sin = float(math.sin(2 * math.pi * hour_fraction / 24.0))
        hour_cos = float(math.cos(2 * math.pi * hour_fraction / 24.0))

        # Build complete feature vector
        features = {
            "pkt_count_10s": float(n_pkts),
            "byte_count_10s": float(total_bytes),
            "pkt_rate_per_sec": pkt_rate,
            "byte_rate_per_sec": byte_rate,
            "flow_duration_sec": float(duration),
            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "iat_min": iat_min,
            "iat_max": iat_max,
            "iat_median": iat_median,
            "iat_skew": iat_skew,
            "iat_p90": iat_p90,
            "burstiness_index": burstiness_index,
            "idle_ratio": idle_ratio,
            "upstream_pkt_ratio": upstream_pkt_ratio,
            "downstream_pkt_ratio": downstream_pkt_ratio,
            "upstream_byte_ratio": upstream_byte_ratio,
            "downstream_byte_ratio": downstream_byte_ratio,
            "pkt_len_mean": pkt_len_mean,
            "pkt_len_std": pkt_len_std,
            "pkt_len_min": pkt_len_min,
            "pkt_len_max": pkt_len_max,
            "pkt_len_median": pkt_len_median,
            "pkt_len_entropy": pkt_len_entropy,
            "small_pkt_ratio": small_pkt_ratio,
            "protocol_mqtt_ratio": protocol_mqtt_ratio,
            "protocol_http_ratio": protocol_http_ratio,
            "protocol_https_ratio": protocol_https_ratio,
            "protocol_dns_ratio": protocol_dns_ratio,
            "protocol_coap_ratio": protocol_coap_ratio,
            "protocol_ntp_ratio": protocol_ntp_ratio,
            "protocol_tcp_other_ratio": protocol_tcp_other_ratio,
            "protocol_udp_other_ratio": protocol_udp_other_ratio,
            "protocol_entropy": protocol_entropy,
            "src_port_entropy": src_port_entropy,
            "dst_port_entropy": dst_port_entropy,
            "unique_dst_ports": unique_dst_ports,
            "wellknown_port_ratio": wellknown_port_ratio,
            "ephemeral_port_ratio": ephemeral_port_ratio,
            "std_port_deviation": std_port_deviation,
            "high_risk_port_flag": high_risk_port_flag,
            "unique_dst_ips": unique_dst_ips,
            "dst_ip_entropy": dst_ip_entropy,
            "external_ip_ratio": external_ip_ratio,
            "new_dst_ip_flag": new_dst_ip_flag,
            "out_degree_centrality": out_degree_centrality,
            "cross_subnet_ratio": cross_subnet_ratio,
            "dns_query_frequency": dns_query_frequency,
            "dns_failure_ratio": dns_failure_ratio,
            "tcp_syn_ratio": tcp_syn_ratio,
            "tcp_ack_ratio": tcp_ack_ratio,
            "tcp_psh_ratio": tcp_psh_ratio,
            "tcp_rst_ratio": tcp_rst_ratio,
            "tcp_fin_ratio": tcp_fin_ratio,
            "tcp_win_mean": tcp_win_mean,
            "ip_ttl_variance": ip_ttl_variance,
            "tcp_clock_skew_est": tcp_clock_skew_est,
            "ip_id_monotonicity": ip_id_monotonicity,
            "hour_sin": hour_sin,
            "hour_cos": hour_cos,
        }

        return features

    def extract_vector(self, summary: FlowSummary) -> np.ndarray:
        """Extract as ordered numpy array matching FEATURE_NAMES."""
        feat_dict = self.extract(summary)
        return np.array([feat_dict[name] for name in FEATURE_NAMES], dtype=np.float64)
