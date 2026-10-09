"""
Feature registry, metadata specifications, and layer groupings for the 60 GUARDIAN features.
"""

from dataclasses import dataclass
from enum import StrEnum


class LayerType(StrEnum):
    LAYER_1_BEHAVIORAL = "LAYER_1_BEHAVIORAL"
    LAYER_2_NETWORK = "LAYER_2_NETWORK"
    LAYER_3_PHYSICAL = "LAYER_3_PHYSICAL"
    TEMPORAL = "TEMPORAL"


@dataclass
class FeatureMetadata:
    name: str
    index: int
    layer: LayerType
    human_name: str
    description: str
    unit: str
    is_anomaly_high: bool  # True if abnormal high value is alarming


FEATURE_REGISTRY: dict[str, FeatureMetadata] = {
    # Layer 1: Traffic Volume & Timing (1-18)
    "pkt_count_10s": FeatureMetadata("pkt_count_10s", 0, LayerType.LAYER_1_BEHAVIORAL, "Packet Count (10s)", "Total packets observed in 10-second window", "packets", True),
    "byte_count_10s": FeatureMetadata("byte_count_10s", 1, LayerType.LAYER_1_BEHAVIORAL, "Byte Volume (10s)", "Total byte volume in 10-second window", "bytes", True),
    "pkt_rate_per_sec": FeatureMetadata("pkt_rate_per_sec", 2, LayerType.LAYER_1_BEHAVIORAL, "Packet Rate", "Average packets per second", "pkts/sec", True),
    "byte_rate_per_sec": FeatureMetadata("byte_rate_per_sec", 3, LayerType.LAYER_1_BEHAVIORAL, "Throughput", "Average data throughput per second", "bytes/sec", True),
    "flow_duration_sec": FeatureMetadata("flow_duration_sec", 4, LayerType.LAYER_1_BEHAVIORAL, "Active Duration", "Active flow duration in window", "seconds", False),
    "iat_mean": FeatureMetadata("iat_mean", 5, LayerType.LAYER_1_BEHAVIORAL, "Mean Inter-Arrival Time", "Mean time between successive packets", "seconds", False),
    "iat_std": FeatureMetadata("iat_std", 6, LayerType.LAYER_1_BEHAVIORAL, "IAT Standard Deviation", "Standard deviation of inter-arrival times", "seconds", True),
    "iat_min": FeatureMetadata("iat_min", 7, LayerType.LAYER_1_BEHAVIORAL, "Min Inter-Arrival Time", "Minimum inter-arrival gap", "seconds", False),
    "iat_max": FeatureMetadata("iat_max", 8, LayerType.LAYER_1_BEHAVIORAL, "Max Inter-Arrival Time", "Maximum inter-arrival gap", "seconds", True),
    "iat_median": FeatureMetadata("iat_median", 9, LayerType.LAYER_1_BEHAVIORAL, "Median Inter-Arrival Time", "Median packet arrival gap", "seconds", False),
    "iat_skew": FeatureMetadata("iat_skew", 10, LayerType.LAYER_1_BEHAVIORAL, "IAT Skewness", "Asymmetry of arrival intervals", "ratio", True),
    "iat_p90": FeatureMetadata("iat_p90", 11, LayerType.LAYER_1_BEHAVIORAL, "90th Percentile IAT", "90th percentile arrival gap", "seconds", True),
    "burstiness_index": FeatureMetadata("burstiness_index", 12, LayerType.LAYER_1_BEHAVIORAL, "Burstiness Index", "Fano factor variance-to-mean arrival ratio", "index", True),
    "idle_ratio": FeatureMetadata("idle_ratio", 13, LayerType.LAYER_1_BEHAVIORAL, "Idle Ratio", "Fraction of window where device was completely idle", "ratio", False),
    "upstream_pkt_ratio": FeatureMetadata("upstream_pkt_ratio", 14, LayerType.LAYER_1_BEHAVIORAL, "Upstream Packet Ratio", "Ratio of transmitted packets to received", "ratio", True),
    "downstream_pkt_ratio": FeatureMetadata("downstream_pkt_ratio", 15, LayerType.LAYER_1_BEHAVIORAL, "Downstream Packet Ratio", "Ratio of received packets to transmitted", "ratio", False),
    "upstream_byte_ratio": FeatureMetadata("upstream_byte_ratio", 16, LayerType.LAYER_1_BEHAVIORAL, "Upstream Byte Ratio", "Ratio of outbound data volume", "ratio", True),
    "downstream_byte_ratio": FeatureMetadata("downstream_byte_ratio", 17, LayerType.LAYER_1_BEHAVIORAL, "Downstream Byte Ratio", "Ratio of inbound data volume", "ratio", False),

    # Layer 1: Packet Size Statistics (19-25)
    "pkt_len_mean": FeatureMetadata("pkt_len_mean", 18, LayerType.LAYER_1_BEHAVIORAL, "Mean Packet Length", "Average packet payload and header size", "bytes", True),
    "pkt_len_std": FeatureMetadata("pkt_len_std", 19, LayerType.LAYER_1_BEHAVIORAL, "Packet Length Std", "Variability in packet lengths", "bytes", True),
    "pkt_len_min": FeatureMetadata("pkt_len_min", 20, LayerType.LAYER_1_BEHAVIORAL, "Min Packet Length", "Smallest packet observed", "bytes", False),
    "pkt_len_max": FeatureMetadata("pkt_len_max", 21, LayerType.LAYER_1_BEHAVIORAL, "Max Packet Length", "Largest packet observed", "bytes", True),
    "pkt_len_median": FeatureMetadata("pkt_len_median", 22, LayerType.LAYER_1_BEHAVIORAL, "Median Packet Length", "Median packet size", "bytes", False),
    "pkt_len_entropy": FeatureMetadata("pkt_len_entropy", 23, LayerType.LAYER_1_BEHAVIORAL, "Packet Length Entropy", "Information entropy of packet sizes", "bits", True),
    "small_pkt_ratio": FeatureMetadata("small_pkt_ratio", 24, LayerType.LAYER_1_BEHAVIORAL, "Small Packet Ratio", "Fraction of tiny packets (<100B, e.g. probes/syn)", "ratio", True),

    # Layer 1: Protocol Distribution (26-34)
    "protocol_mqtt_ratio": FeatureMetadata("protocol_mqtt_ratio", 25, LayerType.LAYER_1_BEHAVIORAL, "MQTT Ratio", "Fraction of MQTT packets", "ratio", False),
    "protocol_http_ratio": FeatureMetadata("protocol_http_ratio", 26, LayerType.LAYER_1_BEHAVIORAL, "HTTP Ratio", "Fraction of HTTP traffic", "ratio", True),
    "protocol_https_ratio": FeatureMetadata("protocol_https_ratio", 27, LayerType.LAYER_1_BEHAVIORAL, "HTTPS Ratio", "Fraction of HTTPS/TLS traffic", "ratio", True),
    "protocol_dns_ratio": FeatureMetadata("protocol_dns_ratio", 28, LayerType.LAYER_1_BEHAVIORAL, "DNS Ratio", "Fraction of DNS traffic", "ratio", True),
    "protocol_coap_ratio": FeatureMetadata("protocol_coap_ratio", 29, LayerType.LAYER_1_BEHAVIORAL, "CoAP Ratio", "Fraction of CoAP traffic", "ratio", False),
    "protocol_ntp_ratio": FeatureMetadata("protocol_ntp_ratio", 30, LayerType.LAYER_1_BEHAVIORAL, "NTP Ratio", "Fraction of NTP time synchronization traffic", "ratio", False),
    "protocol_tcp_other_ratio": FeatureMetadata("protocol_tcp_other_ratio", 31, LayerType.LAYER_1_BEHAVIORAL, "Other TCP Ratio", "Fraction of non-standard TCP traffic", "ratio", True),
    "protocol_udp_other_ratio": FeatureMetadata("protocol_udp_other_ratio", 32, LayerType.LAYER_1_BEHAVIORAL, "Other UDP Ratio", "Fraction of non-standard UDP traffic", "ratio", True),
    "protocol_entropy": FeatureMetadata("protocol_entropy", 33, LayerType.LAYER_1_BEHAVIORAL, "Protocol Entropy", "Entropy across application protocols", "bits", True),

    # Layer 1: Port Dynamics & Entropy (35-41)
    "src_port_entropy": FeatureMetadata("src_port_entropy", 34, LayerType.LAYER_1_BEHAVIORAL, "Source Port Entropy", "Randomness in source ports", "bits", True),
    "dst_port_entropy": FeatureMetadata("dst_port_entropy", 35, LayerType.LAYER_1_BEHAVIORAL, "Dest Port Entropy", "Randomness in destination ports", "bits", True),
    "unique_dst_ports": FeatureMetadata("unique_dst_ports", 36, LayerType.LAYER_1_BEHAVIORAL, "Unique Dest Ports", "Number of distinct destination ports", "count", True),
    "wellknown_port_ratio": FeatureMetadata("wellknown_port_ratio", 37, LayerType.LAYER_1_BEHAVIORAL, "Well-Known Port Ratio", "Traffic to ports 0-1023", "ratio", False),
    "ephemeral_port_ratio": FeatureMetadata("ephemeral_port_ratio", 38, LayerType.LAYER_1_BEHAVIORAL, "Ephemeral Port Ratio", "Traffic to ports >49151", "ratio", True),
    "std_port_deviation": FeatureMetadata("std_port_deviation", 39, LayerType.LAYER_1_BEHAVIORAL, "Port Dispersion", "Standard deviation of destination port numbers", "deviation", True),
    "high_risk_port_flag": FeatureMetadata("high_risk_port_flag", 40, LayerType.LAYER_1_BEHAVIORAL, "High-Risk Port Flag", "Communication with known backdoor/C2/telnet ports", "binary", True),

    # Layer 2: Network Identity & Topology (42-49)
    "unique_dst_ips": FeatureMetadata("unique_dst_ips", 41, LayerType.LAYER_2_NETWORK, "Unique Dest IPs", "Distinct remote IP endpoints contacted", "count", True),
    "dst_ip_entropy": FeatureMetadata("dst_ip_entropy", 42, LayerType.LAYER_2_NETWORK, "Dest IP Entropy", "Dispersion across destination IPs", "bits", True),
    "external_ip_ratio": FeatureMetadata("external_ip_ratio", 43, LayerType.LAYER_2_NETWORK, "External IP Ratio", "Fraction of packets routed to WAN/Internet", "ratio", True),
    "new_dst_ip_flag": FeatureMetadata("new_dst_ip_flag", 44, LayerType.LAYER_2_NETWORK, "New Destination IP", "Presence of never-before-seen IP address", "binary", True),
    "out_degree_centrality": FeatureMetadata("out_degree_centrality", 45, LayerType.LAYER_2_NETWORK, "Out-Degree Centrality", "Normalized network graph egress connectivity", "score", True),
    "cross_subnet_ratio": FeatureMetadata("cross_subnet_ratio", 46, LayerType.LAYER_2_NETWORK, "Cross-Subnet Ratio", "Traffic directed across internal subnets", "ratio", True),
    "dns_query_frequency": FeatureMetadata("dns_query_frequency", 47, LayerType.LAYER_2_NETWORK, "DNS Query Frequency", "Rate of domain resolutions requested", "queries/sec", True),
    "dns_failure_ratio": FeatureMetadata("dns_failure_ratio", 48, LayerType.LAYER_2_NETWORK, "DNS NXDOMAIN Ratio", "Failed DNS responses indicating DGA/beaconing", "ratio", True),

    # Flow State & TCP Flags (50-55)
    "tcp_syn_ratio": FeatureMetadata("tcp_syn_ratio", 49, LayerType.LAYER_1_BEHAVIORAL, "TCP SYN Ratio", "Fraction of SYN packets (scan/flood indicator)", "ratio", True),
    "tcp_ack_ratio": FeatureMetadata("tcp_ack_ratio", 50, LayerType.LAYER_1_BEHAVIORAL, "TCP ACK Ratio", "Fraction of ACK packets", "ratio", False),
    "tcp_psh_ratio": FeatureMetadata("tcp_psh_ratio", 51, LayerType.LAYER_1_BEHAVIORAL, "TCP PSH Ratio", "Fraction of PSH packets (data push)", "ratio", True),
    "tcp_rst_ratio": FeatureMetadata("tcp_rst_ratio", 52, LayerType.LAYER_1_BEHAVIORAL, "TCP RST Ratio", "Fraction of RST packets (connection aborts)", "ratio", True),
    "tcp_fin_ratio": FeatureMetadata("tcp_fin_ratio", 53, LayerType.LAYER_1_BEHAVIORAL, "TCP FIN Ratio", "Fraction of FIN packets (connection closures)", "ratio", False),
    "tcp_win_mean": FeatureMetadata("tcp_win_mean", 54, LayerType.LAYER_1_BEHAVIORAL, "Mean TCP Window Size", "Average advertised TCP receive window", "bytes", False),

    # Layer 3: Physical / Heuristic Signatures (56-58)
    "ip_ttl_variance": FeatureMetadata("ip_ttl_variance", 55, LayerType.LAYER_3_PHYSICAL, "IP TTL Variance", "Variability in IP Time-to-Live indicating routing spoofing", "variance", True),
    "tcp_clock_skew_est": FeatureMetadata("tcp_clock_skew_est", 56, LayerType.LAYER_3_PHYSICAL, "Clock Skew Est", "Estimated drift in TCP timestamp frequency", "ppm", True),
    "ip_id_monotonicity": FeatureMetadata("ip_id_monotonicity", 57, LayerType.LAYER_3_PHYSICAL, "IP ID Monotonicity", "Consistency of IP ID incremental sequence", "score", False),

    # Circadian & Temporal Consistency (59-60)
    "hour_sin": FeatureMetadata("hour_sin", 58, LayerType.TEMPORAL, "Circadian Sine", "Sinusoidal representation of hour of day", "value", False),
    "hour_cos": FeatureMetadata("hour_cos", 59, LayerType.TEMPORAL, "Circadian Cosine", "Cosine representation of hour of day", "value", False),
}

assert len(FEATURE_REGISTRY) == 60, f"Registry size {len(FEATURE_REGISTRY)} does not match 60"
