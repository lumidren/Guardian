"""
Single canonical source of truth for the 60 GUARDIAN behavioral features.

Reconciles code (`config.py`, `extractor.py`, `definitions.py`), `README.md`, and
`docs/REAL_DATA_VALIDATION.md` from a single registry (`registry.py`).

Scope & Header-Only Privacy Notes:
1. All 60 canonical features are extracted exclusively from Layer-2/3/4 packet
   headers (`tcpdump -s 96` snaplen). Zero Layer-7 payload bytes are inspected
   or decrypted (`requires_payload_bytes == False` for all 60 features).
2. Clock Skew (`tcp_clock_skew_est`, index 56): Computed solely from Layer-4 TCP
   Option Kind=8 (`TSval`) header timestamps relative to packet arrival time
   (`|(d_TSval / dt) - 1000| / 1000`). Hardware physical-layer identity
   (RF carrier frequency offset, I/Q constellation fingerprinting, or silicon
   PUFs requiring SDR receivers) is out of scope per ADR-007.
3. MQTT Topic Features (`mqtt_topic_count`, `mqtt_new_topic`, `mqtt_msg_rate`,
   `mqtt_payload_len_mean`): Excluded from the canonical 60-feature header-only
   registry because parsing MQTT topic strings (`PUBLISH` / `SUBSCRIBE` UTF-8
   topic fields) requires inspecting Layer-7 payload bytes after the TCP header
   (beyond header-only capture, and opaque under TLS port 8883). Instead,
   GUARDIAN relies on header-only port/size proxies (`protocol_mqtt_ratio` from
   TCP port 1883/8883 and packet-length statistics `pkt_len_*`).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class LayerType(StrEnum):
    LAYER_1_BEHAVIORAL = "LAYER_1_BEHAVIORAL"
    LAYER_2_NETWORK = "LAYER_2_NETWORK"
    LAYER_3_HEURISTIC = "LAYER_3_HEURISTIC"
    LAYER_3_PHYSICAL = "LAYER_3_HEURISTIC"  # Alias for backward compatibility
    TEMPORAL = "TEMPORAL"


@dataclass(frozen=True)
class FeatureMetadata:
    name: str
    index: int
    layer: LayerType
    human_name: str
    description: str
    unit: str
    is_anomaly_high: bool  # True if abnormal high value is alarming
    requires_payload_bytes: bool = False


CLOCK_SKEW_SCOPE_NOTE: str = (
    "Hardware physical-layer identity (radio-frequency carrier offset, I/Q "
    "constellation fingerprinting, or silicon PUFs) is out of scope for a "
    "software gateway (ADR-007). The feature `tcp_clock_skew_est` (index 56) is "
    "a purely software Layer-4 header heuristic computed from TCP Option Kind=8 "
    "(`TSval`) timestamps relative to gateway arrival timestamps "
    "(`|(d_TSval / dt) - 1000| / 1000`). When devices omit TCP timestamp options, "
    "`tcp_clock_skew_est` deterministically evaluates to `0.0`."
)

MQTT_PAYLOAD_SCOPE_NOTE: str = (
    "Extracting MQTT topic strings (`mqtt_topic_count`, `mqtt_new_topic`) requires "
    "reading variable-length UTF-8 topic bytes inside the Layer-7 MQTT application "
    "payload after the 2-byte MQTT fixed header (and is impossible without TLS "
    "termination on port 8883). To strictly honor GUARDIAN's zero-payload-inspection "
    "guarantee (`tcpdump -s 96` header-only capture), Layer-7 MQTT topic features "
    "are excluded from the canonical 60-feature vector. Instead, MQTT behavior is "
    "profiled via Layer-4 transport port classification (`protocol_mqtt_ratio` on "
    "TCP 1883/8883) and Layer-3/4 packet length distributions (`pkt_len_mean`, "
    "`pkt_len_std`, `pkt_len_entropy`)."
)

EXCLUDED_PAYLOAD_FEATURES: dict[str, str] = {
    "mqtt_topic_count": (
        "Requires parsing Layer-7 MQTT PUBLISH/SUBSCRIBE payload bytes after the TCP "
        "header to extract the UTF-8 topic length and string; incompatible with "
        "strict header-only ('no payload inspection') capture and TLS 8883."
    ),
    "mqtt_new_topic": (
        "Requires Stateful Layer-7 payload inspection of MQTT topic strings; "
        "replaced in the canonical 60-feature set by header-only `protocol_mqtt_ratio` "
        "and `pkt_len_entropy`."
    ),
    "mqtt_msg_rate": (
        "Requires parsing MQTT fixed headers inside the TCP payload stream to count "
        "coalesced messages; replaced by header-only `protocol_mqtt_ratio` and "
        "`pkt_rate_per_sec`."
    ),
    "mqtt_payload_len_mean": (
        "Requires parsing MQTT Remaining Length varint in the Layer-7 payload; "
        "replaced by header-only IP/frame `pkt_len_mean`."
    ),
}


FEATURE_REGISTRY: dict[str, FeatureMetadata] = {
    # Layer 1: Traffic Volume & Timing (1-18)
    "pkt_count_10s": FeatureMetadata("pkt_count_10s", 0, LayerType.LAYER_1_BEHAVIORAL, "Packet Count (10s)", "Total packets observed in 10-second window", "packets", True),
    "byte_count_10s": FeatureMetadata("byte_count_10s", 1, LayerType.LAYER_1_BEHAVIORAL, "Byte Volume (10s)", "Total byte volume in 10-second window", "bytes", True),
    "pkt_rate_per_sec": FeatureMetadata("pkt_rate_per_sec", 2, LayerType.LAYER_1_BEHAVIORAL, "Packet Rate", "Average packets per second ($N_{\\text{pkts}} / W$)", "pkts/sec", True),
    "byte_rate_per_sec": FeatureMetadata("byte_rate_per_sec", 3, LayerType.LAYER_1_BEHAVIORAL, "Throughput", "Average data throughput per second ($\\sum \\text{len}_i / W$)", "bytes/sec", True),
    "flow_duration_sec": FeatureMetadata("flow_duration_sec", 4, LayerType.LAYER_1_BEHAVIORAL, "Active Duration", "Active flow duration in window", "seconds", False),
    "iat_mean": FeatureMetadata("iat_mean", 5, LayerType.LAYER_1_BEHAVIORAL, "Mean Inter-Arrival Time", "Mean time between successive packets", "seconds", False),
    "iat_std": FeatureMetadata("iat_std", 6, LayerType.LAYER_1_BEHAVIORAL, "IAT Standard Deviation", "Standard deviation of inter-arrival times", "seconds", True),
    "iat_min": FeatureMetadata("iat_min", 7, LayerType.LAYER_1_BEHAVIORAL, "Min Inter-Arrival Time", "Minimum inter-arrival gap", "seconds", False),
    "iat_max": FeatureMetadata("iat_max", 8, LayerType.LAYER_1_BEHAVIORAL, "Max Inter-Arrival Time", "Maximum inter-arrival gap", "seconds", True),
    "iat_median": FeatureMetadata("iat_median", 9, LayerType.LAYER_1_BEHAVIORAL, "Median Inter-Arrival Time", "Median packet arrival gap", "seconds", False),
    "iat_skew": FeatureMetadata("iat_skew", 10, LayerType.LAYER_1_BEHAVIORAL, "IAT Skewness", "Third standardized moment of arrival intervals", "ratio", True),
    "iat_p90": FeatureMetadata("iat_p90", 11, LayerType.LAYER_1_BEHAVIORAL, "90th Percentile IAT", "90th percentile arrival gap", "seconds", True),
    "burstiness_index": FeatureMetadata("burstiness_index", 12, LayerType.LAYER_1_BEHAVIORAL, "Burstiness Index", "Fano factor variance-to-mean arrival ratio ($\\sigma^2 / \\mu$)", "index", True),
    "idle_ratio": FeatureMetadata("idle_ratio", 13, LayerType.LAYER_1_BEHAVIORAL, "Idle Ratio", "Fraction of window where device was idle", "ratio", False),
    "upstream_pkt_ratio": FeatureMetadata("upstream_pkt_ratio", 14, LayerType.LAYER_1_BEHAVIORAL, "Upstream Packet Ratio", "Fraction of outbound packets ($N_{\\text{up}} / N_{\\text{pkts}}$)", "ratio", True),
    "downstream_pkt_ratio": FeatureMetadata("downstream_pkt_ratio", 15, LayerType.LAYER_1_BEHAVIORAL, "Downstream Packet Ratio", "Fraction of inbound packets ($N_{\\text{down}} / N_{\\text{pkts}}$)", "ratio", False),
    "upstream_byte_ratio": FeatureMetadata("upstream_byte_ratio", 16, LayerType.LAYER_1_BEHAVIORAL, "Upstream Byte Ratio", "Fraction of outbound byte volume", "ratio", True),
    "downstream_byte_ratio": FeatureMetadata("downstream_byte_ratio", 17, LayerType.LAYER_1_BEHAVIORAL, "Downstream Byte Ratio", "Fraction of inbound byte volume", "ratio", False),

    # Layer 1: Packet Size Statistics (19-25)
    "pkt_len_mean": FeatureMetadata("pkt_len_mean", 18, LayerType.LAYER_1_BEHAVIORAL, "Mean Packet Length", "Average frame/IP packet length from header", "bytes", True),
    "pkt_len_std": FeatureMetadata("pkt_len_std", 19, LayerType.LAYER_1_BEHAVIORAL, "Packet Length Std", "Standard deviation of packet lengths", "bytes", True),
    "pkt_len_min": FeatureMetadata("pkt_len_min", 20, LayerType.LAYER_1_BEHAVIORAL, "Min Packet Length", "Smallest packet length observed", "bytes", False),
    "pkt_len_max": FeatureMetadata("pkt_len_max", 21, LayerType.LAYER_1_BEHAVIORAL, "Max Packet Length", "Largest packet length observed", "bytes", True),
    "pkt_len_median": FeatureMetadata("pkt_len_median", 22, LayerType.LAYER_1_BEHAVIORAL, "Median Packet Length", "Median packet size", "bytes", False),
    "pkt_len_entropy": FeatureMetadata("pkt_len_entropy", 23, LayerType.LAYER_1_BEHAVIORAL, "Packet Length Entropy", "Shannon entropy of 100-byte discretized packet lengths", "bits", True),
    "small_pkt_ratio": FeatureMetadata("small_pkt_ratio", 24, LayerType.LAYER_1_BEHAVIORAL, "Small Packet Ratio", "Fraction of packets $< 100$ bytes (probes/SYN)", "ratio", True),

    # Layer 1: Protocol Distribution (26-34)
    "protocol_mqtt_ratio": FeatureMetadata("protocol_mqtt_ratio", 25, LayerType.LAYER_1_BEHAVIORAL, "MQTT Ratio", "Fraction of packets on MQTT transport ports (1883/8883)", "ratio", False),
    "protocol_http_ratio": FeatureMetadata("protocol_http_ratio", 26, LayerType.LAYER_1_BEHAVIORAL, "HTTP Ratio", "Fraction of packets on HTTP port (80/8080)", "ratio", True),
    "protocol_https_ratio": FeatureMetadata("protocol_https_ratio", 27, LayerType.LAYER_1_BEHAVIORAL, "HTTPS Ratio", "Fraction of packets on HTTPS/TLS port (443)", "ratio", True),
    "protocol_dns_ratio": FeatureMetadata("protocol_dns_ratio", 28, LayerType.LAYER_1_BEHAVIORAL, "DNS Ratio", "Fraction of packets on DNS port (53)", "ratio", True),
    "protocol_coap_ratio": FeatureMetadata("protocol_coap_ratio", 29, LayerType.LAYER_1_BEHAVIORAL, "CoAP Ratio", "Fraction of packets on CoAP port (5683)", "ratio", False),
    "protocol_ntp_ratio": FeatureMetadata("protocol_ntp_ratio", 30, LayerType.LAYER_1_BEHAVIORAL, "NTP Ratio", "Fraction of packets on NTP port (123)", "ratio", False),
    "protocol_tcp_other_ratio": FeatureMetadata("protocol_tcp_other_ratio", 31, LayerType.LAYER_1_BEHAVIORAL, "Other TCP Ratio", "Fraction of unclassified TCP transport traffic", "ratio", True),
    "protocol_udp_other_ratio": FeatureMetadata("protocol_udp_other_ratio", 32, LayerType.LAYER_1_BEHAVIORAL, "Other UDP Ratio", "Fraction of unclassified UDP transport traffic", "ratio", True),
    "protocol_entropy": FeatureMetadata("protocol_entropy", 33, LayerType.LAYER_1_BEHAVIORAL, "Protocol Entropy", "Shannon entropy across classified transport protocols", "bits", True),

    # Layer 1: Port Dynamics & Entropy (35-41)
    "src_port_entropy": FeatureMetadata("src_port_entropy", 34, LayerType.LAYER_1_BEHAVIORAL, "Source Port Entropy", "Shannon entropy of source transport ports", "bits", True),
    "dst_port_entropy": FeatureMetadata("dst_port_entropy", 35, LayerType.LAYER_1_BEHAVIORAL, "Dest Port Entropy", "Shannon entropy of destination transport ports", "bits", True),
    "unique_dst_ports": FeatureMetadata("unique_dst_ports", 36, LayerType.LAYER_1_BEHAVIORAL, "Unique Dest Ports", "Number of distinct destination transport ports", "count", True),
    "wellknown_port_ratio": FeatureMetadata("wellknown_port_ratio", 37, LayerType.LAYER_1_BEHAVIORAL, "Well-Known Port Ratio", "Fraction of destination ports in $[0, 1023]$", "ratio", False),
    "ephemeral_port_ratio": FeatureMetadata("ephemeral_port_ratio", 38, LayerType.LAYER_1_BEHAVIORAL, "Ephemeral Port Ratio", "Fraction of destination ports $\\ge 49152$", "ratio", True),
    "std_port_deviation": FeatureMetadata("std_port_deviation", 39, LayerType.LAYER_1_BEHAVIORAL, "Port Dispersion", "Standard deviation of destination port numbers", "deviation", True),
    "high_risk_port_flag": FeatureMetadata("high_risk_port_flag", 40, LayerType.LAYER_1_BEHAVIORAL, "High-Risk Port Flag", "Binary indicator of traffic to known backdoor/Telnet/C2 ports", "binary", True),

    # Layer 2: Network Identity & Topology (42-49)
    "unique_dst_ips": FeatureMetadata("unique_dst_ips", 41, LayerType.LAYER_2_NETWORK, "Unique Dest IPs", "Number of distinct destination IP addresses contacted", "count", True),
    "dst_ip_entropy": FeatureMetadata("dst_ip_entropy", 42, LayerType.LAYER_2_NETWORK, "Dest IP Entropy", "Shannon entropy across destination IP addresses", "bits", True),
    "external_ip_ratio": FeatureMetadata("external_ip_ratio", 43, LayerType.LAYER_2_NETWORK, "External IP Ratio", "Fraction of packets destined outside the local LAN subnet", "ratio", True),
    "new_dst_ip_flag": FeatureMetadata("new_dst_ip_flag", 44, LayerType.LAYER_2_NETWORK, "New Destination IP", "Binary flag indicating an un-whitelisted destination IP", "binary", True),
    "out_degree_centrality": FeatureMetadata("out_degree_centrality", 45, LayerType.LAYER_2_NETWORK, "Out-Degree Centrality", "Normalized egress endpoint fan-out centrality", "score", True),
    "cross_subnet_ratio": FeatureMetadata("cross_subnet_ratio", 46, LayerType.LAYER_2_NETWORK, "Cross-Subnet Ratio", "Fraction of packets directed across internal private subnets", "ratio", True),
    "dns_query_frequency": FeatureMetadata("dns_query_frequency", 47, LayerType.LAYER_2_NETWORK, "DNS Query Frequency", "Rate of DNS port-53 packets per second", "queries/sec", True),
    "dns_failure_ratio": FeatureMetadata("dns_failure_ratio", 48, LayerType.LAYER_2_NETWORK, "DNS NXDOMAIN Ratio", "Fraction of failed DNS responses", "ratio", True),

    # Layer 1 & 2: Flow State & TCP Flags (50-55)
    "tcp_syn_ratio": FeatureMetadata("tcp_syn_ratio", 49, LayerType.LAYER_1_BEHAVIORAL, "TCP SYN Ratio", "Fraction of TCP packets with SYN flag set", "ratio", True),
    "tcp_ack_ratio": FeatureMetadata("tcp_ack_ratio", 50, LayerType.LAYER_1_BEHAVIORAL, "TCP ACK Ratio", "Fraction of TCP packets with ACK flag set", "ratio", False),
    "tcp_psh_ratio": FeatureMetadata("tcp_psh_ratio", 51, LayerType.LAYER_1_BEHAVIORAL, "TCP PSH Ratio", "Fraction of TCP packets with PSH flag set", "ratio", True),
    "tcp_rst_ratio": FeatureMetadata("tcp_rst_ratio", 52, LayerType.LAYER_1_BEHAVIORAL, "TCP RST Ratio", "Fraction of TCP packets with RST flag set", "ratio", True),
    "tcp_fin_ratio": FeatureMetadata("tcp_fin_ratio", 53, LayerType.LAYER_1_BEHAVIORAL, "TCP FIN Ratio", "Fraction of TCP packets with FIN flag set", "ratio", False),
    "tcp_win_mean": FeatureMetadata("tcp_win_mean", 54, LayerType.LAYER_1_BEHAVIORAL, "Mean TCP Window Size", "Mean advertised TCP receive window size in header", "bytes", False),

    # Layer 3: Protocol & Header Heuristic Signatures (56-58)
    "ip_ttl_variance": FeatureMetadata("ip_ttl_variance", 55, LayerType.LAYER_3_HEURISTIC, "IP TTL Variance", "Variance of IPv4 header Time-to-Live field", "variance", True),
    "tcp_clock_skew_est": FeatureMetadata("tcp_clock_skew_est", 56, LayerType.LAYER_3_HEURISTIC, "TCP Header TSval Skew Est", "Software TCP Option Kind=8 (`TSval`) header rate drift estimate (0.0 when TCP TS option absent; distinct from out-of-scope RF hardware fingerprinting)", "ppm", True),
    "ip_id_monotonicity": FeatureMetadata("ip_id_monotonicity", 57, LayerType.LAYER_3_HEURISTIC, "IP ID Monotonicity", "Fraction of sequential positive increments in IPv4 header ID field", "score", False),

    # Circadian & Temporal Consistency (59-60)
    "hour_sin": FeatureMetadata("hour_sin", 58, LayerType.TEMPORAL, "Circadian Sine", "Sine projection of hour of day: $\\sin(2\\pi \\cdot t_{\\text{hour}} / 24)$", "value", False),
    "hour_cos": FeatureMetadata("hour_cos", 59, LayerType.TEMPORAL, "Circadian Cosine", "Cosine projection of hour of day: $\\cos(2\\pi \\cdot t_{\\text{hour}} / 24)$", "value", False),
}

FEATURE_NAMES: list[str] = list(FEATURE_REGISTRY.keys())

assert len(FEATURE_REGISTRY) == 60, f"Registry size {len(FEATURE_REGISTRY)} does not match 60"
assert len(FEATURE_NAMES) == 60, f"FEATURE_NAMES size {len(FEATURE_NAMES)} does not match 60"
assert all(not m.requires_payload_bytes for m in FEATURE_REGISTRY.values()), (
    "All canonical features must be header-only (requires_payload_bytes=False)"
)


def _short_layer_label(layer: LayerType) -> str:
    if layer == LayerType.LAYER_1_BEHAVIORAL:
        return "1"
    if layer == LayerType.LAYER_2_NETWORK:
        return "2"
    if layer == LayerType.LAYER_3_HEURISTIC:
        return "3"
    return "Temp"


def render_readme_feature_table() -> str:
    """Render the canonical 60-feature Markdown table directly from FEATURE_REGISTRY."""
    lines = [
        "| # | Feature Name | Layer | Description & Formula | Unit | Suspicious Trend |",
        "| :---: | :--- | :---: | :--- | :---: | :---: |",
    ]
    for meta in FEATURE_REGISTRY.values():
        idx_1 = meta.index + 1
        layer_str = _short_layer_label(meta.layer)
        trend = "Higher ($\\uparrow$)" if meta.is_anomaly_high else "Lower / Shift ($\\downarrow$)"
        lines.append(
            f"| {idx_1} | `{meta.name}` | {layer_str} | {meta.description} | {meta.unit} | {trend} |"
        )
    return "\n".join(lines)


def get_canonical_feature_registry() -> dict[str, FeatureMetadata]:
    """Return a read-only copy of the canonical 60-feature registry."""
    return dict(FEATURE_REGISTRY)


def validate_registry_invariants() -> bool:
    """Validate that indices 0..59 are contiguous and all 60 features are header-only."""
    if len(FEATURE_REGISTRY) != 60 or len(FEATURE_NAMES) != 60:
        return False
    for expected_idx, (fname, meta) in enumerate(FEATURE_REGISTRY.items()):
        if meta.name != fname or meta.index != expected_idx or meta.requires_payload_bytes:
            return False
    return True


def sync_readme_feature_table(readme_path: object | None = None) -> bool:
    """
    Task 48: Synchronize the 60-feature Markdown table in README.md directly from FEATURE_REGISTRY.
    Returns True if the file was modified, False if already in sync.
    """
    from pathlib import Path

    target = Path(str(readme_path)) if readme_path is not None else (
        Path(__file__).resolve().parent.parent.parent.parent / "README.md"
    )
    content = target.read_text(encoding="utf-8")
    rendered = render_readme_feature_table()
    header = "| # | Feature Name | Layer | Description & Formula | Unit | Suspicious Trend |"
    if header not in content:
        raise ValueError(f"Feature table header not found in {target}")

    lines = content.splitlines()
    start_idx = next(i for i, ln in enumerate(lines) if ln.strip() == header)
    end_idx = start_idx + 1
    while end_idx < len(lines) and lines[end_idx].strip().startswith("|"):
        end_idx += 1

    new_lines = lines[:start_idx] + rendered.splitlines() + lines[end_idx:]
    updated = "\n".join(new_lines) + ("\n" if content.endswith("\n") else "")
    if updated != content:
        target.write_text(updated, encoding="utf-8")
        return True
    return False


def get_clock_skew_feature_policy() -> dict[str, object]:
    """
    Task 50: Return explicit scope and privacy policy metadata for tcp_clock_skew_est.
    Documents that hardware RF/PUF physical-layer identity is out of scope (ADR-007) and
    that index 56 is a purely software Layer-4 TCP Option Kind=8 (TSval) header heuristic.
    """
    meta = FEATURE_REGISTRY["tcp_clock_skew_est"]
    return {
        "feature_name": meta.name,
        "index": meta.index,
        "layer": str(meta.layer),
        "header_source": "TCP Option Kind=8 (TSval)",
        "fallback_when_ts_option_absent": 0.0,
        "requires_rf_or_sdr_hardware": False,
        "physical_layer_identity_in_scope": False,
        "scope_note": CLOCK_SKEW_SCOPE_NOTE,
    }
