"""
Global configuration and feature definitions for GUARDIAN IoT Security Framework.
"""

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel


class ThreatLevel(StrEnum):
    MONITOR = "MONITOR"       # 0 - 30: Enhanced logging only (minimal impact)
    RESTRICT = "RESTRICT"     # 31 - 60: Rate limit bandwidth 50%, block external IPs
    QUARANTINE = "QUARANTINE" # 61 - 85: Isolated local subnet, disable WAN
    BLOCK = "BLOCK"           # 86 - 100: Complete isolation, device offline


class SystemPhase(StrEnum):
    COLD_START_OBSERVATION = "COLD_START_OBSERVATION"  # Hour 0-24: Whitelist + rate limiting
    STATISTICAL_BASELINE = "STATISTICAL_BASELINE"      # Hour 24-48: Z-Score statistical thresholds
    ACTIVE_PROTECTION = "ACTIVE_PROTECTION"            # Hour 48+: Isolation Forest ML + XAI


# Canonical 60-feature specification
FEATURE_NAMES: list[str] = [
    # Layer 1: Traffic Volume & Timing (1-18)
    "pkt_count_10s",
    "byte_count_10s",
    "pkt_rate_per_sec",
    "byte_rate_per_sec",
    "flow_duration_sec",
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "iat_median",
    "iat_skew",
    "iat_p90",
    "burstiness_index",
    "idle_ratio",
    "upstream_pkt_ratio",
    "downstream_pkt_ratio",
    "upstream_byte_ratio",
    "downstream_byte_ratio",

    # Layer 1: Packet Size Statistics (19-25)
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_min",
    "pkt_len_max",
    "pkt_len_median",
    "pkt_len_entropy",
    "small_pkt_ratio",     # packets < 100 bytes

    # Layer 1: Protocol Distribution (26-34)
    "protocol_mqtt_ratio",
    "protocol_http_ratio",
    "protocol_https_ratio",
    "protocol_dns_ratio",
    "protocol_coap_ratio",
    "protocol_ntp_ratio",
    "protocol_tcp_other_ratio",
    "protocol_udp_other_ratio",
    "protocol_entropy",

    # Layer 1: Port Dynamics & Entropy (35-41)
    "src_port_entropy",
    "dst_port_entropy",
    "unique_dst_ports",
    "wellknown_port_ratio",
    "ephemeral_port_ratio",
    "std_port_deviation",
    "high_risk_port_flag",

    # Layer 2: Network Identity & Topology (42-49)
    "unique_dst_ips",
    "dst_ip_entropy",
    "external_ip_ratio",
    "new_dst_ip_flag",
    "out_degree_centrality",
    "cross_subnet_ratio",
    "dns_query_frequency",
    "dns_failure_ratio",

    # Layer 1 & 2: Flow State & TCP Flags (50-55)
    "tcp_syn_ratio",
    "tcp_ack_ratio",
    "tcp_psh_ratio",
    "tcp_rst_ratio",
    "tcp_fin_ratio",
    "tcp_win_mean",

    # Layer 3: Protocol, Circadian & Heuristic Signatures (56-58)
    "ip_ttl_variance",
    "tcp_clock_skew_est",
    "ip_id_monotonicity",

    # Circadian & Temporal Consistency (59-60)
    "hour_sin",
    "hour_cos",
]

assert len(FEATURE_NAMES) == 60, f"Expected 60 features, got {len(FEATURE_NAMES)}"


class GuardianConfig(BaseModel):
    # Base paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = Path(__file__).resolve().parent.parent.parent / "data"
    MODELS_DIR: Path = Path(__file__).resolve().parent.parent.parent / "models"
    DB_PATH: Path = Path(__file__).resolve().parent.parent.parent / "guardian.db"

    # Gateway Networking
    GATEWAY_INTERFACE: str = "eth0"
    LOCAL_SUBNET: str = "192.168.1.0/24"
    GATEWAY_IP: str = "192.168.1.1"
    MQTT_BROKER_HOST: str = "127.0.0.1"
    MQTT_BROKER_PORT: int = 1883

    # Pipeline Timing
    WINDOW_SIZE_SECONDS: float = 10.0
    INFERENCE_INTERVAL_SECONDS: float = 1.0
    MAX_PACKETS_PER_WINDOW: int = 50000

    # ML Parameters
    N_ESTIMATORS: int = 100
    CONTAMINATION: float = 0.05
    RANDOM_STATE: int = 42

    # Graduated Response Thresholds (Threat Scores 0-100)
    THREAT_THRESHOLD_MONITOR: float = 0.0
    THREAT_THRESHOLD_RESTRICT: float = 31.0
    THREAT_THRESHOLD_QUARANTINE: float = 61.0
    THREAT_THRESHOLD_BLOCK: float = 86.0

    # Cold Start Timeline (Hours)
    COLD_START_HOURS: float = 24.0
    STATISTICAL_HOURS: float = 48.0

    # Concept Drift Thresholds (Percentage change in baseline profile)
    DRIFT_MINOR_THRESHOLD: float = 0.10   # <10% auto-adapt
    DRIFT_MODERATE_THRESHOLD: float = 0.30 # 10-30% prompt user
    # >30% trigger major warning

    # System Performance Targets (from Section 8.2 & Table 9)
    MAX_ALLOWED_DETECTION_LATENCY_S: float = 1.0
    MAX_ALLOWED_ENFORCEMENT_LATENCY_S: float = 0.3
    TARGET_CPU_USAGE_PCT: float = 40.0
    TARGET_RAM_USAGE_MB: float = 2048.0

    model_config = {"arbitrary_types_allowed": True}


# Global default configuration instance
config = GuardianConfig()
