"""Core Pydantic v2 data models and abstract interfaces for GUARDIAN.

Defines the authoritative data contracts used across all pipeline stages,
storage layers, explainability engine, response controllers, and APIs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# --- Enumerations ---


class PacketDirection(StrEnum):
    """Direction of traffic relative to the monitored device."""

    OUT = "out"
    IN = "in"


class DeviceType(StrEnum):
    """Supported IoT device profiles."""

    ESP32_SENSOR = "esp32_sensor"
    ESP8266_ACTUATOR = "esp8266_actuator"
    PI_ZERO = "pi_zero"
    ESP32_CAM = "esp32_cam"


class DeviceStage(StrEnum):
    """Lifecycle stage for hybrid cold-start profiling."""

    OBSERVE = "observe"
    RULES = "rules"
    STATISTICAL = "statistical"
    ML = "ml"


class DeviceMode(StrEnum):
    """Enforcement policy mode."""

    OBSERVE = "observe"
    ENFORCE = "enforce"


class ResponseLevel(StrEnum):
    """Graduated response levels."""

    NORMAL = "normal"
    MONITOR = "monitor"
    RESTRICT = "restrict"
    QUARANTINE = "quarantine"
    BLOCK = "block"


class AlertStatus(StrEnum):
    """Alert lifecycle states."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


# --- Core Models ---


class PacketRecord(BaseModel):
    """Normalized metadata for a single network packet."""

    model_config = ConfigDict(frozen=True)

    ts: float = Field(..., description="Timestamp in epoch seconds from Clock")
    src_ip: str
    dst_ip: str
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    proto: str = Field(..., description="Transport protocol: tcp, udp, icmp, or other")
    length: int = Field(..., ge=0, description="Total packet length in bytes")
    tcp_flags: str | None = Field(None, description="TCP flag string (e.g., SYN, ACK)")
    direction: PacketDirection = Field(
        ..., description="Direction relative to the monitored device"
    )
    app_proto: str = Field(
        ..., description="Detected application protocol: mqtt, http, tls, dns, ntp, other"
    )
    mqtt_topic: str | None = Field(None, description="MQTT topic string if applicable")
    payload_len: int = Field(0, ge=0, description="Application payload byte length")
    device_id: str = Field(..., description="Unique identifier of the monitored IoT device")


class Device(BaseModel):
    """Monitored IoT device metadata and security posture state."""

    device_id: str
    name: str
    type: DeviceType
    ip: str
    mac: str
    stage: DeviceStage = DeviceStage.OBSERVE
    first_seen: float
    mode: DeviceMode = DeviceMode.OBSERVE


class WindowFeatures(BaseModel):
    """Aggregated statistical feature vector over a fixed time window."""

    device_id: str
    window_start: float
    window_end: float
    vector: list[float] = Field(..., description="60-dimensional normalized feature vector")
    feature_names: list[str] = Field(..., description="Names corresponding to vector indices")
    n_packets: int = Field(..., ge=0)
    quality_flags: list[str] = Field(
        default_factory=list, description="Quality indicators such as sparse_window"
    )


class FeatureAttribution(BaseModel):
    """Feature-level attribution for explainability and diagnostics."""

    name: str
    value: float
    expected: float
    robust_z: float
    direction: str = Field(..., description="Direction of anomaly: higher, lower, or abnormal")


class Detection(BaseModel):
    """Multi-layer anomaly detection scoring result for a single window."""

    device_id: str
    window_end: float
    ml_score: float = Field(..., ge=0.0, le=100.0)
    stat_score: float = Field(..., ge=0.0, le=100.0)
    net_score: float = Field(..., ge=0.0, le=100.0)
    threat_score: float = Field(..., ge=0.0, le=100.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    level: ResponseLevel
    top_features: list[FeatureAttribution] = Field(default_factory=list)
    triggers: list[str] = Field(default_factory=list)


class LikelyAttack(BaseModel):
    """Predicted attack classification with confidence."""

    label: str
    confidence: float = Field(..., ge=0.0, le=1.0)


class Alert(BaseModel):
    """Security alert emitted following hysteresis confirmation."""

    alert_id: str
    device_id: str
    opened_at: float
    closed_at: float | None = None
    peak_score: float = Field(..., ge=0.0, le=100.0)
    level: ResponseLevel
    explanation: dict[str, Any] = Field(default_factory=dict)
    explanation_text: str
    likely_attack: LikelyAttack
    recommended_actions: list[str] = Field(default_factory=list)
    status: AlertStatus = AlertStatus.OPEN


class ResponseAction(BaseModel):
    """Enforcement or mitigation action dispatched by the Response Controller."""

    action_id: str
    device_id: str
    level: ResponseLevel
    backend: str
    rules_applied: list[str] = Field(default_factory=list)
    applied_at: float
    expires_at: float | None = None
    reverted_at: float | None = None
    reason: str
    overridden_by: str | None = None


class GeoInfo(BaseModel):
    """Geographical and autonomous system metadata for an external IP."""

    country: str | None = None
    city: str | None = None
    asn: int | None = None
    asn_org: str | None = None


# --- Abstract Base Interfaces ---


class PacketSource(ABC):
    """Abstract packet feed yielding PacketRecord objects."""

    @abstractmethod
    def __iter__(self) -> Iterator[PacketRecord]:
        """Iterate synchronously over incoming packet records."""
        raise NotImplementedError


class Detector(ABC):
    """Abstract interface for statistical and ML anomaly detectors."""

    @abstractmethod
    def fit(self, x_data: Any) -> None:
        """Train or fit baseline distributions on normal baseline data."""
        raise NotImplementedError

    @abstractmethod
    def score(self, x_sample: Any) -> float:
        """Compute anomaly score normalized in range [0, 100]."""
        raise NotImplementedError

    @abstractmethod
    def save(self, path: str) -> None:
        """Serialize model state to filesystem."""
        raise NotImplementedError

    @abstractmethod
    def load(self, path: str) -> None:
        """Load model state from filesystem."""
        raise NotImplementedError


class EnforcementBackend(ABC):
    """Abstract graduated response execution backend."""

    @abstractmethod
    def apply(self, device: Device, level: ResponseLevel) -> bool:
        """Apply containment rules for device at given response level."""
        raise NotImplementedError

    @abstractmethod
    def revert(self, device: Device) -> bool:
        """Revert containment rules back to normal state."""
        raise NotImplementedError

    @abstractmethod
    def status(self) -> dict[str, Any]:
        """Return backend runtime health and active containment state."""
        raise NotImplementedError


class GeoProvider(ABC):
    """Abstract geolocation provider."""

    @abstractmethod
    def lookup(self, ip: str) -> GeoInfo | None:
        """Look up geolocation and ASN metadata for an IP address."""
        raise NotImplementedError


class PhysicalIdentityProvider:
    """Stub for physical hardware identity provider."""

    def score(self, device: Device | str) -> None:
        """Return None as physical identity is a future hardware stub."""
        return None
