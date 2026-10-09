"""
SQLAlchemy ORM models for GUARDIAN storage.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # MAC or IP
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    device_type: Mapped[str] = mapped_column(String(64), default="Sensor")  # Camera, Plug, Sensor, Compute, Actuator
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False)
    hardware: Mapped[str] = mapped_column(String(64), default="ESP32")  # ESP32, ESP8266, RPi Zero, ESP32-CAM
    threat_level: Mapped[str] = mapped_column(String(32), default="MONITOR")  # MONITOR, RESTRICT, QUARANTINE, BLOCK
    current_threat_score: Mapped[int] = mapped_column(Integer, default=0)
    confidence_level: Mapped[str] = mapped_column(String(32), default="High (90-100%)")
    is_isolated: Mapped[bool] = mapped_column(Boolean, default=False)
    phase: Mapped[str] = mapped_column(String(32), default="ACTIVE_PROTECTION")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "device_type": self.device_type,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hardware": self.hardware,
            "threat_level": self.threat_level,
            "current_threat_score": self.current_threat_score,
            "confidence_level": self.confidence_level,
            "is_isolated": self.is_isolated,
            "phase": self.phase,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False)
    device_name: Mapped[str] = mapped_column(String(128), nullable=False)
    threat_score: Mapped[int] = mapped_column(Integer, nullable=False)
    threat_level: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence_level: Mapped[str] = mapped_column(String(32), nullable=False)
    likely_attack: Mapped[str] = mapped_column(String(64), nullable=False)
    details_json: Mapped[str] = mapped_column(Text, nullable=False)
    plain_text_summary: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "threat_score": self.threat_score,
            "threat_level": self.threat_level,
            "confidence_level": self.confidence_level,
            "likely_attack": self.likely_attack,
            "details_json": self.details_json,
            "plain_text_summary": self.plain_text_summary,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "is_resolved": self.is_resolved,
        }


class BehavioralBaseline(Base):
    __tablename__ = "baselines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, default=0)
    means_json: Mapped[str] = mapped_column(Text, nullable=False)
    stds_json: Mapped[str] = mapped_column(Text, nullable=False)
    model_path: Mapped[str | None] = mapped_column(String(256), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class SystemMetric(Base):
    __tablename__ = "metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    cpu_usage_pct: Mapped[float] = mapped_column(Float, default=0.0)
    ram_usage_mb: Mapped[float] = mapped_column(Float, default=0.0)
    detection_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    enforcement_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    active_devices_count: Mapped[int] = mapped_column(Integer, default=0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "cpu_usage_pct": self.cpu_usage_pct,
            "ram_usage_mb": self.ram_usage_mb,
            "detection_latency_ms": self.detection_latency_ms,
            "enforcement_latency_ms": self.enforcement_latency_ms,
            "active_devices_count": self.active_devices_count,
        }


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    action: Mapped[str] = mapped_column(String(64), nullable=False)  # "BLOCK", "OVERRIDE", "RETRAIN", "STARTUP"
    device_id: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
