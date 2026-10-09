"""
SQLAlchemy ORM models for GUARDIAN storage.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Device(Base):
    __tablename__ = "devices"

    id = Column(String(64), primary_key=True)  # MAC or IP
    name = Column(String(128), nullable=False)
    device_type = Column(String(64), default="Sensor")  # Camera, Plug, Sensor, Compute, Actuator
    ip_address = Column(String(45), nullable=False)
    mac_address = Column(String(17), nullable=False)
    hardware = Column(String(64), default="ESP32")  # ESP32, ESP8266, RPi Zero, ESP32-CAM
    threat_level = Column(String(32), default="MONITOR")  # MONITOR, RESTRICT, QUARANTINE, BLOCK
    current_threat_score = Column(Integer, default=0)
    confidence_level = Column(String(32), default="High (90-100%)")
    is_isolated = Column(Boolean, default=False)
    phase = Column(String(32), default="ACTIVE_PROTECTION")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
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

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(64), nullable=False)
    device_name = Column(String(128), nullable=False)
    threat_score = Column(Integer, nullable=False)
    threat_level = Column(String(32), nullable=False)
    confidence_level = Column(String(32), nullable=False)
    likely_attack = Column(String(64), nullable=False)
    details_json = Column(Text, nullable=False)
    plain_text_summary = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_resolved = Column(Boolean, default=False)

    def to_dict(self):
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

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(64), unique=True, nullable=False)
    sample_count = Column(Integer, default=0)
    means_json = Column(Text, nullable=False)
    stds_json = Column(Text, nullable=False)
    model_path = Column(String(256), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)


class SystemMetric(Base):
    __tablename__ = "metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    cpu_usage_pct = Column(Float, default=0.0)
    ram_usage_mb = Column(Float, default=0.0)
    detection_latency_ms = Column(Float, default=0.0)
    enforcement_latency_ms = Column(Float, default=0.0)
    active_devices_count = Column(Integer, default=0)

    def to_dict(self):
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

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String(64), nullable=False)  # "BLOCK", "OVERRIDE", "RETRAIN", "STARTUP"
    device_id = Column(String(64), nullable=False)
    details = Column(Text, nullable=False)
