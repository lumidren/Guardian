"""
Database Manager for GUARDIAN storage.
Provides robust thread-safe connection pooling, SQLite initialization, and CRUD methods.
"""

from datetime import datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from ..config import config
from .models import Alert, Base, Device, SystemMetric


class DatabaseManager:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or config.DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            connect_args={"check_same_thread": False}
        )
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self._init_db()

    def _init_db(self):
        Base.metadata.create_all(bind=self.engine)

    def get_session(self) -> Session:
        return self.SessionLocal()

    def upsert_device(
        self,
        device_id: str,
        name: str,
        device_type: str,
        ip_address: str,
        mac_address: str,
        hardware: str,
        threat_level: str = "MONITOR",
        current_threat_score: int = 0,
        confidence_level: str = "High (90-100%)",
        phase: str = "ACTIVE_PROTECTION"
    ) -> Device:
        with self.get_session() as session:
            dev = session.query(Device).filter(Device.id == device_id).first()
            if not dev:
                dev = Device(
                    id=device_id,
                    name=name,
                    device_type=device_type,
                    ip_address=ip_address,
                    mac_address=mac_address,
                    hardware=hardware,
                    threat_level=threat_level,
                    current_threat_score=current_threat_score,
                    confidence_level=confidence_level,
                    phase=phase,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow()
                )
                session.add(dev)
            else:
                dev.name = name
                dev.threat_level = threat_level
                dev.current_threat_score = current_threat_score
                dev.confidence_level = confidence_level
                dev.phase = phase
                dev.last_seen = datetime.utcnow()
            session.commit()
            session.refresh(dev)
            return dev

    def record_alert(
        self,
        device_id: str,
        device_name: str,
        threat_score: int,
        threat_level: str,
        confidence_level: str,
        likely_attack: str,
        details_json: str,
        plain_text_summary: str
    ) -> Alert:
        with self.get_session() as session:
            alert = Alert(
                device_id=device_id,
                device_name=device_name,
                threat_score=threat_score,
                threat_level=threat_level,
                confidence_level=confidence_level,
                likely_attack=likely_attack,
                details_json=details_json,
                plain_text_summary=plain_text_summary,
                timestamp=datetime.utcnow(),
                is_resolved=False
            )
            session.add(alert)
            session.commit()
            session.refresh(alert)
            return alert

    def get_all_devices(self) -> list[dict]:
        with self.get_session() as session:
            devices = session.query(Device).all()
            return [d.to_dict() for d in devices]

    def get_recent_alerts(self, limit: int = 50) -> list[dict]:
        with self.get_session() as session:
            alerts = session.query(Alert).order_by(Alert.id.desc()).limit(limit).all()
            return [a.to_dict() for a in alerts]

    def record_system_metric(
        self,
        cpu_usage_pct: float,
        ram_usage_mb: float,
        detection_latency_ms: float,
        enforcement_latency_ms: float,
        active_devices_count: int
    ) -> SystemMetric:
        with self.get_session() as session:
            metric = SystemMetric(
                timestamp=datetime.utcnow(),
                cpu_usage_pct=cpu_usage_pct,
                ram_usage_mb=ram_usage_mb,
                detection_latency_ms=detection_latency_ms,
                enforcement_latency_ms=enforcement_latency_ms,
                active_devices_count=active_devices_count
            )
            session.add(metric)
            session.commit()
            session.refresh(metric)
            return metric

    def get_recent_metrics(self, limit: int = 30) -> list[dict]:
        with self.get_session() as session:
            metrics = session.query(SystemMetric).order_by(SystemMetric.id.desc()).limit(limit).all()
            return [m.to_dict() for m in reversed(metrics)]
