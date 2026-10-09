"""
Unit tests for GUARDIAN FastAPI routes and WebSocket connection manager.
"""

from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from guardian.api.routes import get_router
from guardian.api.websockets import ConnectionManager
from guardian.enforcement.controller import EnforcementController
from guardian.intelligence.cross_device import CrossDeviceThreatIntelligence
from guardian.storage.database import DatabaseManager


@pytest.fixture
def test_app(tmp_path: Path) -> TestClient:
    db = DatabaseManager(db_path=tmp_path / "test_api.db")
    db.upsert_device(
        device_id="DEV-001",
        name="Test Sensor",
        device_type="Sensor",
        ip_address="192.168.1.10",
        mac_address="00:11:22:33:44:55",
        hardware="ESP32",
    )
    enforcer = EnforcementController()
    intelligence = CrossDeviceThreatIntelligence()
    gateway_state: dict[str, Any] = {
        "live_features": {"192.168.1.10": {"pkt_rate": 2.5}},
        "attack_trigger_fn": None,
        "is_running": False,
    }

    app = FastAPI()
    app.include_router(get_router(db, enforcer, intelligence, gateway_state))
    return TestClient(app)


def test_api_status(test_app: TestClient) -> None:
    resp = test_app.get("/api/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ONLINE"
    assert "active_devices" in data
    assert data["gateway_ip"] == "192.168.1.1"


def test_api_devices(test_app: TestClient) -> None:
    resp = test_app.get("/api/devices")
    assert resp.status_code == 200
    devices = resp.json()
    assert len(devices) >= 1
    assert devices[0]["id"] == "DEV-001"


def test_api_device_detail(test_app: TestClient) -> None:
    resp = test_app.get("/api/devices/DEV-001")
    assert resp.status_code == 200
    data = resp.json()
    assert data["device"]["name"] == "Test Sensor"
    assert "live_features" in data

    resp_404 = test_app.get("/api/devices/NON_EXISTENT")
    assert resp_404.status_code == 404


def test_api_alerts_and_metrics(test_app: TestClient) -> None:
    resp_alerts = test_app.get("/api/alerts")
    assert resp_alerts.status_code == 200
    assert isinstance(resp_alerts.json(), list)

    resp_metrics = test_app.get("/api/metrics")
    assert resp_metrics.status_code == 200
    assert isinstance(resp_metrics.json(), list)


def test_api_threat_intelligence(test_app: TestClient) -> None:
    resp = test_app.get("/api/intelligence")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_shared_indicators" in data
    assert "blacklisted_ips" in data


def test_api_override(test_app: TestClient) -> None:
    resp = test_app.post(
        "/api/override",
        json={
            "device_id": "DEV-001",
            "requested_level": "RESTRICT",
            "note": "Operator manual restrict",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["new_level"] == "RESTRICT"


def test_api_simulate_attack_invalid(test_app: TestClient) -> None:
    resp = test_app.post(
        "/api/simulate-attack",
        json={
            "device_id": "DEV-001",
            "attack_type": "NON_EXISTENT_ATTACK",
        },
    )
    # Simulator function not bound or invalid attack type
    assert resp.status_code in (400, 500)


@pytest.mark.asyncio
async def test_websocket_manager() -> None:
    mgr = ConnectionManager()
    assert len(mgr.active_connections) == 0
    # Broadcast with no connections should complete gracefully
    await mgr.broadcast({"test": "value"})
