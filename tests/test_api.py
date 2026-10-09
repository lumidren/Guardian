"""
Integration tests for FastAPI REST routes.
"""

import pytest
from fastapi.testclient import TestClient

from guardian.api.app import create_app


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


def test_api_status(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ONLINE"
    assert data["active_devices"] == 8


def test_api_list_devices(client):
    res = client.get("/api/devices")
    assert res.status_code == 200
    devices = res.json()
    assert len(devices) == 8


def test_api_override(client):
    res = client.post("/api/override", json={
        "device_id": "dev_01_temp",
        "requested_level": "RESTRICT",
        "note": "Test override"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["new_level"] == "RESTRICT"


def test_api_simulate_attack(client):
    res = client.post("/api/simulate-attack", json={
        "device_id": "dev_08_camera",
        "attack_type": "ZERO_DAY_HYBRID"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["attack_type"] == "ZERO_DAY_HYBRID"
    assert data["alert"] is not None
    assert data["alert"]["threat_score"] >= 80
