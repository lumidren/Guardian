"""
FastAPI REST routes for GUARDIAN Gateway.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Depends

from ..storage.database import DatabaseManager
from ..enforcement.controller import EnforcementController
from ..intelligence.cross_device import CrossDeviceThreatIntelligence
from simulation.fleet_emulator import DEFAULT_FLEET_SPECS
from simulation.attack_suite import AttackType


class OverrideRequest(BaseModel):
    device_id: str
    requested_level: str  # MONITOR, RESTRICT, QUARANTINE, BLOCK
    note: Optional[str] = "Manual user override from dashboard"


class SimulateAttackRequest(BaseModel):
    device_id: str
    attack_type: str  # DDOS_FLOODING, CNC_BEACONING, NETWORK_SCANNING, DATA_EXFILTRATION, CRYPTOMINING, ZERO_DAY_HYBRID


def get_router(
    db: DatabaseManager,
    enforcer: EnforcementController,
    intelligence: CrossDeviceThreatIntelligence,
    gateway_state: dict
) -> APIRouter:
    router = APIRouter(prefix="/api")

    @router.get("/status")
    async def get_status():
        return {
            "status": "ONLINE",
            "framework": "GUARDIAN v1.0.0",
            "active_devices": len(DEFAULT_FLEET_SPECS),
            "protection_mode": "ACTIVE_PROTECTION",
            "gateway_ip": "192.168.1.1"
        }

    @router.get("/devices")
    async def list_devices():
        devices = db.get_all_devices()
        # Merge live enforcement states
        for d in devices:
            enf_state = enforcer.get_state(d["id"])
            if enf_state:
                d["threat_level"] = enf_state.current_level.value
                d["current_threat_score"] = enf_state.threat_score
                d["is_isolated"] = enf_state.current_level.value in ("QUARANTINE", "BLOCK")
                d["enforcement_latency_ms"] = enf_state.enforcement_latency_ms
                d["is_overridden"] = enf_state.is_user_overridden
        return devices

    @router.get("/devices/{device_id}")
    async def get_device(device_id: str):
        devices = db.get_all_devices()
        dev = next((d for d in devices if d["id"] == device_id or d["ip_address"] == device_id), None)
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Add live telemetry and baseline info
        live_data = gateway_state.get("live_features", {}).get(dev["ip_address"], {})
        enf = enforcer.get_state(dev["id"])
        return {
            "device": dev,
            "live_features": live_data,
            "enforcement_state": enf.__dict__ if enf else None
        }

    @router.get("/alerts")
    async def list_alerts(limit: int = 50):
        return db.get_recent_alerts(limit=limit)

    @router.post("/override")
    async def set_override(req: OverrideRequest):
        enforcer.override_manager.request_override(
            device_id=req.device_id,
            new_level=req.requested_level,
            note=req.note
        )
        return {
            "success": True,
            "device_id": req.device_id,
            "new_level": req.requested_level,
            "message": f"Device {req.device_id} policy set to {req.requested_level} via user override."
        }

    @router.post("/simulate-attack")
    async def trigger_attack(req: SimulateAttackRequest):
        trigger_fn = gateway_state.get("attack_trigger_fn")
        if not trigger_fn:
            raise HTTPException(status_code=500, detail="Attack simulator handler not bound")

        try:
            attack_enum = AttackType[req.attack_type.upper()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid attack type: {req.attack_type}")

        alert_report = trigger_fn(req.device_id, attack_enum)
        return {
            "success": True,
            "attack_type": req.attack_type,
            "target_device": req.device_id,
            "alert": alert_report.to_dict() if alert_report else None
        }

    @router.get("/metrics")
    async def get_metrics():
        return db.get_recent_metrics(limit=30)

    @router.get("/intelligence")
    async def get_threat_intelligence():
        return intelligence.get_fleet_threat_summary()

    return router
