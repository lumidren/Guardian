"""
Main FastAPI Application for GUARDIAN Gateway.
Combines REST routes, WebSocket broadcaster, background monitoring loop, and static UI serving.
"""

import asyncio
import json
import time
from typing import Any

import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from simulation.attack_suite import AttackSuite, AttackType
from simulation.dataset_generator import BaselineDatasetGenerator
from simulation.fleet_emulator import DEFAULT_FLEET_SPECS, IoTDeviceSpec, IoTFleetEmulator

from ..capture.flow_tracker import FlowTracker
from ..config import config
from ..enforcement.controller import EnforcementController
from ..features.extractor import FeatureExtractor
from ..intelligence.cross_device import CrossDeviceThreatIntelligence
from ..ml.concept_drift import ConceptDriftDetector
from ..ml.hybrid_startup import HybridStartupManager
from ..ml.isolation_forest import IsolationForestDetector
from ..ml.statistical_baseline import DeviationDetail, StatisticalBaseline
from ..ml.threat_scorer import ThreatScorer
from ..storage.database import DatabaseManager
from ..xai.nlg_engine import ExplainableAlertReport, NLGEngine
from .routes import get_router
from .websockets import ws_manager


def create_app() -> FastAPI:
    app = FastAPI(
        title="GUARDIAN IoT Security Gateway",
        description="Multi-Layer Identity-Based Zero-Day Defense Framework for IoT",
        version="1.0.0"
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Core components
    db = DatabaseManager()
    enforcer = EnforcementController()
    intelligence = CrossDeviceThreatIntelligence()
    emulator = IoTFleetEmulator()
    extractor = FeatureExtractor()
    threat_scorer = ThreatScorer()
    nlg_engine = NLGEngine()
    _drift_detector = ConceptDriftDetector()
    startup_manager = HybridStartupManager()
    attack_suite = AttackSuite()

    # Shared runtime state
    models: dict[str, IsolationForestDetector] = {}
    baselines: dict[str, StatisticalBaseline] = {}
    trackers: dict[str, FlowTracker] = {}
    gateway_state: dict[str, Any] = {
        "live_features": {},
        "attack_trigger_fn": None,
        "is_running": True
    }

    # Initialize devices in DB and setup baseline models
    def initialize_fleet():
        for dev in DEFAULT_FLEET_SPECS:
            db.upsert_device(
                device_id=dev.id,
                name=dev.name,
                device_type=dev.device_type,
                ip_address=dev.ip_address,
                mac_address=dev.mac_address,
                hardware=dev.hardware,
                threat_level="MONITOR",
                current_threat_score=0,
                confidence_level="High (90-100%)",
                phase="ACTIVE_PROTECTION"
            )
            tracker = FlowTracker(window_size_seconds=10.0)
            for dest in dev.normal_destinations:
                tracker.register_known_destination(dev.ip_address, dest)
            trackers[dev.ip_address] = tracker
            startup_manager.register_device(dev.id)

        # Check if models exist, otherwise generate initial baseline dataset
        sample_model_file = config.MODELS_DIR / f"{DEFAULT_FLEET_SPECS[0].id}_iforest.json"
        if not sample_model_file.exists():
            print("[Gateway] No cached models found. Running baseline generator (40,000+ samples)...")
            gen = BaselineDatasetGenerator()
            gen.generate_and_train_all(total_target_samples=40000)

        # Load models into memory
        for dev in DEFAULT_FLEET_SPECS:
            m_path = config.MODELS_DIR / f"{dev.id}_iforest.json"
            if m_path.exists():
                models[dev.ip_address] = IsolationForestDetector.load(m_path)

            b_path = config.DATA_DIR / f"{dev.id}_baseline.json"
            if b_path.exists():
                with open(b_path, encoding="utf-8") as f:
                    b_data = json.load(f)
                    stat_b = StatisticalBaseline()
                    stat_b.means = b_data.get("means", {})
                    stat_b.stds = b_data.get("stds", {})
                    stat_b.is_ready = True
                    baselines[dev.ip_address] = stat_b

    initialize_fleet()

    # Real-time analysis logic for a single device window
    def analyze_window(dev: IoTDeviceSpec, packets: list) -> ExplainableAlertReport | None:
        t_detect_start = time.perf_counter()
        tracker = trackers.get(dev.ip_address)
        if not tracker:
            return None

        for p in packets:
            tracker.ingest_packet(p)

        summary = tracker.get_window_summary(dev.ip_address)
        if not summary:
            return None

        features = extractor.extract(summary)
        vec = extractor.extract_vector(summary)
        gateway_state["live_features"][dev.ip_address] = features

        model = models.get(dev.ip_address)
        stat_b = baselines.get(dev.ip_address)

        ml_score = 0.0
        ml_attribution: dict[str, float] = {}
        if model and model.is_trained:
            ml_score, ml_attribution = model.score_sample(vec)

        stat_score = 0.0
        stat_deviations: list[DeviationDetail] = []
        if stat_b and stat_b.is_ready:
            stat_score, stat_deviations = stat_b.evaluate(features)

        # Threat Assessment
        assessment = threat_scorer.assess(
            ml_score=ml_score,
            statistical_score=stat_score,
            features=features
        )

        _detect_latency_ms = (time.perf_counter() - t_detect_start) * 1000.0

        # Enforce policy via Graduated Response Controller
        enf_state = enforcer.enforce(
            device_id=dev.id,
            ip_address=dev.ip_address,
            assessment=assessment
        )

        # Update DB record
        db.upsert_device(
            device_id=dev.id,
            name=dev.name,
            device_type=dev.device_type,
            ip_address=dev.ip_address,
            mac_address=dev.mac_address,
            hardware=dev.hardware,
            threat_level=enf_state.current_level.value,
            current_threat_score=assessment.threat_score,
            confidence_level=assessment.confidence_level
        )

        # Generate Explainable Alert Report if threat score exceeds RESTRICT (>30)
        report = None
        if assessment.threat_score >= config.THREAT_THRESHOLD_RESTRICT:
            base_means = stat_b.means if stat_b else {}
            report = nlg_engine.generate_report(
                device_id=dev.id,
                device_name=dev.name,
                assessment=assessment,
                features=features,
                baseline_means=base_means,
                ml_attribution=ml_attribution,
                statistical_deviations=stat_deviations
            )
            # Persist alert
            db.record_alert(
                device_id=dev.id,
                device_name=dev.name,
                threat_score=assessment.threat_score,
                threat_level=enf_state.current_level.value,
                confidence_level=assessment.confidence_level,
                likely_attack=report.likely_attack,
                details_json=json.dumps(report.why_blocked_bullet_points),
                plain_text_summary=report.plain_text_summary
            )
            # Propagate to Cross-Device Threat Intelligence
            external_destinations = [p.dst_ip for p in packets if not p.dst_ip.startswith("192.168.1.")]
            external_ports = [p.dst_port for p in packets if p.dst_port > 0]
            intelligence.broadcast_attack(
                source_device_id=dev.id,
                dest_ips=external_destinations,
                dest_ports=external_ports,
                attack_category=report.likely_attack,
                threat_score=assessment.threat_score
            )

        return report

    # Attack trigger handler for on-demand demonstration
    def trigger_attack_handler(device_id: str, attack_type: AttackType) -> ExplainableAlertReport | None:
        dev = next((d for d in DEFAULT_FLEET_SPECS if d.id == device_id or d.ip_address == device_id), None)
        if not dev:
            return None
        attack_pkts = attack_suite.inject_attack(attack_type=attack_type, victim_device=dev)
        report = analyze_window(dev, attack_pkts)
        return report

    gateway_state["attack_trigger_fn"] = trigger_attack_handler

    # Mount REST routes
    app.include_router(get_router(db, enforcer, intelligence, gateway_state))

    # WebSocket telemetry stream
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await ws_manager.connect(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)

    # Background Telemetry & Normal Traffic Generation Task
    @app.on_event("startup")
    async def startup_event():
        async def telemetry_loop():
            while gateway_state["is_running"]:
                t_loop_start = time.perf_counter()
                now = time.time()

                # Generate normal traffic for devices
                for dev in DEFAULT_FLEET_SPECS:
                    pkts = emulator.generate_normal_window_packets(device=dev, current_time=now)
                    analyze_window(dev, pkts)

                loop_duration_ms = (time.perf_counter() - t_loop_start) * 1000.0

                # Record hardware metrics (CPU, RAM, Latency)
                cpu_pct = psutil.cpu_percent()
                ram_mb = psutil.virtual_memory().used / (1024 * 1024)
                db.record_system_metric(
                    cpu_usage_pct=cpu_pct,
                    ram_usage_mb=ram_mb,
                    detection_latency_ms=round(loop_duration_ms / len(DEFAULT_FLEET_SPECS), 2),
                    enforcement_latency_ms=0.25,
                    active_devices_count=len(DEFAULT_FLEET_SPECS)
                )

                # Broadcast live telemetry over WebSocket
                devices = db.get_all_devices()
                alerts = db.get_recent_alerts(limit=5)
                await ws_manager.broadcast({
                    "type": "TELEMETRY_UPDATE",
                    "timestamp": now,
                    "devices": devices,
                    "recent_alerts": alerts,
                    "system": {
                        "cpu_pct": cpu_pct,
                        "ram_mb": round(ram_mb, 1),
                        "avg_detection_latency_ms": round(loop_duration_ms / len(DEFAULT_FLEET_SPECS), 2),
                        "enforcement_latency_ms": 0.25,
                    }
                })

                await asyncio.sleep(2.0)

        asyncio.create_task(telemetry_loop())

    # Serve static dashboard UI
    dashboard_dir = config.BASE_DIR / "dashboard"
    if dashboard_dir.exists():
        app.mount("/", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard")

    return app
