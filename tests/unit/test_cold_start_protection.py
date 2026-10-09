"""
Unit tests for Cold-Start Containment Protection (Milestone P2-7).
Verifies that during Stage 1 (Cold-Start Observation, Hours 0-24),
the device is actively protected by heuristic allowlists and rate limiting containment,
ensuring IoT devices are never left unprotected.
"""

import time

from guardian.config import SystemPhase, ThreatLevel
from guardian.enforcement.controller import EnforcementController
from guardian.ml.hybrid_startup import HybridStartupManager
from guardian.ml.threat_scorer import ThreatScorer


def test_cold_start_stage_provides_active_containment() -> None:
    startup = HybridStartupManager(cold_start_hours=24.0)
    device_id = "dev_cold_start_01"
    device_ip = "192.168.1.150"
    now = time.time()

    startup.register_device(device_id, connected_at=now)
    state = startup.get_phase(device_id, current_time=now + 3600.0)  # Hour 1
    assert state.current_phase == SystemPhase.COLD_START_OBSERVATION

    scorer = ThreatScorer()
    enforcer = EnforcementController()

    # 1. Benign in-profile traffic during cold start -> MONITOR (score <= 30)
    clean_features = {
        "new_dst_ip_flag": 0.0,
        "high_risk_port_flag": 0.0,
        "external_ip_ratio": 0.0,
        "pkt_rate_per_sec": 2.0,
    }
    assessment_clean = scorer.assess(
        ml_score=0.0,
        statistical_score=0.0,
        features=clean_features,
        is_cold_start=True,
    )
    assert assessment_clean.threat_score <= 30
    assert assessment_clean.threat_level == ThreatLevel.MONITOR

    # 2. Attack traffic during cold start (unauthorized external C2 beaconing)
    # Even without trained ML models, heuristic allowlist & rate tripwires trigger containment!
    attack_features = {
        "new_dst_ip_flag": 1.0,
        "high_risk_port_flag": 1.0,
        "external_ip_ratio": 1.0,
        "pkt_rate_per_sec": 50.0,
    }
    assessment_attack = scorer.assess(
        ml_score=0.0,  # ML is untrained
        statistical_score=0.8,  # Extreme rate deviation
        features=attack_features,
        is_cold_start=True,
    )

    # Must exceed restriction/quarantine threshold
    assert assessment_attack.threat_score >= 60
    assert assessment_attack.threat_level in (ThreatLevel.RESTRICT, ThreatLevel.QUARANTINE, ThreatLevel.BLOCK)

    # 3. Verify enforcement applies containment policy immediately
    enf_state = enforcer.enforce(device_id, device_ip, assessment_attack)
    assert enf_state.current_level in (ThreatLevel.RESTRICT, ThreatLevel.QUARANTINE, ThreatLevel.BLOCK)
