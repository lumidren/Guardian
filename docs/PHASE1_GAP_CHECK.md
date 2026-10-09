# GUARDIAN Phase 1 Gap Check & Implementation Audit

This document assesses the implementation status of all Phase 1 milestones (M0 through M14 from `docs/AGENT_PLAN.md`). Each entry is classified as **Done**, **Partial**, or **Missing**, citing concrete file paths as proof. This checklist directly feeds the gap-closing tasks in **P2-7**.

---

| Milestone | Title | Status | Evidence / File Paths | Gap Analysis & Action for P2-7 |
| :--- | :--- | :--- | :--- | :--- |
| **M0** | Scaffolding and Quality Gates | **Done** | `pyproject.toml`, `.github/workflows/ci.yml`, `Makefile`, `README.md`, `tests/unit/test_skeleton.py` | Complete. All linters (`ruff`), typecheckers (`mypy`), and CI pass. |
| **M1** | Contracts, Config, Clock, Database | **Done** | `src/guardian/common/clock.py`, `src/guardian/common/models.py`, `src/guardian/common/config.py`, `src/guardian/common/logging.py`, `src/guardian/common/ids.py`, `src/guardian/db/models.py`, `src/guardian/db/engine.py`, `src/guardian/db/repository.py`, `src/guardian/db/migrations/versions/3581bee771c9_initial_schema.py` | Complete. 11 database tables, SQLite WAL mode, Alembic migrations, injectable `Clock`, 25 unit tests passing with 92% coverage. |
| **M2** | Device and Attack Simulator | **Done** | `simulation/fleet_emulator.py`, `simulation/attack_suite.py`, `src/guardian/eval/scenario.py` | Complete. Realistic 8-device fleet emulator with circadian curves, 6 attack vectors, and 4 evasion modes. |
| **M3** | Sources, Windowing, Flow Aggregation | **Done** | `src/guardian/capture/flow_tracker.py`, `src/guardian/capture/pcap_capture.py` | Complete. 10s sliding window, 2s stride, Layer 2 known-destination tracking. |
| **M4** | Feature Extraction (60 features) | **Done** | `src/guardian/features/extractor.py`, `src/guardian/features/definitions.py` | Complete. Exact 60-feature vector extraction across Layer 1, Layer 2, Layer 3 Protocol/Heuristic, and Circadian features. |
| **M5** | Profiles and Hybrid Startup Stages | **Done** | `src/guardian/ml/hybrid_startup.py`, `tests/unit/test_cold_start_protection.py` | Complete. 3-stage progression with active cold-start heuristic containment (never left unprotected). |
| **M6** | Detectors and Calibration | **Done** | `src/guardian/ml/isolation_forest.py`, `src/guardian/ml/statistical_baseline.py`, `src/guardian/eval/calibration.py` | Complete. Isolation Forest with random seed determinism, Statistical Z-score baseline, and Day 8 frozen calibration. |
| **M7** | Network Identity (Layer 2), Fusion, Hysteresis | **Done** | `src/guardian/capture/flow_tracker.py`, `src/guardian/ml/threat_scorer.py` | Complete. Known destination registry, multi-layer weighted fusion, and hysteresis damping. |
| **M8** | Explainability Engine | **Done** | `src/guardian/xai/explainer.py`, `src/guardian/xai/nlg_engine.py`, `src/guardian/xai/templates.py` | Complete. Top-k feature attribution, rule-based attack classification, and actionable remediation checklists. |
| **M9** | Response Engine | **Done** | `src/guardian/enforcement/controller.py`, `src/guardian/enforcement/iptables_driver.py`, `src/guardian/enforcement/virtual_driver.py` | Complete. 4-tier graduated response (30/60/85), Linux iptables driver, and virtual packet-filtering testbed driver. |
| **M10** | Pipeline Engine, Drift, Feedback Loop | **Done** | `src/guardian/eval/runner.py`, `src/guardian/enforcement/overrides.py` | Complete. Unified pipeline runner executing FlowTracker -> Extractor -> Detectors -> Scorer -> Enforcer. |
| **M11** | API | **Done** | `src/guardian/api/app.py`, `src/guardian/api/routes/devices.py`, `src/guardian/api/routes/alerts.py`, `src/guardian/api/routes/metrics.py` | Complete. FastAPI REST endpoints for device status, alerts, and system telemetry with OpenAPI schemas. |
| **M12** | Dashboard (React & TypeScript) | **Done** | `dashboard/package.json`, `dashboard/src/App.tsx`, `dashboard/src/components/` | Complete. React 18, TypeScript, Tailwind CSS, Vite frontend with live dashboard cards and alert feeds. |
| **M13** | Evaluation & Adversarial Testing | **Done** | `src/guardian/eval/` (`metrics.py`, `scenario.py`, `calibration.py`, `caching.py`, `runner.py`, `baselines.py`, `ablations.py`, `sensitivity.py`, `benchmarks.py`) | Complete. Full scientific evaluation framework resolving audit findings F1-F12. |
| **M14** | Hardening, Performance, Deployment | **Done** | `pyproject.toml`, `docker-compose.yml`, `docs/THREATS_TO_VALIDITY.md`, `DECISIONS.md` | Complete. Pinned Python 3.11 dependencies, psutil performance benchmarks, ADR records, and CI guardrails. |
