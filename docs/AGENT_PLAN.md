# GUARDIAN Software Build Plan (AI Agent Spec)

By Mustafa (lumidren). Software only: every hardware part is replaced by simulators,
replay and adapters. Source: GUARDIAN Executive Summary, April 22, 2026.

## 0. How to use this document
1. Save this file in the repo as `docs/AGENT_PLAN.md`.
2. Paste the Master Prompt (section 1) as the agent's first message.
3. Tell the agent to re-read this file at the start of every milestone and to finish milestones in order.
4. Review at the end of each milestone. Do not let the agent skip ahead.

## 1. Master prompt (paste this)
You are the lead engineer building GUARDIAN: a per-device behavioral anomaly detection
and graduated-response system for IoT networks, with natural-language explanations.
Read `docs/AGENT_PLAN.md` fully before writing code. Build only the software. There is
no hardware: use the simulator, pcap replay and adapter interfaces defined in the plan.
Work milestone by milestone (M0 to M14). For each task: write the tests first when a
contract is involved, implement, run lint, type check and tests, then make exactly one
commit for that single edit or update, following the commit rule in section 2 (one edit, one
commit, no batching, no squashing). Keep `PROGRESS.md` (what is done, what is next) and
`DECISIONS.md` (every choice not already fixed by the plan, with the reason) updated.
Never invent results. Every metric in the paper assets must come from the evaluation
harness. If something in the plan is ambiguous or blocked, pick the safest default, record
it in `DECISIONS.md` and continue; ask me only if the choice changes scope or cost. Stop
after each milestone and report: what was built, test results, known gaps.

## 2. Ground rules for the agent
- **Honesty of numbers.** The PDF lists 87% detection, <5% false positives, <1s response as targets. They are not results. The agent must measure everything and report what it gets, even if lower. Never hardcode a metric, never tune on the test split.
- **Determinism.** Every random process takes a seed. Same seed gives the same dataset, same model, same metrics.
- **Injectable time.** No code calls `time.time()` or `datetime.now()` directly. Use a `Clock` interface (real clock, simulated clock). This is what lets the evaluation run days of traffic in minutes.
- **Safe by default.** Enforcement defaults to dry-run. Nothing touches firewall rules unless enforce mode is switched on explicitly and the process runs on Linux as root.
- **Attack code stays synthetic.** Attack generators only emit synthetic packet records inside the simulator. No real exploit code, no scanning of real networks.
- **Small, typed, tested.** Python type hints everywhere, mypy strict on core packages, ruff clean, pytest green before any commit.
- **One source of truth for config.** All thresholds, windows, weights and durations live in `config/guardian.yaml` and are loaded into one pydantic settings object. No magic numbers in code.
- **No new dependency without a line in `DECISIONS.md`.** Pin versions in lockfiles.
- **Privacy.** 100% local processing. No outbound network calls at runtime, no telemetry.
- **One edit, one commit.** Every single edit or update gets its own commit, made right after that change passes lint, type check and the relevant tests. Never batch several edits into one commit and never leave edits uncommitted while starting the next one.
  - A test and the code that satisfies it are two edits, so two commits (test first, then implementation).
  - Updates to `PROGRESS.md`, `DECISIONS.md`, config, docs, dependency pins and generated files are edits too, each with its own commit.
  - One edit that spans several files because the files only make sense together (for example a model and its migration) is still one commit.
  - A fix for an earlier mistake is a new commit. Never amend, squash, rebase away or force-push history.
  - Message format: Conventional Commits, for example `feat(features): add iat_cv extractor`, `test(features): add iat_cv fixture`, `fix(windowing): handle late packets`, `docs(decisions): record FastAPI choice`. Subject under 72 characters, a short body when the reason is not obvious, and the milestone tag in the body (for example `Milestone: M4`).
  - Before committing, run git status and confirm that only the files for that one edit are staged.

## 3. Decisions made for you (the PDF contradicts itself)
The agent must follow these. They fix inconsistencies in the source document.

| Topic | Problem in the PDF | Decision |
| :--- | :--- | :--- |
| **Response levels** | Section 3.4 says 0-30 / 31-60 / 61-85 / 86-100. Section 6.6 uses 30-50 / 51-70 / 71-85 / 86-100. | Use 3.4: MONITOR 0-30, RESTRICT 31-60, QUARANTINE 61-85, BLOCK 86-100. Configurable. |
| **Sample count** | 40,000 samples in 24-48h with 10-second windows gives only about 8,600-17,300 samples. | Window length 10s, stride 2s (sliding). That gives 43,200 samples per day per device. Document that overlapping windows are correlated and split train/test by time, never randomly. |
| **Latency claims** | 'Detected in under 1s' vs 'stopped in about 6 seconds' vs a 10s window. | Define and measure three numbers: window-close to score (compute latency), attack-start to first alert (time-to-detect), alert to rule applied (enforcement latency). Report all three honestly. |
| **API framework** | PDF says Flask. | Use FastAPI (async, WebSocket, auto OpenAPI, pydantic). Record in `DECISIONS.md`. |
| **Firewall** | PDF says iptables. | Use nftables with a dedicated table, behind an interface that also supports iptables. |
| **Z-score fallback** | Flagging any feature past 2.5 std over 60 features will fire constantly. | Use robust z (median and MAD) and flag on an aggregate of several features, not a single one. |
| **Physical layer** | Layer 3 is optional and hardware based. | Out of scope. Provide an empty `PhysicalIdentityProvider` interface and document it as future work. |
| **Baseline comparisons** | PDF table lists Snort numbers. | Do not fake Snort. Baselines are: static-threshold rules, global (pooled) Isolation Forest, z-score only. |
| **Geolocation** | Alerts show 'Moscow, Russia' but there is no cloud. | Optional offline GeoLite2 database behind an interface. Fallback text: 'external address, location unknown'. |
| **Stats in the PDF** | Robot vacuum incident, 75B devices, 80% encrypted and similar figures. | Not the agent's job to verify. Mustafa must verify and cite sources before using them in the paper. |

## 4. Scope

### In scope
- Packet and flow ingestion through a source abstraction (live sniffer, pcap replay, simulator)
- Device simulator for all 8 device types plus 6 attack types (synthetic)
- Feature extraction (60 features per window)
- Per-device profiles with hybrid startup (rules, statistics, then ML)
- Isolation Forest, robust z-score detector, fusion into a 0-100 threat score with confidence
- Layer 1 behavioral identity and Layer 2 network identity
- Explainability engine (template language, feature attribution, likely-attack label, recommendations)
- Graduated response with nftables backend, dry-run backend and simulator backend
- Concept drift handling and user feedback loop
- Cross-device threat intelligence and feature importance analysis
- Adversarial testing (mimicry, low-and-slow, time-delayed)
- FastAPI backend, WebSocket events, React dashboard with a demo mode
- Evaluation harness that produces every table and figure for the IEEE paper
- Docker Compose and Raspberry Pi deployment files

### Out of scope
Firmware for ESP32/ESP8266/Pi Zero/ESP32-CAM, wiring, physical identity (clock skew, RF), federated learning, user study, cloud features.

**Hardware adapter contract:** When the hardware person has devices running, the only thing that changes is the packet source: `LiveSnifferSource` replaces `SimulatorSource` through config. Nothing else in the codebase may care where packets come from.

## 5. Tech stack

| Layer | Choice |
| :--- | :--- |
| **Language** | Python 3.11/3.12 (backend, ML, simulator, eval), TypeScript (dashboard) |
| **Packet capture** | scapy (`AsyncSniffer`) for live, dpkt or scapy for pcap parsing |
| **Data** | numpy, pandas, scipy |
| **ML** | scikit-learn (`IsolationForest`), joblib for model files, shap (`TreeExplainer`) for attribution cross-check |
| **Graph** | networkx |
| **API** | FastAPI, uvicorn, pydantic v2, SQLAlchemy 2, Alembic |
| **Storage** | SQLite (WAL mode) |
| **MQTT (demo mode only)** | paho-mqtt client, Mosquitto broker in Docker |
| **Dashboard** | React 18, Vite, TypeScript, Tailwind, Recharts, TanStack Query |
| **Types shared with UI** | openapi-typescript generated from the FastAPI OpenAPI schema |
| **Quality** | pytest, hypothesis, pytest-cov, ruff, mypy, pre-commit, GitHub Actions |
| **Logging** | structlog (JSON) |
| **Packaging** | uv or poetry with lockfile, Docker, docker compose, systemd unit for the Pi |
| **Eval plots** | matplotlib, seaborn; tables exported as CSV and LaTeX |

## 6. Repository layout

```
guardian/
README.md PROGRESS.md DECISIONS.md Makefile docker-compose.yml
config/guardian.yaml config/device_types.yaml config/attacks.yaml
docs/AGENT_PLAN.md docs/architecture.md docs/runbook.md
src/guardian/
  common/       clock.py config.py models.py ids.py logging.py
  sources/      base.py live_sniffer.py pcap_replay.py simulator_source.py
  simulator/    devices.py traffic_models.py attacks.py scenario.py mqtt_demo.py
  flows/        windowing.py aggregator.py
  features/     registry.py volume.py timing.py protocol.py network.py temporal.py mqtt_meta.py
  profiles/     store.py baseline.py stages.py drift.py priors.py
  detection/    robust_z.py iforest.py network_identity.py fusion.py hysteresis.py calibration.py
  explain/      attribution.py findings.py templates.py attack_label.py geo.py
  response/     levels.py controller.py backends/(base,dryrun,nftables,sim).py
  intel/        bus.py watchlist.py
  identity/     physical.py (interface stub only)
  pipeline/     engine.py scheduler.py
  api/          main.py routes/ schemas.py ws.py auth.py
  db/           models.py migrations/
  eval/         datasets.py splits.py metrics.py baselines.py ablations.py adversarial.py report.py
dashboard/      (Vite React app)
tests/          unit/ integration/ e2e/ perf/ golden/
deploy/         Dockerfile.backend Dockerfile.dashboard guardian.service nftables.conf.example
```

## 7. Architecture and data contracts

### 7.1 Data flow
`PacketSource` -> `PacketRecord` stream -> `FlowAggregator` (per device, sliding window 10s, stride 2s) -> `FeatureExtractor` (60 features) -> `Pipeline.engine` -> detectors (robust z, Isolation Forest, network identity) -> `Fusion` -> `Hysteresis` -> `Explainer` -> `ResponseController` -> backend. Everything is persisted to SQLite and pushed to the dashboard over WebSocket.

### 7.2 Core models (pydantic, in `common/models.py`)
- `PacketRecord`: `ts` (float, from `Clock`), `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto` (tcp, udp, icmp, other), `length`, `tcp_flags`, `direction` (out or in, relative to the device), `app_proto` (mqtt, http, tls, dns, ntp, other), `mqtt_topic` (optional), `payload_len`, `device_id`.
- `Device`: `device_id`, `name`, `type` (esp32_sensor, esp8266_actuator, pi_zero, esp32_cam), `ip`, `mac`, `stage` (observe, rules, statistical, ml), `first_seen`, `mode` (observe or enforce).
- `WindowFeatures`: `device_id`, `window_start`, `window_end`, `vector` (array of 60 floats in registry order), `feature_names`, `n_packets`, `quality_flags` (for example `sparse_window`).
- `Detection`: `device_id`, `window_end`, `ml_score` (0-100), `stat_score` (0-100), `net_score` (0-100), `threat_score` (0-100), `confidence` (0-1), `level`, `top_features` (list of name, value, expected, robust_z, direction), `triggers` (list of rule names).
- `Alert`: `alert_id`, `device_id`, `opened_at`, `closed_at`, `peak_score`, `level`, `explanation` (structured), `explanation_text`, `likely_attack` (label and confidence), `recommended_actions`, `status` (open, acknowledged, false_positive, resolved).
- `ResponseAction`: `action_id`, `device_id`, `level`, `backend`, `rules_applied`, `applied_at`, `expires_at`, `reverted_at`, `reason`, `overridden_by`.

### 7.3 Interfaces (abstract base classes, all swappable and mockable)
- `Clock`: `now()`, `sleep_until(ts)`. Implementations: `RealClock`, `SimClock` (advances only when the source emits).
- `PacketSource`: `__iter__` or async iterator yielding `PacketRecord`. Implementations: `LiveSnifferSource`, `PcapReplaySource` (with speed factor), `SimulatorSource`.
- `Detector`: `fit(X)`, `score(x) -> float 0..100`, `save(path)`, `load(path)`.
- `EnforcementBackend`: `apply(device, level)`, `revert(device)`, `status()`. Implementations: `DryRunBackend`, `NftablesBackend`, `SimBackend`.
- `GeoProvider`: `lookup(ip) -> GeoInfo or None`.
- `PhysicalIdentityProvider`: `score(device) -> None` (stub).

### 7.4 Database tables
`devices`, `windows` (features, retained N days then compacted), `profiles` (versioned JSON), `models` (path, sha256, trained_at, train_range, metrics), `detections`, `alerts`, `actions`, `feedback`, `drift_events`, `destinations` (`device_id`, `dst_ip`, `port`, `first_seen`, `last_seen`, `count`, status: known, pending, trusted, watched), `settings`. Use Alembic migrations from day one.

### 7.5 The 60 features (fixed registry, order matters)
Define them once in `features/registry.py` with name, group, unit, human label, and a flag saying whether higher or lower is suspicious.

| Group (count) | Features |
| :--- | :--- |
| **Volume (12)** | `pkts_out`, `pkts_in`, `bytes_out`, `bytes_in`, `pkt_rate`, `byte_rate`, `mean_pkt_size_out`, `mean_pkt_size_in`, `std_pkt_size`, `max_pkt_size`, `out_in_ratio`, `burst_count` |
| **Timing (10)** | `iat_mean`, `iat_std`, `iat_min`, `iat_max`, `iat_median`, `iat_cv`, `periodicity_score` (autocorrelation peak), `idle_fraction`, `flow_duration_mean`, `beacon_regularity` |
| **Protocol (12)** | `frac_mqtt`, `frac_http`, `frac_tls`, `frac_dns`, `frac_ntp`, `frac_other`, `frac_tcp`, `frac_udp`, `frac_icmp`, `syn_count`, `rst_count`, `syn_ack_ratio` |
| **Network (14)** | `n_unique_dst_ip`, `n_unique_dst_port`, `n_new_dst_ip`, `n_new_dst_port`, `frac_external`, `frac_local`, `n_new_flows`, `n_failed_conns`, `dst_entropy`, `port_entropy`, `n_unique_src_ports`, `dns_unique_domains`, `fan_out`, `conn_rate` |
| **Temporal (6)** | `hour_sin`, `hour_cos`, `dow_sin`, `dow_cos`, `in_active_hours`, `secs_since_last_activity` |
| **MQTT and payload metadata (6)** | `mqtt_topic_count`, `mqtt_new_topic`, `mqtt_msg_rate`, `mqtt_payload_len_mean`, `payload_len_entropy`, `tls_present` |

## 8. Milestones
- **M0. Scaffolding and quality gates**
- **M1. Contracts, config, clock, database**
- **M2. Device and attack simulator (replaces hardware)**
- **M3. Sources, windowing and flow aggregation**
- **M4. Feature extraction (60 features)**
- **M5. Profiles and hybrid startup**
- **M6. Detectors and calibration**
- **M7. Network identity (Layer 2), fusion and hysteresis**
- **M8. Explainability engine**
- **M9. Response engine**
- **M10. Pipeline engine, drift and feedback loop**
- **M11. API**
- **M12. Dashboard (React and TypeScript)**
- **M13. Evaluation, adversarial testing and enhancements**
- **M14. Hardening, performance, deployment, documentation**

## 9. Evaluation protocol (what makes the paper credible)
- Data generation: simulate at least 14 days of normal traffic per device with several random seeds (at least 5). Splits by time: days 1-7 train (baseline and model), day 8 calibration, days 9-14 test with injected attacks. Never shuffle windows.
- Attack schedule in test period: each of the 6 attack types, on each applicable device type, at 3 intensities, with random start times, durations from 1 to 30 minutes, repeated across seeds.
- Metrics: Episode-level detection rate, Window-level TPR/FPR/Precision/Recall/F1/ROC-AUC/PR-AUC, False alerts per device per day after hysteresis, Time-to-detect (median, p95), compute latency, enforcement latency.
- Baselines and ablations: Static-threshold rules, Global Isolation Forest, Robust z-score only, Isolation Forest only, Layer 1 only, Layer 2 only, with/without hysteresis, with/without cross-device intelligence, with/without calibration.
- Adversarial tests: mimicry, low-and-slow, delayed start, adaptive attacker.

## 10. Quality gates (global definition of done)
- Lint, type check and unit tests pass in CI; coverage at least 85% on `features`, `detection`, `explain`, `response`, `profiles`.
- No TODO or FIXME left in core packages without an entry in `PROGRESS.md`.
- Reproducibility: `make eval` with committed seed list recreates paper tables exactly.
- Latency budget measured, not assumed: compute latency under 100ms for 8 devices on Pi-limited container.
- Every public function has a docstring; every config key is documented.
- Demo script (`make demo`) runs scripted 5-minute story.
- Git history check: every commit contains one logical edit, follows Conventional Commits.

## Appendix A. Config skeleton (`config/guardian.yaml`)
```yaml
window: {length_s: 10, stride_s: 2}
stages: {rules_hours: 24, statistical_hours: 24, ml_min_samples: 20000}
detection:
  robust_z: {threshold: 3.5, clip: 20, top_k: 5}
  iforest: {n_estimators: 200, max_samples: auto, seed: 42, holdout_fraction: 0.2}
  fusion_weights: {ml: 0.5, stat: 0.3, net: 0.2}
  hysteresis: {k: 2, n: 3, calm_windows: 15}
levels: {monitor_max: 30, restrict_max: 60, quarantine_max: 85}
response:
  mode: observe
  backend: dryrun
  ttl_s: {restrict: 900, quarantine: 3600, block: null}
  protected_addresses: []
network_identity: {known_after_windows: 20, known_after_hours: 2}
drift: {check_every_h: 168, auto_pct: 10, ask_pct: 30}
source: {type: simulator, scenario: scenarios/default.yaml, speed: fast}
api: {host: 127.0.0.1, port: 8000, demo_mode: false}
geo: {provider: null, db_path: null}
```

## Appendix B. Milestone checklist for `PROGRESS.md`
- [ ] M0 scaffolding
- [ ] M1 contracts and DB
- [ ] M2 simulator
- [ ] M3 sources and windows
- [ ] M4 features
- [ ] M5 profiles and stages
- [ ] M6 detectors
- [ ] M7 network identity and fusion
- [ ] M8 explainability
- [ ] M9 response
- [ ] M10 pipeline, drift, feedback
- [ ] M11 API
- [ ] M12 dashboard
- [ ] M13 evaluation and enhancements
- [ ] M14 hardening and docs

## Appendix C. Report template the agent sends after each milestone
1. What was built (files and modules)
2. How to run the demo for this milestone
3. Test, lint and type results (numbers)
4. Measured performance or metrics, if any
5. Decisions added to DECISIONS.md
6. Known gaps and what the next milestone needs from me
