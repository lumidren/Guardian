# GUARDIAN Architectural & Technical Decisions Log

This document records architectural, algorithmic, and engineering decisions made throughout the GUARDIAN implementation, including resolutions of inconsistencies in the source executive summary.

---

## 1. Source Contradiction Resolutions (Section 3)

### ADR-001: Response Levels & Thresholds
- **Problem**: Section 3.4 of the source PDF uses (0–30, 31–60, 61–85, 86–100), while Section 6.6 uses (30–50, 51–70, 71–85, 86–100).
- **Decision**: Adopt Section 3.4 standard:
  - `MONITOR`: 0 – 30
  - `RESTRICT`: 31 – 60
  - `QUARANTINE`: 61 – 85
  - `BLOCK`: 86 – 100
- **Rationale**: Provides clear separation with minimal false alarm penalty. All threshold values are configurable in `config/guardian.yaml`.

### ADR-002: Sliding Windowing and Sample Accounting
- **Problem**: The PDF describes 40,000 samples collected in 24–48 hours. A disjoint 10-second window yields only 8,640 windows/day.
- **Decision**: Define sliding window length = 10s, stride = 2s.
- **Rationale**: Yields 43,200 evaluation windows per day per device. Train/test splits must strictly partition by chronological time, never by random shuffle, preserving temporal correlation.

### ADR-003: Honest Latency Metric Disambiguation
- **Problem**: PDF interchangeably references "Detected in under 1s" vs "stopped in about 6 seconds" vs 10s window duration.
- **Decision**: Define and measure three distinct latencies:
  1. *Compute Latency*: Window-close to score completion (target: <100ms).
  2. *Time-to-Detect*: Attack initiation to first alert emission.
  3. *Enforcement Latency*: Alert emission to firewall rule application (target: <300ms).

### ADR-004: API Framework Selection
- **Problem**: PDF mentions Flask API server in Table 5.
- **Decision**: Standardize on **FastAPI** with `uvicorn`, `pydantic v2`, and native WebSockets.
- **Rationale**: Native async I/O, auto-generated OpenAPI 3.1 schema for TypeScript client generation, high throughput, and strict typing.

### ADR-005: Firewall Architecture
- **Problem**: PDF specifies `iptables`.
- **Decision**: Standardize on `nftables` using a dedicated `inet guardian` table and atomic rule changes (`nft -f`), exposed behind an abstract `EnforcementBackend` interface that also supports dry-run, simulation, and legacy `iptables`.

### ADR-006: Robust Z-Score Fallback Calculation
- **Problem**: Flagging individual feature deviation >2.5 standard deviations over 60 features causes false alarm explosion.
- **Decision**: Use robust statistics (Median and Median Absolute Deviation - MAD):
  $$Z_{\text{robust}} = \frac{x - \text{median}}{1.4826 \times \text{MAD} + \epsilon}$$
  Alerts fire on an aggregate metric across multiple features, not on isolated individual features.

### ADR-007: Physical Layer Scope
- **Problem**: Section 3.2 mentions Layer 3 Physical Identity (clock skew, RF fingerprinting, power consumption).
- **Decision**: Physical layer hardware measurement is out of scope for pure software build. Provide an empty `PhysicalIdentityProvider` interface stub and document as future work.

### ADR-008: Baseline Comparison Integrity
- **Problem**: PDF Table 8 lists synthetic Snort comparison numbers without reproducibility scripts.
- **Decision**: Do not fake Snort outputs. Real baselines in evaluation are:
  1. Static-threshold rules
  2. Global (pooled) Isolation Forest
  3. Z-score only
  4. Full multi-layer GUARDIAN

### ADR-009: Offline Geolocation
- **Problem**: Alerts display "Moscow, Russia" while system architecture promises 100% local processing with zero cloud calls.
- **Decision**: Use an optional local offline MaxMind GeoLite2 database behind a `GeoProvider` interface. If absent, fallback text is strictly: *"external address, location unknown"*.

### ADR-010: Third-Party Numbers in Executive Summary
- **Problem**: General market statistics (75B devices, 80% encrypted) cited in source summary.
- **Decision**: Exclude unverified numbers from automated codebase. Must be verified and cited directly by author prior to IEEE submission.

---

## 2. Milestone M1 Architecture Decisions

### ADR-011: Injectable Deterministic Simulation Clock (`SimClock`)
- **Problem**: Simulating 14+ days of network traffic for IEEE evaluations in real time would require two weeks per test run; using system wall clock prevents determinism and headless replay.
- **Decision**: All pipeline components, timestamp records, window aggregators, and response timers must accept an injected `Clock` interface (`RealClock` for live deployments, `SimClock` for simulation).
- **Rationale**: Guarantees strict monotonicity, eliminates non-deterministic timing bugs, and enables multi-day network evaluations to run in minutes.

### ADR-012: SQLite WAL Persistence & Alembic Migration Discipline
- **Problem**: High-frequency feature window evaluation (every 2 seconds per device) causes SQLite lock contention and database growth on resource-constrained edge platforms.
- **Decision**: SQLite configured with Write-Ahead Logging (`PRAGMA journal_mode=WAL`), `PRAGMA synchronous=NORMAL`, `PRAGMA busy_timeout=5000`, and strict foreign key integrity. All schema iterations are managed through Alembic migrations from day one.
- **Rationale**: Concurrent reads and writes without thread deadlocks, minimal write amplification on SD cards, and auditable versioned database migrations.

---

## 3. Phase 2 Architecture Decisions (Milestone P2-1)

### ADR-013: Python 3.11 Standard and pyproject.toml Consolidation
- **Problem**: Inconsistent package specifications between `requirements.txt` and `pyproject.toml`, and Python 3.10+ declaration while the project plan standardized on Python 3.11.
- **Decision**: Standardize `requires-python = ">=3.11"` in `pyproject.toml`, make `pyproject.toml` the sole canonical source of runtime and development dependencies, remove standalone `requirements.txt` from repository tracking, and provide `make export-requirements` for headless environments.
- **Rationale**: Eliminates split-brain dependency specifications and enforces modern Python 3.11 typing and performance optimizations across all quality gates.

### ADR-014: Unified `src/guardian` Package Layout & SQLAlchemy 2.0 Typing Modernization
- **Problem**: Dual package layouts (`guardian/` in root and `src/guardian/`) created ambiguous imports, broken module resolutions in editable installs, and legacy SQLAlchemy `Column` definitions produced strict mypy type errors.
- **Decision**: Completely remove legacy root `guardian/` directory. Migrate all submodules (`capture`, `config`, `features`, `ml`, `intelligence`, `enforcement`, `xai`, `storage`, `api`) into `src/guardian/`. Upgrade all SQLAlchemy ORM models (`Device`, `Alert`, `BehavioralBaseline`, `SystemMetric`, `AuditLog`) to `DeclarativeBase` with typed `Mapped[T] = mapped_column(...)`. Add repo root to `tool.pytest.ini_options.pythonpath = ["src", "."]`.
- **Rationale**: Guarantees standard packaging compliance, prevents import shadowing, provides 100% strict type safety under mypy without untyped escapes, and ensures seamless testing across CI matrices.

---

## 4. Phase 2 Architecture Decisions (Milestone P2-2)

### ADR-015: Dedicated `eval/` Evaluation Framework Architecture & Ground Truth Methodology
- **Problem**: Phase 1 evaluation relied on isolated 50-trial loops feeding pure attack packets into a feature tracker without background normal traffic, hardcoded baseline strings, differing operating points between detection and false alarms, and silent fallbacks to 0.0 when model files were missing.
- **Decision**: Implement a dedicated evaluation package (`guardian.eval` and root `eval/`) with:
  1. `ScenarioBuilder`: 14-day stream generation with strictly time-ordered splits (Days 1-7 Train, Day 8 Calibration, Days 9-14 Test). Attack episodes are injected directly into ongoing background normal traffic, guaranteeing all attack windows contain realistic background noise.
  2. `Calibrator` & `OperatingPoint`: Operating point selected on clean Day 8 calibration split and frozen, enforcing that the exact same threshold determines both detection and false alarm metrics.
  3. `EvaluationRunner`: Exercises the real production pipeline (`FlowTracker`, `FeatureExtractor`, `IsolationForestDetector`, `StatisticalBaseline`, `ThreatScorer`, `EnforcementController`) and fails loudly via `ArtifactMissingError` if any model checkpoint is missing.
- **Rationale**: Enforces absolute scientific integrity, eliminates synthetic evaluation shortcuts, produces verifiable empirical metrics, and enables deterministic reproducibility across seeds.

---

## 5. Phase 2 Architecture Decisions (Milestones P2-3 and P2-4)

### ADR-016: Content-Hash Bundle Caching and Cryptographic Quality Sidecars
- **Problem**: Baseline generation retrained models on every execution, causing metric drift across evaluation runs, and missing or corrupted model artifacts could lead to silent evaluation failures.
- **Decision**: Implement `ModelCacheManager` using SHA-256 content hashes of training data, model configurations, and feature registries. Persist accompanying `ModelSidecarData` recording training sample counts, observed feature ranges, and held-out anomaly score percentiles with a cryptographic signature. Reject tampered or corrupted bundles loudly via `TamperedBundleError`.
- **Rationale**: Guarantees deterministic, cache-accelerated evaluation across runs, eliminates metric drift, and ensures complete traceability of trained models against their training inputs.

### ADR-017: Empirical Baselines and Layer/Component Ablation Architecture
- **Problem**: Literature comparison tables previously included unmeasured or hardcoded values for external tools (e.g. Snort), and no empirical baselines existed within the framework to isolate the value of GUARDIAN's individual components.
- **Decision**: Remove all unverified literature numbers (F1). Implement three real empirical baselines:
  1. `StaticThresholdBaseline`: Simulates commercial firewall/NIDS static rules with allowlists (known destinations and ports) and volumetric packet/byte rate ceilings.
  2. `PooledIsolationForestBaseline`: Represents generic fleet-wide machine learning anomaly detection trained on all device classes without per-device separation.
  3. `RobustZScoreOnlyBaseline`: Evaluates Layer 1 statistical tests without machine learning.
  Implement `AblationRunner` and `get_standard_ablation_battery()` supporting systematic ablation of Layer 1, Layer 2, hysteresis damping, and operating point calibration.
- **Rationale**: Replaces fabricated literature comparisons with rigorous, reproducible, measured empirical baselines and demonstrates the precise marginal utility of each defense layer.

---

## 6. Phase 2 Architecture Decisions (Milestones P2-5 and P2-6)

### ADR-018: Empirical System Measurements, Latency Disaggregation, and Scalability Benchmarking
- **Problem**: Previous benchmarks presented literal strings for resource utilization (CPU 18.4%, RAM 142 MB), hardcoded scalability results, and reported a single ambiguous "detection latency" number that only measured window calculation without end-to-end time-to-detect.
- **Decision**: 
  1. Implement `SystemResourceBenchmark` to measure active process CPU% and memory RSS using OS-level process counters (`psutil`), dynamically computing `PASS`/`FAIL` against configured engineering targets ($CPU < 25\%$, $RAM < 256\text{ MB}$).
  2. Implement `LatencyBenchmark` reporting three distinct, non-conflated latency metrics:
     - **Compute Latency**: Time to extract features and evaluate anomaly detectors on a single window ($ms$).
     - **Time-to-Detect (TTD)**: Wall-clock duration elapsed from the onset of an attack episode to the first detection alert ($s$).
     - **Enforcement Latency**: Time to apply firewall containment policies via the enforcement controller ($ms$).
  3. Implement `ScalabilityBenchmark` with `generate_scaled_fleet` evaluating throughput and resource overhead across 8, 12, 16, and 20 devices with fair trial round-robin allocation.
- **Rationale**: Eliminates fabricated benchmark literals (F2, F3, F4, F12) and provides verifiable, empirical measurements of production runtime characteristics under varying fleet sizes.

---

## 7. Phase 3 Architecture Decisions (Milestone P3-0)

### ADR-019: Evaluation Validity, Simulator Realism, and Plausibility Controls Strategy
- **Problem**: Phase 2 generated verifiable numbers with run IDs and seeds, but results were implausible in a different way: 100% detection and 0.00s time-to-detect across all attacks and evasion modes, identical F1 scores across rows, and mismatched FPR between tables. An evaluation that cannot fail proves nothing.
- **Decision**: 
  1. Freeze Phase 2 final state (phase2-final tag) in eval/results/phase2_snapshot/ as read-only evidence.
  2. Adopt Phase 3 Prime Directive: Every evaluation result must survive:
     - Leakage audit (test that labels, injected markers, or ground truth do not leak into feature extraction or detection models).
     - Broken-detector controls (shuffled labels, random score detector with ROC-AUC ~ 0.5, always-alert and never-alert bounds).
     - Plausibility guard (flags 100% TPR on hard tier, 0.00s time-to-detect, identical metrics across rows, or flat scaling curves as WARN/FAIL).
  3. Enforce sample-size policy (at least 5 seeds, at least 50 episodes per attack type per tier per seed, at least 6 normal test days per device per seed).
  4. Restore episode-level detection within 60s as headline metric.
- **Rationale**: Ensures the evaluation is scientifically trustworthy, able to fail, and reflects true detection limits rather than inflated metrics on synthetic tests.

### ADR-020: Simulator Realism v2: Multi-Tier Injections, Statistical Mimicry, and Operational Hard Negatives
- **Problem**: In Phase 2, attack injections generated high volumetric rates (850–1400 packets in 10s against devices producing 4–12 packets), rendering attacks trivially separable and producing unrealistic 100% TPR / 0.00s TTD results. Evasion mimicry lacked statistical matching of byte distributions, and no benign operational transients were evaluated.
- **Decision**:
  1. Implement difficulty tiers (`EASY`, `MEDIUM`, `HARD`) across all 6 threat vectors with calibrated packet count and size dispersion scaling.
  2. Implement true statistical mimicry matching legitimate first- and second-order packet length statistics ($\mu, \sigma$ within $25\text{ B}$), supporting destination-reuse and novel-destination sub-modes.
  3. Implement low-and-slow exfiltration with tight hourly byte limits ($120 - 1000\text{ B/hr}$), delayed-start dormancy ($50\%$ initial quiet window), and closed-loop adaptive attacker backoff (quiescence above $45.0$ threat score).
  4. Implement 10 benign operational hard negatives (firmware updates, user toggles, reboot storms, DNS retry storms, NTP bursts, MQTT reconnect floods, camera motion bursts, router reboots, new cloud endpoints, DST shifts).
- **Rationale**: Elevates synthetic simulation realism to peer-review scientific standards, preventing trivial separability and uncovering genuine detection boundaries.

### ADR-021: Evaluation Integrity v2: Sample Sizes, Non-Zero Time-to-Detect, and Cross-Table Consistency
- **Problem**: In Phase 2, evaluation tables exhibited identical rows across different attack vectors (G2), cross-table FPR discrepancies between main and ablation tables (G3), unverified baseline numbers without multi-seed sampling (G6), and instantaneous 0.00s time-to-detect due to window boundary overlap (G9).
- **Decision**:
  1. Restore episode-level detection within 60s deadline as headline evaluation metric, retaining window-level detection as secondary.
  2. Implement bounded non-zero time-to-detect where alert timestamps are tied to window completion (`w.end_time`) and episode overlap is strictly bounded (`overlap_start < overlap_end`).
  3. Multi-seed execution ($N_{seeds} \ge 5$) with 1000-iteration 95% bootstrap confidence intervals on detection rate, time-to-detect, and false positive rate.
  4. Concurrently score real empirical baselines (`StaticThresholdBaseline`, `RobustZScoreOnlyBaseline`, `PooledIsolationForestBaseline`) on identical stream windows without mock estimates.
  5. Add cross-table consistency validation (`check_evaluation_cross_table_consistency`) rejecting identical copied rows across attack classes and enforcing mathematical agreement between tables.
- **Rationale**: Ensures evaluation outputs withstand adversarial academic peer review, resolving audit findings G2, G3, G6, and G9.


