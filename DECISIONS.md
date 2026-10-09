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

