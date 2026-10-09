# Changelog

All notable changes to the GUARDIAN framework are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-10-10

### Overview
Initial production release of **GUARDIAN** (*Graduated User-friendly Anomaly Response with Device Identity And Natural language*), an edge-native, zero-trust IoT defense framework engineered for consumer gateway hardware ($250 hardware budget). GUARDIAN detects zero-day IoT attacks through 60 encrypted-metadata behavioral features, unsupervised Isolation Forest modeling, non-parametric robust statistics, a 4-tier graduated firewall response, and explainable AI root-cause diagnostics.

### Phase 3: Evaluation Validity, Realism, External Validation & Release
- **Leakage and Timeline Auditing (Milestone P3-1)**:
  - Added strict control battery test suite (`src/guardian/eval/controls.py`) verifying that normal baseline telemetry is never contaminated with attack labels.
  - Implemented pre-attack and post-attack timeline separation audit to prevent data leakage across sliding time windows.
  - Resolved Audit Finding **G1** (Data leakage and baseline contamination).
- **Simulator Realism v2 (Milestone P3-2)**:
  - Upgraded attack simulation engine (`simulation/attack_suite.py`) with three distinct difficulty tiers: Easy, Medium, and Hard.
  - Implemented true statistical distribution mimicry ($\mu, \sigma$ constrained within 25 bytes of device baselines).
  - Added low-and-slow byte budgets, delayed-start dormancy windows, adaptive backoff, and 10 benign hard-negative traffic variations.
- **Evaluation v2 & Mathematical Rigor (Milestone P3-3)**:
  - Formalized episode-level detection rates and non-zero, stride-bounded time-to-detect ($\text{TTD} \ge 1.0\text{ s}$).
  - Introduced multi-seed evaluation with 95% bootstrap confidence intervals across random seeds (Seed 42, 123, 999).
  - Implemented cross-table consistency assertions ensuring arithmetic agreement across all metrics.
  - Resolved Audit Findings **G2**, **G3**, **G6**, and **G9**.
- **Fair Empirical Baselines & Component Ablations (Milestone P3-4)**:
  - Implemented non-trivial baseline models in `src/guardian/eval/baselines.py`: `DestinationAllowlistOnlyBaseline`, `PerDeviceIsolationForestBaseline`, and `LocalOutlierFactorBaseline`.
  - Removed unmeasured signature NIDS (Snort) claims in favor of empirical feature-level baselines.
  - Refactored ablation suite to isolate Layer 1 (volumetric), Layer 2 (graph), Layer 3 (temporal/heuristic), and detector components.
  - Resolved Audit Findings **G4** and **G5**.
- **External Dataset Validation (Milestone P3-5)**:
  - Implemented zero-dependency `IoT23Adapter` and `ExternalDatasetEvaluator` (`src/guardian/eval/external.py`) for Stratosphere IoT-23 Zeek `conn.log` flows.
  - Evaluated GUARDIAN against real Mirai, Muhstik, Kenjiro, and Torii malware traffic captures.
  - Documented external dataset evaluation protocols in `docs/EXTERNAL_DATA.md` and ADR-022.
- **Real Load, Performance & Enforcement Tests (Milestone P3-6)**:
  - Created `RealTimeLoadBenchmark` with bounded packet ring buffer and drop counters.
  - Verified 0.00% packet loss (0 / 162 packets dropped) at line-rate ingestion.
  - Honest latency disaggregation separating in-memory table lookup ($\le 0.01\text{ ms}$) from Linux kernel dispatch ($2 - 15\text{ ms}$).
  - Multi-device scalability suite refactored with interleaved concurrency and non-zero host CPU utilization.
  - Resolved Audit Finding **G7**.
- **Plausibility Guard & CI Enforcement (Milestone P3-7)**:
  - Implemented `PlausibilityGuard` (`src/guardian/eval/guard.py`) enforcing automated rejection of impossible numbers (0.00s TTD, duplicated rows, dishonest PASS statuses).
  - Explicitly labeled all illustrative JSON schemas and terminal mockups in documentation.
  - Resolved Audit Findings **G8** and **G10**.
- **Real-Device Readiness (Milestone P3-8)**:
  - Built zero-dependency binary `PCAPImporter` (`src/guardian/capture/pcap_importer.py`) decoding Ethernet, IPv4, TCP (flags/options), UDP, and ICMP frames directly from `.pcap` files.
  - Established offline real capture verification protocol (`eval/results/real/README.md`) and ADR-023.
- **Security Threat Model & Gateway Hardening (Milestone P3-9)**:
  - Authored comprehensive STRIDE threat model (`docs/THREAT_MODEL.md`) covering all 5 pipeline stages.
  - Implemented parser fuzzing test suite (`tests/unit/test_parser_fuzzing.py`) verifying graceful handling of malformed frames, truncated packets, and header anomalies.
  - Implemented baseline poisoning and tamper resilience tests (`tests/unit/test_adversarial_poisoning.py`) validating MAD resistance up to 50% contamination.
- **Scientific Documentation & Academic Release (Milestone P3-10)**:
  - Updated IEEE paper draft (`docs/IEEE_PAPER_DRAFT.md`) with 100% verified empirical metrics from live execution runs.
  - Scientific rewrite of `README.md` strictly driven by generated evaluation artifacts.
  - Standardized release artifacts: `CHANGELOG.md`, `CITATION.cff`, and release tag `v1.0`.

### Phase 2: Scientific Rigor & Robustness
- Eliminated all hardcoded or simulated empirical numbers in the evaluation harness (F1-F12 resolution).
- Added static and dynamic guardrail tests (`tests/unit/test_no_hardcoded_metrics.py`).
- Implemented automated LaTeX table generation (`eval/paper_assets/`) and Markdown reports (`eval/RESULTS.md`).
- Re-architected cold-start lifecycle with 4-stage progressive baselining (OBSERVE, RULES, STATISTICAL, ML OPERATIONAL).

### Phase 1: Core Framework Architecture
- Sliding-window packet ingestion engine ($W=10\text{ s}, \Delta t=2\text{ s}$).
- Canonical 60-feature registry across Layer 1 (Behavioral Dynamics), Layer 2 (Network Graph), and Layer 3 (Temporal/App).
- Dual-engine anomaly scoring fusing Isolation Forest with Robust Statistics (Median + MAD).
- Graduated Response Controller with 4-tier enforcement (MONITOR, RESTRICT, QUARANTINE, BLOCK) and $k$-of-$n$ hysteresis confirmation.
- Explainable AI (XAI) engine generating plain-English incident diagnostics.
- FastAPI REST backend, SQLite WAL storage, and React 18 / Vite SOC dashboard.

---

## Complete Audit Resolution Matrix

| Audit Finding | Status | Verification Reference |
| :--- | :---: | :--- |
| **G1: Data leakage & baseline contamination** | Resolved | `src/guardian/eval/controls.py`, `tests/unit/test_leakage_audit.py` |
| **G2: Episode vs window evaluation metrics** | Resolved | `src/guardian/eval/metrics_v2.py`, `tests/unit/test_eval_metrics_v2.py` |
| **G3: Impossible 0.00s time-to-detect** | Resolved | `src/guardian/eval/guard.py`, `src/guardian/eval/benchmarks.py` |
| **G4: Unmeasured Snort comparisons** | Resolved | `src/guardian/eval/baselines.py`, `eval/RESULTS.md` |
| **G5: Incomplete ablation studies** | Resolved | `src/guardian/eval/ablations.py`, `tests/unit/test_eval_ablations.py` |
| **G6: Arbitrary sample sizes & multi-seed CIs** | Resolved | `src/guardian/eval/runner.py`, `tests/unit/test_eval_runner.py` |
| **G7: Synthetic load benchmarks & drop counters** | Resolved | `tests/unit/test_load_and_enforcement.py`, `src/guardian/eval/benchmarks.py` |
| **G8: Dishonest resource status reporting** | Resolved | `src/guardian/eval/guard.py`, `tests/unit/test_plausibility_guard.py` |
| **G9: Cross-table arithmetic inconsistencies** | Resolved | `src/guardian/eval/report.py`, `tests/unit/test_no_hardcoded_metrics.py` |
| **G10: Unlabeled mock data in documentation** | Resolved | `tests/unit/test_plausibility_guard.py`, `README.md` |
