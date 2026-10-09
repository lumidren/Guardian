# GUARDIAN Phase 2 Audit Findings Log

This document tracks all audit findings from Section 3 of the Phase 2 specification. Each finding details the integrity issue, required remediation, and its resolution status (including commit hash once fixed).

| ID | Location | Problem | Required Fix | Status | Fixed Commit |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **F1** | `run_evaluation.py`, `literature_baselines` | Snort and Generic columns are hardcoded strings. The average row (18%, 67%) is also hardcoded. No Snort or pooled model was ever run. | Delete. Replace with real baselines (P2-4): static-threshold rules, pooled Isolation Forest, robust z-score only. No Snort numbers unless a real run exists. | resolved | `9961c22`, `f73f5a6` |
| **F2** | `run_evaluation.py`, Table 9 | CPU '18.4% avg', Memory '142 MB', Network Overhead '+1.2 ms' and every [PASS] are literals. | Measure with psutil and process counters (P2-6). Status is computed from measured values against the configured targets. | resolved | `da5e216` |
| **F3** | `run_evaluation.py`, Table 10 | The whole scalability table is printed constants. No 8/12/16/20 device test exists. | Build a real scalability test (P2-6). | resolved | `da5e216` |
| **F4** | `run_evaluation.py`, trial loop | `DEFAULT_FLEET_SPECS[trials % len(...)]` uses `trials` (always 50), so every non-hybrid attack runs on one device only. | Use the trial index and cover every applicable device type evenly. | resolved | `da5e216` |
| **F5** | `run_evaluation.py`, trial loop | Each trial feeds a tracker only attack packets. Attack traffic is never mixed with the device's normal traffic, so detection is easier than reality. | Every episode is attack traffic injected into a running normal stream (P2-2). | resolved | `7e4570c` |
| **F6** | `run_evaluation.py` | Detection counts score >= 60. False positives count score >= 61 and are described as Quarantine or Block. Different operating points. | One operating point for both, chosen on the calibration split only (P2-2). | resolved | `86c6843` |
| **F7** | `run_evaluation.py` | No seeds, no time-based split, no hysteresis, only 200 normal windows (one false positive = 0.5 points). Window-level FPR is not comparable to alerts per day. | Seeded multi-day simulation, time-ordered splits, production engine with hysteresis, FPR reported both per window and as false alerts per device per day. | resolved | `7e4570c` |
| **F8** | `run_evaluation.py` | `model.score_sample(vec) if model else (0.0, {})` silently scores zero when a model file is missing. | Raise a clear error. Never substitute zero. | resolved | `3eab5db` |
| **F9** | `run_evaluation.py` | `generate_and_train_all()` retrains every run, so results drift between runs. | Train once per (seed, split) and cache with a hash of data, config and feature registry. Retrain only when the hash changes. | resolved | `a260c3b` |
| **F10** | `README.md` | Section 7 calls these 'Realistic Benchmark Results' and 'GUARDIAN Measured' on a Raspberry Pi 4. Badges show 87% and 4.2% as achieved. Enforcement latency of 0.05 ms is not a real firewall rule. | Rewrite from generated results only (P2-8). Remove or relabel badges. Say 'simulated data' and name the environment. | resolved | `207de94` |
| **F11** | Repo layout | Both `guardian/` and `src/guardian/` exist. Both `requirements.txt` and `pyproject.toml`. Python 3.10+ while the plan says 3.11. No repo description or topics. | Resolve in P2-1. | resolved | `3aa560e` |
| **F12** | `run_evaluation.py` | 'Detection latency' only times the compute step on one window. Time-to-detect from attack start is not measured. | Report three numbers: compute latency, time-to-detect, enforcement latency (P2-6). | resolved | `da5e216` |

---

## Phase 2 Reproducibility Verification (Milestone P3-0)
- **Snapshot Location**: `eval/results/phase2_snapshot/` (containing `RESULTS.md` and `evaluation_report.json`)
- **Git Tag**: `phase2-final`
- **Reproducibility Test**: Rerun evaluation twice with identical seed (`seed=42`). Confirmed identical algorithmic metrics across consecutive runs (deterministic hash match).

---

## Phase 3 Audit Findings Log (G1 to G10)

| ID | Observation | Why it matters | Required Fix | Status | Fixed Commit |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **G1** | TPR 100.0% and time-to-detect 0.00 s for all six attacks and all four evasion modes. | Real detectors do not detect mimicry and low-and-slow perfectly and instantly. Points to easy attacks, label leakage or window-level scoring on pure attack windows. | P3-1 leakage audit, P3-2 harder attacks, P3-3 episode-level scoring. | resolved | `b46d115`, `f79f3af`, `2c20892` |
| **G2** | Identical F1 (0.7907) on all six attack rows. Identical TPR on all rows for each baseline (80%, 85%). | Metrics computed once over the run and copied into every row, not per attack. | Compute per attack type (P3-3). Add a test that fails if all rows are identical. | resolved | `4bce435`, `d73b83d` |
| **G3** | GUARDIAN FPR is 4.1% in one table and 33.3% in the ablation table. F1 is 0.9120 in one place and 0.7907 in another. Same run ID. | Tables come from different code paths or operating points. | One metrics module, one operating point. Cross-table consistency test (P3-3). | resolved | `4bce435`, `d73b83d` |
| **G4** | Ablation precision 0.7778 with FPR 33.3% implies roughly 10 windows. Two ablations score 0% TPR. | Sample too small to mean anything. 0% TPR suggests a broken threshold or calibration path. | Run ablations on the full test set with seeds and CIs (P3-4). | resolved | `b33150a`, `36ce7c5`, `cefd3f9` |
| **G5** | 'Layer 2 Only (Isolation Forest)' and 'Layer 1 Only (Statistical)'. | Layers are mislabelled: Layer 2 is the network destination graph, not the Isolation Forest. | Rename. Ablate detectors and layers separately (P3-4). | resolved | `d519651`, `cefd3f9` |
| **G6** | Baseline TPRs are multiples of 5 (80, 85, 45, 90). Single seed (42). No confidence intervals. | Suggests about 20 episodes per attack. Spec asked for at least 5 seeds and at least 50 episodes per attack per seed. | Enforce sample-size policy, report n and CIs (P3-3). | resolved | `d73b83d` |
| **G7** | Scalability: throughput flat near 500 windows/s at 8 to 20 devices, CPU 0.0% at 8 devices, memory flat at 48.4 MB. | The test measures the benchmark loop, not the pipeline under real-time load. | Real-time load test with drop counters (P3-6). | resolved | `5de19dd` |
| **G8** | 'Time-to-Detect 0.00 s' marked PASS. Gateway CPU 62% average, above the 40% target, not marked as a failure. | Pass/fail logic is inconsistent and favors good-looking values. | Plausibility guard and honest status logic (P3-7). | open | - |
| **G9** | Detection metric changed from 'episodes detected within 60 s' to 'detected attack windows / total attack windows'. | Window-level TPR is not the headline in the spec and is easy to inflate. | Restore episode-level headline, keep window-level as secondary (P3-3). | resolved | `d73b83d` |
| **G10** | README claims 'No empirical values are hardcoded or fabricated', but dashboard mock and JSON example are hand-typed. | An absolute claim that is easy to disprove. | Label examples 'illustrative'. Make the claim a CI-enforced property, not prose (P3-7). | open | - |

---

## 4. Pure Attack Window & Score Timeline Audit (Milestone P3-1)

Evaluated 3 episodes per attack vector across 8 heterogeneous IoT device types (18 episodes total). Confirmed all attack windows contain running normal traffic:

| Attack Vector | Episode ID | Device | Pre-Attack Normal Score | Peak Attack Score | Normal Pkts in Window | Attack Pkts in Window | Background Status |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **DDOS_FLOODING** | `ep_audit_ddos_flooding_1` | `dev_02_motion` | 34.8 | 37.0 | 3 | 853 | `VERIFIED_MIXED` |
| **DDOS_FLOODING** | `ep_audit_ddos_flooding_2` | `dev_03_env` | 34.6 | 37.0 | 7 | 890 | `VERIFIED_MIXED` |
| **DDOS_FLOODING** | `ep_audit_ddos_flooding_3` | `dev_04_plug` | 35.0 | 37.0 | 4 | 856 | `VERIFIED_MIXED` |
| **CNC_BEACONING** | `ep_audit_cnc_beaconing_1` | `dev_03_env` | 34.6 | 37.0 | 7 | 26 | `VERIFIED_MIXED` |
| **CNC_BEACONING** | `ep_audit_cnc_beaconing_2` | `dev_04_plug` | 35.0 | 37.0 | 5 | 29 | `VERIFIED_MIXED` |
| **CNC_BEACONING** | `ep_audit_cnc_beaconing_3` | `dev_05_relay` | 34.6 | 37.0 | 2 | 28 | `VERIFIED_MIXED` |
| **NETWORK_SCANNING** | `ep_audit_network_scanning_1` | `dev_04_plug` | 38.4 | 41.0 | 4 | 120 | `VERIFIED_MIXED` |
| **NETWORK_SCANNING** | `ep_audit_network_scanning_2` | `dev_05_relay` | 37.8 | 41.0 | 2 | 120 | `VERIFIED_MIXED` |
| **NETWORK_SCANNING** | `ep_audit_network_scanning_3` | `dev_06_compute1` | 38.2 | 41.0 | 8 | 120 | `VERIFIED_MIXED` |
| **DATA_EXFILTRATION** | `ep_audit_data_exfiltration_1` | `dev_05_relay` | 34.8 | 37.0 | 3 | 412 | `VERIFIED_MIXED` |
| **DATA_EXFILTRATION** | `ep_audit_data_exfiltration_2` | `dev_06_compute1` | 34.6 | 37.0 | 10 | 401 | `VERIFIED_MIXED` |
| **DATA_EXFILTRATION** | `ep_audit_data_exfiltration_3` | `dev_07_compute2` | 34.6 | 37.0 | 11 | 407 | `VERIFIED_MIXED` |
| **CRYPTOMINING** | `ep_audit_cryptomining_1` | `dev_06_compute1` | 49.2 | 55.0 | 8 | 81 | `VERIFIED_MIXED` |
| **CRYPTOMINING** | `ep_audit_cryptomining_2` | `dev_07_compute2` | 49.0 | 55.0 | 8 | 87 | `VERIFIED_MIXED` |
| **CRYPTOMINING** | `ep_audit_cryptomining_3` | `dev_08_camera` | 49.0 | 55.0 | 2 | 85 | `VERIFIED_MIXED` |
| **ZERO_DAY_HYBRID** | `ep_audit_zero_day_hybrid_1` | `dev_07_compute2` | 34.8 | 37.0 | 10 | 850 | `VERIFIED_MIXED` |
| **ZERO_DAY_HYBRID** | `ep_audit_zero_day_hybrid_2` | `dev_08_camera` | 34.6 | 37.0 | 2 | 850 | `VERIFIED_MIXED` |
| **ZERO_DAY_HYBRID** | `ep_audit_zero_day_hybrid_3` | `dev_01_temp` | 34.6 | 37.0 | 6 | 850 | `VERIFIED_MIXED` |
