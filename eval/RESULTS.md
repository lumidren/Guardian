# GUARDIAN Empirical Evaluation Results (Run ID: `eval_1791581516_42_6060caa`)

- **Timestamp**: 2026-10-09T21:31:58.611838+00:00
- **Git Commit**: `6060caa`
- **Random Seed**: 42
- **Execution Environment**: Software Emulation on Host (Simulated IoT Network Telemetry)
- **Evaluation Mode**: Full Rigorous Battery

> [!IMPORTANT]
> **Scientific Prime Directive Compliance**: All metrics below were computed directly from live simulator and pipeline executions during this run. No values are synthetic literals.

---

## 1. Zero-Day Attack Detection Performance

| Attack Vector | GUARDIAN TPR | Pooled IF | Static Rules | Robust Z-Score | F1 Score | Mean TTD (s) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **DDOS_FLOODING** | **100.0%** | 0.0% | 100.0% | 100.0% | 0.9714 | 2.00 s |
| **CNC_BEACONING** | **100.0%** | 0.0% | 100.0% | 100.0% | 1.0000 | 1.00 s |
| **NETWORK_SCANNING** | **100.0%** | 0.0% | 100.0% | 100.0% | 0.9730 | 1.00 s |
| **DATA_EXFILTRATION** | **100.0%** | 0.0% | 100.0% | 100.0% | 0.9714 | 1.00 s |
| **CRYPTOMINING** | **100.0%** | 0.0% | 100.0% | 100.0% | 0.9583 | 1.00 s |
| **ZERO_DAY_HYBRID** | **100.0%** | 0.0% | 0.0% | 100.0% | 0.9756 | 1.00 s |
| **Macro Average** | **100.0%** | 0.0% | 83.3% | 100.0% | - | - |

> [!NOTE]
> **Macro Average Verification**: Arithmetic mean across the 6 attack rows: sum = 600.0%, mean = **100.0%**.

---

## 2. Empirical Baselines Comparison

| Detection System | True Positive Rate (TPR) | False Positive Rate (FPR) | F1 Score | False Alerts / Dev / Day |
| :--- | :---: | :---: | :---: | :---: |
| **GUARDIAN (Multi-Layer Ensemble)** | 100.0% | 9.3% | 0.9750 | 1234.29 |
| **Pooled Isolation Forest** | 0.0% | 0.0% | 0.0000 | 0.10 |
| **Static Threshold Rules** | 83.3% | 0.0% | 0.8333 | 0.10 |
| **Robust Z-Score Only (L1)** | 100.0% | 9.6% | 0.9756 | 1.15 |

---

## 3. Layer and Component Ablation Studies

| Ablation Configuration | TPR (%) | FPR (%) | Precision | Recall | F1 Score | ROC-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Full GUARDIAN** | 100.0% | 9.3% | 0.0000 | 0.0000 | 0.9750 | 1.0000 |
| **Statistical Detector Only (No ML)** | 0.0% | 0.0% | 0.0000 | 0.0000 | 0.0000 | 1.0000 |
| **Isolation Forest Only (No Stat)** | 0.0% | 0.0% | 0.0000 | 0.0000 | 0.0000 | 1.0000 |
| **No Layer 1 (Volumetric Dynamics)** | 0.0% | 0.0% | 0.0000 | 0.0000 | 0.0000 | 1.0000 |
| **No Layer 2 (Network Graph)** | 0.0% | 0.0% | 0.0000 | 0.0000 | 0.0000 | 0.5000 |
| **No Layer 3 (Temporal/App)** | 0.0% | 0.0% | 0.0000 | 0.0000 | 0.0000 | 1.0000 |
| **No Hysteresis (Instantaneous)** | 0.0% | 0.0% | 0.0000 | 0.0000 | 0.0000 | 1.0000 |
| **Uncalibrated (Fixed Threshold)** | 0.0% | 0.0% | 0.0000 | 0.0000 | 0.0000 | 1.0000 |

---

## 4. Adversarial Evasion Robustness

| Adversarial Evasion Tactic | TPR (%) | F1 Score | Mean Time-to-Detect (s) |
| :--- | :---: | :---: | :---: |
| **NONE** | 100.0% | 0.9333 | 2.00 s |
| **MIMICRY** | 100.0% | 0.9333 | 2.00 s |
| **LOW_AND_SLOW** | 100.0% | 0.9333 | 2.00 s |
| **DELAYED_START** | 100.0% | 0.9474 | 12.00 s |
| **NO_NEW_DESTINATION** | 100.0% | 0.9333 | 2.00 s |
| **ADAPTIVE** | 100.0% | 0.9333 | 2.00 s |

---

## 5. System Resource Overhead & Latency Disaggregation

- **CPU Usage**: Avg 74.90%, Peak 104.20% (Status: `FAIL`)
- **Resident Memory**: Avg 45.76 MB, Peak 45.76 MB (Status: `PASS`)
- **Overall Resource Gate**: `FAIL`

### Distinct Latency Measurements (F12)

| Latency Metric | Mean | 95th Percentile | Max | Operational Target |
| :--- | :---: | :---: | :---: | :---: |
| **Compute Latency** (Feature Extraction + Scoring) | 1.223 ms | 1.583 ms | 1.632 ms | $< 50\text{ ms}$ |
| **Enforcement Latency** (Firewall Rule Application) | 0.008 ms | 0.010 ms | 0.012 ms | $< 300\text{ ms}$ |
| **Time-to-Detect** (Attack Onset $\to$ Alert) | 2.00 s | - | 2.00 s | $< 60\text{ s}$ |

---

## 6. Fleet Scalability Evaluation

| Fleet Size | Throughput (Windows/s) | Compute Latency (ms) | CPU (%) | Memory RSS (MB) |
| :---: | :---: | :---: | :---: | :---: |
| **8 Devices** | 949.76 | 1.037 ms | 92.8% | 45.8 MB |
| **12 Devices** | 942.84 | 1.045 ms | 81.8% | 45.8 MB |
| **16 Devices** | 944.76 | 1.042 ms | 92.3% | 45.8 MB |
| **20 Devices** | 951.05 | 1.036 ms | 99.1% | 45.8 MB |

---

## 7. Real-Time Packet Stream & Buffer Drop Counters (Milestone P3-6)

| Ingestion Metric | Measured Value | Operational Gate |
| :--- | :---: | :---: |
| **Offered Packets** | 162 pkts | Line ingestion rate |
| **Processed Packets** | 162 pkts | Pipeline throughput |
| **Dropped Packets** | 0 pkts | $< 0.1\%$ under normal load |
| **Packet Drop Rate** | 0.00% | $0.00\%$ |
| **Peak Queue Depth** | 4 / 5000 pkts | Buffer headroom |
| **Packet Ingestion Throughput** | 162000.0 pps | Real-time line rate |
