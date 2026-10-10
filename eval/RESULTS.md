# GUARDIAN Empirical Evaluation Results (Run ID: `eval_1791615776_42_11270e5`)

- **Timestamp**: 2026-10-10T07:05:23.544586+00:00
- **Git Commit**: `11270e5`
- **Random Seed**: 42
- **Execution Environment**: Software Emulation on Host (Simulated IoT Network Telemetry)
- **Evaluation Mode**: Full Rigorous Battery

> [!IMPORTANT]
> **Scientific Prime Directive Compliance**: All metrics below were computed directly from live simulator and pipeline executions during this run. No values are synthetic literals.

---

## 1. Zero-Day Attack Detection Performance

| Attack Vector | GUARDIAN TPR | Pooled IF | Static Rules | Robust Z-Score | F1 Score | Mean TTD (s) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **DDOS_FLOODING** | **100.0%** | 0.0% | 91.3% | 100.0% | 0.9995 | 1.01 s |
| **CNC_BEACONING** | **83.3%** | 0.0% | 66.7% | 99.3% | 0.7569 | 2.85 s |
| **NETWORK_SCANNING** | **100.0%** | 0.0% | 100.0% | 100.0% | 0.9999 | 1.00 s |
| **DATA_EXFILTRATION** | **100.0%** | 0.0% | 100.0% | 100.0% | 0.9996 | 1.02 s |
| **CRYPTOMINING** | **100.0%** | 0.0% | 100.0% | 100.0% | 0.9995 | 1.03 s |
| **ZERO_DAY_HYBRID** | **90.0%** | 0.0% | 64.7% | 96.7% | 0.7520 | 4.06 s |
| **Macro Average** | **95.5%** | 0.0% | 87.1% | 99.3% | - | - |

> [!NOTE]
> **Macro Average Verification**: Arithmetic mean across the 6 attack rows: sum = 573.3%, mean = **95.5%**.

---

## 2. Empirical Baselines Comparison

| Detection System | True Positive Rate (TPR) | False Positive Rate (FPR) | F1 Score | False Alerts / Dev / Day |
| :--- | :---: | :---: | :---: | :---: |
| **GUARDIAN (Multi-Layer Ensemble)** | 95.5% | 0.0% | 0.9179 | 0.00 |
| **Pooled Isolation Forest** | 0.0% | 0.0% | 0.0000 | 0.10 |
| **Static Threshold Rules** | 87.1% | 0.0% | 0.0000 | 0.10 |
| **Robust Z-Score Only (L1)** | 99.3% | 9.7% | 0.0000 | 1.16 |

---

## 3. Layer and Component Ablation Studies

| Ablation Configuration | TPR (%) | FPR (%) | Precision | Recall | F1 Score | ROC-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Full GUARDIAN** | 95.5% | 0.0% | 0.0000 | 0.0000 | 0.9179 | 1.0000 |
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
| **NONE** | 100.0% | 1.0000 | 1.63 s |
| **MIMICRY** | 100.0% | 1.0000 | 1.29 s |
| **LOW_AND_SLOW** | 100.0% | 1.0000 | 1.31 s |
| **DELAYED_START** | 100.0% | 1.0000 | 11.21 s |
| **NO_NEW_DESTINATION** | 100.0% | 1.0000 | 1.48 s |
| **ADAPTIVE** | 100.0% | 1.0000 | 0.64 s |

---

## 5. System Resource Overhead & Latency Disaggregation

- **CPU Usage**: Avg 56.78%, Peak 104.20% (Status: `FAIL`)
- **Resident Memory**: Avg 68.07 MB, Peak 68.07 MB (Status: `PASS`)
- **Overall Resource Gate**: `FAIL`

### Distinct Latency Measurements (F12)

| Latency Metric | Mean | 95th Percentile | Max | Operational Target |
| :--- | :---: | :---: | :---: | :---: |
| **Compute Latency** (Feature Extraction + Scoring) | 1.407 ms | 2.029 ms | 2.198 ms | $< 50\text{ ms}$ |
| **Enforcement Latency** (Firewall Rule Application) | 0.009 ms | 0.011 ms | 0.013 ms | $< 300\text{ ms}$ |
| **Time-to-Detect** (Attack Onset $\to$ Alert) | 1.05 s | - | 1.05 s | $< 60\text{ s}$ |

---

## 6. Fleet Scalability Evaluation

| Fleet Size | Throughput (Windows/s) | Compute Latency (ms) | CPU (%) | Memory RSS (MB) |
| :---: | :---: | :---: | :---: | :---: |
| **8 Devices** | 903.41 | 1.090 ms | 88.2% | 68.1 MB |
| **12 Devices** | 883.23 | 1.114 ms | 95.8% | 68.1 MB |
| **16 Devices** | 872.23 | 1.130 ms | 85.2% | 68.1 MB |
| **20 Devices** | 849.52 | 1.161 ms | 88.5% | 68.1 MB |

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
