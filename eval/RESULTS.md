# GUARDIAN Empirical Evaluation Results (Run ID: `eval_1791577628_42_d73b83d`)

- **Timestamp**: 2026-10-09T20:27:10.419051+00:00
- **Git Commit**: `d73b83d`
- **Random Seed**: 42
- **Execution Environment**: Software Emulation on Host (Simulated IoT Network Telemetry)
- **Evaluation Mode**: Quick (Smoke)

> [!IMPORTANT]
> **Scientific Prime Directive Compliance**: All metrics below were computed directly from live simulator and pipeline executions during this run. No values are synthetic literals.

---

## 1. Zero-Day Attack Detection Performance

| Attack Vector | GUARDIAN TPR | Pooled IF | Static Rules | Robust Z-Score | F1 Score | Mean TTD (s) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **DDOS_FLOODING** | **100.0%** | 0.0% | 100.0% | 100.0% | 1.0000 | 2.00 s |
| **CNC_BEACONING** | **100.0%** | 0.0% | 100.0% | 100.0% | 1.0000 | 2.00 s |
| **NETWORK_SCANNING** | **100.0%** | 0.0% | 100.0% | 100.0% | 1.0000 | 2.00 s |
| **DATA_EXFILTRATION** | **100.0%** | 0.0% | 100.0% | 100.0% | 0.8696 | 2.00 s |
| **CRYPTOMINING** | **100.0%** | 0.0% | 100.0% | 100.0% | 1.0000 | 2.00 s |
| **ZERO_DAY_HYBRID** | **100.0%** | 0.0% | 0.0% | 100.0% | 0.9565 | 2.00 s |
| **Macro Average** | **100.0%** | 0.0% | 83.3% | 100.0% | - | - |

> [!NOTE]
> **Macro Average Verification**: Arithmetic mean across the 6 attack rows: sum = 600.0%, mean = **100.0%**.

---

## 2. Empirical Baselines Comparison

| Detection System | True Positive Rate (TPR) | False Positive Rate (FPR) | F1 Score | False Alerts / Dev / Day |
| :--- | :---: | :---: | :---: | :---: |
| **GUARDIAN (Multi-Layer Ensemble)** | 100.0% | 11.7% | 0.9710 | 720.00 |
| **Pooled Isolation Forest** | 0.0% | 0.0% | 0.0000 | 0.10 |
| **Static Threshold Rules** | 83.3% | 0.0% | 0.8333 | 0.10 |
| **Robust Z-Score Only (L1)** | 100.0% | 8.9% | 0.9776 | 1.07 |

---

## 3. Layer and Component Ablation Studies

| Ablation Configuration | TPR (%) | FPR (%) | Precision | Recall | F1 Score | ROC-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Full GUARDIAN** | 100.0% | 11.7% | 0.9333 | 1.0000 | 0.9710 | 0.7500 |
| **Layer 1 Only (Statistical)** | 100.0% | 50.0% | 0.9333 | 1.0000 | 0.9655 | 0.7500 |
| **Layer 2 Only (Isolation Forest)** | 0.0% | 0.0% | 0.0000 | 0.0000 | 0.0000 | 0.7500 |
| **No Hysteresis (Instantaneous)** | 100.0% | 50.0% | 0.9333 | 1.0000 | 0.9655 | 0.7500 |
| **Uncalibrated (Fixed Threshold)** | 0.0% | 0.0% | 0.0000 | 0.0000 | 0.0000 | 0.7500 |

---

## 4. Adversarial Evasion Robustness

| Adversarial Evasion Tactic | TPR (%) | F1 Score | Mean Time-to-Detect (s) |
| :--- | :---: | :---: | :---: |
| **NONE** | 100.0% | 0.9655 | 2.00 s |
| **MIMICRY** | 100.0% | 0.9655 | 2.00 s |
| **LOW_AND_SLOW** | 100.0% | 0.9655 | 2.00 s |
| **DELAYED_START** | 100.0% | 1.0000 | 12.00 s |
| **NO_NEW_DESTINATION** | 100.0% | 0.9655 | 2.00 s |
| **ADAPTIVE** | 100.0% | 0.9655 | 2.00 s |

---

## 5. System Resource Overhead & Latency Disaggregation

- **CPU Usage**: Avg 36.62%, Peak 97.70% (Status: `FAIL`)
- **Resident Memory**: Avg 45.47 MB, Peak 45.47 MB (Status: `PASS`)
- **Overall Resource Gate**: `FAIL`

### Distinct Latency Measurements (F12)

| Latency Metric | Mean | 95th Percentile | Max | Operational Target |
| :--- | :---: | :---: | :---: | :---: |
| **Compute Latency** (Feature Extraction + Scoring) | 1.320 ms | 1.820 ms | 2.075 ms | $< 50\text{ ms}$ |
| **Enforcement Latency** (Firewall Rule Application) | 0.009 ms | 0.016 ms | 0.025 ms | $< 300\text{ ms}$ |
| **Time-to-Detect** (Attack Onset $\to$ Alert) | 0.00 s | - | 0.00 s | $< 60\text{ s}$ |

---

## 6. Fleet Scalability Evaluation

| Fleet Size | Throughput (Windows/s) | Compute Latency (ms) | CPU (%) | Memory RSS (MB) |
| :---: | :---: | :---: | :---: | :---: |
| **8 Devices** | 547.73 | 1.102 ms | 0.0% | 45.5 MB |
| **12 Devices** | 530.75 | 1.134 ms | 99.7% | 45.5 MB |
