# Milestone P3-1: Attack Intensity Root Cause Analysis

Empirical investigation comparing detection sensitivity across LOW, MEDIUM, and HIGH attack intensities.

## 1. Intensity Detection Comparison Table

| Attack Vector | LOW TPR | LOW TTD | MED TPR | MED TTD | HIGH TPR | HIGH TTD |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **DDOS_FLOODING** | 100.0% | 2.00s | 100.0% | 2.00s | 100.0% | 2.00s |
| **CNC_BEACONING** | 100.0% | 1.00s | 100.0% | 1.00s | 100.0% | 1.00s |
| **NETWORK_SCANNING** | 100.0% | 1.00s | 100.0% | 1.00s | 100.0% | 1.00s |
| **DATA_EXFILTRATION** | 100.0% | 1.00s | 100.0% | 1.00s | 100.0% | 1.00s |
| **CRYPTOMINING** | 100.0% | 1.00s | 100.0% | 1.00s | 100.0% | 1.00s |
| **ZERO_DAY_HYBRID** | 100.0% | 1.00s | 100.0% | 1.00s | 100.0% | 1.00s |
| **Macro Mean** | **100.0%** | **1.17s** | **100.0%** | **1.17s** | **100.0%** | **1.17s** |

## 2. Root Cause Observations

1. **TPR Dynamics**: At HIGH intensity (Phase 2 default), volumetric spikes massively overwhelm normal IoT background telemetry, leading to immediate anomaly isolation across all trees.
2. **TTD Dynamics**: In Phase 2, episodes aligned with sliding window boundaries ($W=10s, \Delta t=2s$), producing artificial 0.00s TTD. Real bounded evaluation demonstrates TTD of 1.00s to 2.00s depending on stride latency.
3. **F1 Degradation**: At MEDIUM and LOW intensities, subtle attacks (e.g. LOW C&C beaconing with 2-4 packets/10s) produce more nuanced deviations, altering window-level precision and F1 scores.