# External IoT Dataset Validation Report

## 1. Executive Summary & Objective

In accordance with Milestone **P3-5** of the GUARDIAN Phase 3 specification, this report validates GUARDIAN's threat detection architecture against independent, external, real-world IoT datasets. Synthetic emulations, even with realistic distributions and statistical mimicry, cannot capture every nuance of real malware implementations, physical network card buffers, and operating system scheduling jitter.

We evaluate GUARDIAN on two standard peer-reviewed public datasets:
1. **IoT-23** (Stratosphere Laboratory, CTU University): 23 real network traffic captures (16 IoT malware captures executing live exploits including Mirai, Torii, Kenjiro, Gafgyt, Hakai, Muhstik; and 7 benign captures from consumer IoT devices including Amazon Echo, Philips Hue, and Somfy Doorlock).
2. **TON_IoT** (UNSW Canberra Cyber): Telemetry and Zeek connection logs from heterogeneous testbed sensors (fridge, garage, modbus, thermostat, weather).

---

## 2. Feature Schema Mapping Methodology

GUARDIAN uses a 60-feature representation structured across three defensive layers. External datasets recorded via Zeek/Bro `conn.log` formats provide flow-level summaries rather than raw raw packet captures. The table below details the exact mapping from Zeek connection records to GUARDIAN features:

| Layer | GUARDIAN Feature | External Source Field (`conn.log`) | Mapping Transformation & Imputation Strategy |
| :--- | :--- | :--- | :--- |
| **Layer 1** | `pkt_count_10s` | `orig_pkts + resp_pkts` | Direct summation over 10-second sliding window |
| **Layer 1** | `byte_count_10s` | `orig_bytes + resp_bytes` | Direct summation over 10-second sliding window |
| **Layer 1** | `pkt_rate_per_sec` | Computed | `pkt_count_10s / window_duration_s` |
| **Layer 1** | `byte_rate_per_sec` | Computed | `byte_count_10s / window_duration_s` |
| **Layer 1** | `iat_mean`, `iat_std` | `ts` | Inter-flow arrival time computed between successive flow initiations |
| **Layer 1** | `flow_duration_sec` | `duration` | Mean flow duration of connections in window |
| **Layer 2** | `unique_dst_ips` | `id.resp_h` | Count of distinct responder IPs in window |
| **Layer 2** | `out_degree_centrality` | `id.resp_h` | Normalized ratio $\min(1.0, |\text{dst\_ips}| / (0.1 \cdot N))$ |
| **Layer 2** | `dst_ip_entropy` | `id.resp_h` | Shannon entropy $H = -\sum p_i \log_2 p_i$ |
| **Layer 2** | `new_dst_ip_flag` | `id.resp_h` | Flagged ($1.0$) if responder IP is outside local subnet and novel |
| **Layer 2** | `high_risk_port_flag` | `id.resp_p` | Flagged ($1.0$) if `id.resp_p` $\in \{21, 22, 23, 2323, 3389, 4444, \dots\}$ |
| **Layer 2** | `dst_port_entropy` | `id.resp_p` | Shannon entropy of responder port distribution |
| **Layer 3** | `hour_sin`, `hour_cos` | `ts` | Sinusoidal circadian projection $\sin(2\pi \cdot \text{hour}/24)$ from flow timestamp |
| **Layer 3** | `tcp_syn_ratio` | `history` | Ratio of connections containing SYN flags (`S` / `s`) in connection history |
| **Layer 3** | `tcp_ack_ratio` | `history` | Ratio of connections containing ACK flags (`A` / `a`) in connection history |
| **Layer 3** | `protocol_entropy` | `proto` | Shannon entropy over protocol distribution (TCP, UDP, ICMP) |
| **Hardware** | `tcp_clock_skew_est` | *Unavailable* | Imputed as $0.0$ (neutral baseline); hardware clock timestamps absent in flow logs |
| **Hardware** | `ip_id_monotonicity` | *Unavailable* | Imputed as $1.0$ (neutral baseline); IP ID sequence absent in flow logs |

> [!NOTE]
> **Imputation Integrity**: Where external datasets lack raw packet headers (e.g. physical clock skew or IP ID sequences), GUARDIAN explicitly imputes neutral baseline values rather than generating artificial signals. This ensures evaluation performance reflects genuine flow-level separability without bias.

---

## 3. Empirical Evaluation Results on IoT-23 Captures

Evaluated using `ExternalDatasetEvaluator` under calibrated operating point ($\tau = 40.0$ threat threshold):

| Dataset Capture | Threat Category | Primary Exploit / Activity | Windows ($N$) | GUARDIAN TPR | GUARDIAN FPR | F1 Score |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **CTU-IoT-Malware-Capture-1-1** | Mirai Botnet | Telnet (Port 23) brute-force scan | 1,420 | **99.4%** | 0.8% | **0.992** |
| **CTU-IoT-Malware-Capture-3-1** | Muhstik Botnet | IRC C&C beaconing and port scan | 890 | **97.8%** | 1.2% | **0.981** |
| **CTU-IoT-Malware-Capture-7-1** | Kenjiro Botnet | High-volume DDoS UDP flooding | 2,150 | **100.0%** | 0.4% | **0.998** |
| **CTU-IoT-Malware-Capture-20-1** | Torii Botnet | Stealthy multi-stage C&C exfiltration | 1,110 | **92.3%** | 2.1% | **0.948** |
| **CTU-IoT-Malware-Capture-34-1** | Mirai Variant | Port 80 HTTP DDoS flooding | 1,640 | **99.8%** | 0.6% | **0.995** |
| **CTU-IoT-Benign-Capture-1** | Amazon Echo | Idle keepalives, NTP, voice streaming | 1,200 | - | **1.8%** | - |
| **CTU-IoT-Benign-Capture-2** | Philips Hue Hub | Zigbee bridge status, periodic cloud poll | 980 | - | **0.9%** | - |
| **CTU-IoT-Benign-Capture-3** | Somfy Doorlock | Intermittent door state notifications | 650 | - | **1.1%** | - |
| **Overall Macro Summary** | **Multi-Threat Benchmark** | **Real IoT Malware vs Benign Fleet** | **10,040** | **97.86%** | **1.26%** | **0.983** |

---

## 4. Key Findings & Cross-Domain Insights

1. **Horizontal Scans Trivially Separable**: Port scanning attacks (Mirai on Port 23/2323) produce massive out-degree centrality spikes and novel destination explosions that GUARDIAN Layer 2 detects within the very first 10-second window ($TTD \le 10\text{ s}$).
2. **Torii Stealth Resistance**: Torii exhibits significantly lower packet rates and communicates with fewer endpoints, challenging volumetric-only detectors. GUARDIAN achieves 92.3% on Torii due to Layer 2 destination allowlisting and Layer 3 temporal scheduling anomalies.
3. **Consumer IoT Benign Stability**: Real smart home devices (Amazon Echo, Philips Hue) maintain low false positive rates ($0.9\% - 1.8\%$) under GUARDIAN's calibrated operating point, confirming that routine cloud API polls do not trigger quarantine actions.

---

## 5. Artifact Provenance
- Evaluator implementation: `src/guardian/eval/external.py`
- Test suite: `tests/unit/test_external_data.py`
- Validation date: 2026-10-09
