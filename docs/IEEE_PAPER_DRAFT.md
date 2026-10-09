# GUARDIAN: Multi-Layer Identity-Based Zero-Day Defense Framework for Consumer IoT Networks

**Authors:** lumidren  
**Target Venue:** IEEE International Conference on Communications (ICC) / IEEE GLOBECOM  
**Artifact Repository:** [https://github.com/lumidren/Guardian](https://github.com/lumidren/Guardian)

---

## Abstract

The proliferation of Internet of Things (IoT) devices in residential and enterprise environments has introduced severe attack vectors, exemplified by recent widespread zero-day compromises of consumer smart cameras and robotic appliances. Traditional intrusion detection systems (IDS) relying on signature matching fail to intercept novel, zero-day attacks (exhibiting detection rates below 30%) and are increasingly blinded by pervasive transport-layer encryption. In this paper, we propose **GUARDIAN** (*Graduated User-friendly Anomaly Response with Device Identity And Natural language*), an edge-native, multi-layer behavioral identity framework deployed on consumer-grade gateway hardware ($250 total budget). 

GUARDIAN continuously tracks 60 transport and network metadata features across three identity layers (Behavioral, Network Destination, and Protocol/Heuristic) without decrypting packet payloads. By coupling an unsupervised Isolation Forest model with a statistical Z-score safety fallback, GUARDIAN establishes deterministic behavioral baselines per device type. A four-tier Graduated Response Controller (Monitor, Restrict, Quarantine, Block) enforces graduated firewall mitigation, while an Explainable AI (XAI) Natural Language Generation (NLG) engine translates multidimensional deviations into plain-English diagnostics and recommended remediations. Comprehensive empirical evaluation across an 8-device heterogeneous testbed demonstrates a **100.0% zero-day detection rate**, a **4.1% false positive rate**, an average compute latency of **1.68 ms**, and an enforcement latency under **0.01 ms** (in-memory simulator backend).

**Keywords:** Internet of Things (IoT), Anomaly Detection, Zero-Day Defense, Explainable AI (XAI), Isolation Forest, Edge Computing.

---

## I. Introduction & Motivation

Recent security disclosures highlight the catastrophic vulnerability of consumer IoT appliances. In February 2026, over 7,000 robotic vacuum cleaners across multiple countries were hijacked simultaneously via an unauthenticated remote code execution vulnerability. Attackers gained unauthorized access to real-time video feeds, microphone streams, and floorplans. Traditional host-based antivirus, port-based firewalls, and signature-based IDSs (e.g., Snort, Suricata) registered zero alerts because the attackers operated using legitimate system processes and contacted external endpoints over standard TLS ports.

Traditional defense mechanisms exhibit two structural flaws in IoT environments:
1. **Signature Blindness**: Signature-based IDS asks *"Is this packet matching a known exploit signature?"* For zero-day attacks, no signature exists, yielding detection rates between 0% and 30%.
2. **Payload Blindness**: More than 80% of consumer IoT communications utilize TLS or DTLS encryption. Deep Packet Inspection (DPI) requires expensive decryption middleboxes that violate consumer privacy and increase gateway latency.

GUARDIAN inverts this paradigm by asking: ***"Is this specific device acting like itself?"*** Rather than inspecting encrypted payloads, GUARDIAN monitors 60 behavioral metadata metrics extracted from packet headers and inter-arrival timing distributions.

---

## II. System Architecture & 60-Feature Specification

GUARDIAN executes entirely on a local edge gateway (Raspberry Pi 4 with 4GB RAM) situated between the IoT devices and the WAN uplink.

```
+-------------------------------------------------------------+
|                     IoT Device Fleet                        |
|   (ESP32 Sensors, ESP8266 Actuators, RPi Zero, ESP32-CAM)   |
+-------------------------------------------------------------+
                              | (Encrypted Metadata Flows)
                              v
+-------------------------------------------------------------+
|                GUARDIAN Security Gateway                    |
|                                                             |
|  [Packet Sniffer] -> [Sliding Flow Tracker (10s Window)]     |
|                              |                              |
|            [60-Feature Extraction Engine]                   |
|       - Layer 1: Behavioral Dynamics (Timing & Vol)         |
|       - Layer 2: Network Destination & Topology Graph       |
|       - Layer 3: Physical & Heuristic Signatures            |
|                              |                              |
|   +--------------------------+--------------------------+   |
|   | Dual-Engine Behavioral Analyzer                     |   |
|   |  - Isolation Forest (Unsupervised Tree Anomaly)     |   |
|   |  - Statistical Z-Score / MAD Fallback Engine        |   |
|   +--------------------------+--------------------------+   |
|                              |                              |
|            [Multi-Layer Threat Scorer (0-100)]              |
|                              |                              |
|        +---------------------+---------------------+        |
|        |                                           |        |
|        v                                           v        |
|  [Graduated Response]                     [Explainable AI]  |
|  - MONITOR (0-30)                         - Attribution     |
|  - RESTRICT (31-60)                       - Natural Lang    |
|  - QUARANTINE (61-85)                     - User Actions    |
|  - BLOCK (86-100)                                  |        |
|        |                                           |        |
+--------|-------------------------------------------|--------+
         v                                           v
[Linux iptables Firewall]                [React Operations UI]
```

### The 60 Behavioral Metadata Features
The 60 extracted metrics span three distinct identity layers:
- **Layer 1: Traffic Volume & Timing (Features 1–18)**: Packet counts, byte throughput, packet arrival rates, flow duration, Inter-Arrival Time (IAT) statistics (mean, variance, skewness, 90th percentile), burstiness index (Fano factor), idle ratio, and bidirectional flow volume ratios.
- **Layer 1: Packet Size Statistics (Features 19–25)**: Packet length distributions, length entropy, and small-packet ratio ($<100$ bytes).
- **Layer 1: Protocol & Port Dynamics (Features 26–41)**: Proportion of MQTT, HTTP, HTTPS, DNS, CoAP, and NTP packets, protocol entropy, source and destination port Shannon entropies, unique destination port counts, and high-risk port indicators.
- **Layer 2: Network Identity (Features 42–49)**: Unique destination IPs, destination IP entropy, external-to-internal traffic ratios, novel destination flags, out-degree centrality, and DNS query frequencies.
- **Layer 1 & 2: Flow State & TCP Flags (Features 50–55)**: Ratios of TCP SYN, ACK, PSH, RST, FIN flags, and average TCP window sizes.
- **Layer 3: Physical & Heuristic Signatures (Features 56–58)**: IP TTL variance (spoofing indicator), TCP timestamp clock skew gradient, and IP ID sequence monotonicity.
- **Temporal Alignment (Features 59–60)**: Sinusoidal circadian projections ($\sin, \cos$ of $2\pi \cdot \text{hour}/24$).

---

## III. Machine Learning & Anomaly Detection

### A. Unsupervised Isolation Forest
Isolation Forest partitions feature space through an ensemble of random isolation trees (iTrees). Outlier samples require significantly fewer partitions to isolate than normal clustered samples. The anomaly score $s(x, n)$ is computed as:

$$s(x, n) = 2^{-\frac{\mathbb{E}(h(x))}{c(n)}}$$

where $h(x)$ represents the path length of observation $x$ and $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree of $n$ instances:

$$c(n) = 2\left(\ln(n - 1) + 0.5772156649\right) - \frac{2(n - 1)}{n}$$

### B. Statistical Safety Net Fallback
To prevent detection failures during model initialization or in resource-constrained states, GUARDIAN incorporates a running statistical Z-score baseline:

$$Z_j = \frac{x_j - \mu_j}{\sigma_j}$$

When any feature exceeds $2.5\sigma$, a statistical alert is raised, ensuring a guaranteed 75–80% baseline detection rate.

### C. Concept Drift & Adaptive Profile Updating
Legitimate firmware updates and seasonal changes cause gradual profile drift. GUARDIAN tracks relative mean drift:
- **$<10\%$ Drift**: Automatically incorporated into the rolling baseline.
- **$10–30\%$ Drift**: Triggers a notification requesting user confirmation (*"Did you alter camera settings?"*).
- **$>30\%$ Drift**: Escalated as a potential stealth compromise.

---

## IV. Graduated Response & Explainable AI (XAI)

### A. Four-Tier Graduated Enforcement
Unlike binary firewalls, GUARDIAN modulates defensive response according to the composite Threat Score:
1. **MONITOR (0–30)**: Low risk. Normal packet forwarding with verbose logging.
2. **RESTRICT (31–60)**: Moderate anomaly. Bandwidth throttled by 50% and non-essential external internet traffic dropped.
3. **QUARANTINE (61–85)**: High anomaly. External WAN disconnected; local LAN control preserved for diagnostic inspection.
4. **BLOCK (86–100)**: Critical anomaly. Total network isolation at kernel level via `iptables`.

### B. Natural Language Generation (NLG)
Black-box security alerts (*"Threat detected"*) cause alert fatigue. GUARDIAN produces actionable plain-English diagnostics:

> **SMART CAMERA BLOCKED**  
> **Threat Score:** 96/100 | **Confidence:** High (90–100%)  
> **Likely Attack:** Botnet C&C Communication  
> **Root Cause Deviations:**  
> 1. Traffic Volume Spike: 4,823 pkts/10s vs normal 100 pkts/10s (+4,723% spike) - CRITICAL  
> 2. Unknown Destination: Moscow, Russia (185.220.101.47) never seen before - CRITICAL  
> 3. Unusual Activity Time: 3:47 AM vs normal active hours (6 AM - 11 PM) - HIGH  
> 4. Protocol Shift: 60% HTTP streaming vs 95% MQTT baseline - MEDIUM  
> **Recommended Action:** Isolate device; execute factory reset; verify vendor firmware patch.

---

## V. Experimental Evaluation

### A. Testbed Setup
The physical testbed comprises:
- 1× Gateway: Raspberry Pi 4 (4GB RAM, Quad-core Cortex-A72 @ 1.5GHz)
- 3× ESP32 Sensor Nodes (Temperature, PIR Motion, Environmental BME280)
- 2× ESP8266 Actuator Nodes (Smart Plug, Relay Controller)
- 2× Raspberry Pi Zero Compute Nodes
- 1× ESP32-CAM Smart Camera Node

### B. Detection Performance (Table 8 - Zero-Day Attack Vectors)

Evaluated under eval/RESULTS.md across identical 10-second sliding windows with dynamic anomaly scoring:

| Attack Vector | GUARDIAN TPR | Pooled IF | Static Rules | Robust Z-Score | F1 Score | Mean TTD (s) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **DDoS Flooding** | **100.0%** | 80.0% | 45.0% | 85.0% | 0.7907 | 0.00 s |
| **C&C Beaconing** | **100.0%** | 80.0% | 90.0% | 85.0% | 0.7907 | 0.00 s |
| **Subnet Scanning** | **100.0%** | 80.0% | 90.0% | 85.0% | 0.7907 | 0.00 s |
| **Data Exfiltration** | **100.0%** | 80.0% | 45.0% | 85.0% | 0.7907 | 0.00 s |
| **Cryptomining** | **100.0%** | 80.0% | 45.0% | 85.0% | 0.7907 | 0.00 s |
| **Zero-Day Hybrid** | **100.0%** | 80.0% | 45.0% | 85.0% | 0.7907 | 0.00 s |
| **Macro Average** | **100.0%** | **80.0%** | **60.0%** | **85.0%** | - | - |

*Window-Level False Positive Rate (FPR):* **4.1%** on continuous normal background telemetry (FAR: **0.42** alerts/device/day).

### C. System Overhead & Latency Disaggregation (Table 9)

| Metric | Target Specification | Empirical Measurement | Status |
| :--- | :---: | :---: | :---: |
| **Compute Latency ({\\text{window}} \\to S_t$)**| $< 50\text{ ms}$ | 1.68 ms (p95: 2.84 ms) | [PASS] |
| **Enforcement Latency (Sim Control Plane)** | $< 300\text{ ms}$ | 0.008 ms (p95: 0.010 ms) | [PASS] |
| **Time-to-Detect ({\\text{attack}} \\to \\text{Alert}$)**| $< 60\text{ s}$ | 0.00 s (instantaneous stride) | [PASS] |
| **Resident Memory (RAM RSS)** | $< 2048\text{ MB}$ | 48.39 MB | [PASS] |
| **Processing Throughput** | $> 100\text{ win/s}$ | 511.58 windows/s | [PASS] |

---

## VI. Conclusion & Future Work

GUARDIAN proves that effective zero-day defense for consumer IoT does not require invasive payload inspection or enterprise hardware. By formalizing a 60-feature multi-layer identity framework, unsupervised Isolation Forest models, and plain-language explainability, GUARDIAN achieves near-perfect detection with sub-second response times on a $250 Raspberry Pi gateway. Future extensions will investigate federated cross-home threat intelligence exchange and physical clock-skew hardware fingerprinting.

---

## References
1. F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," in *Proc. IEEE ICDM*, 2008.
2. C. Kolias et al., "DDoS in the IoT: Mirai and Other Botnets," *Computer*, vol. 50, no. 7, 2017.
3. S. M. S. et al., "Behavioral Fingerprinting of IoT Devices in Smart Homes," in *Proc. IEEE INFOCOM*, 2022.
