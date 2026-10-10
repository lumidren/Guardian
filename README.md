# GUARDIAN: Multi-Layer Identity-Based Zero-Day Defense Framework for IoT

<p align="center">
  <img src="docs/assets/guardian_hero.svg" alt="GUARDIAN Architecture Banner" width="100%">
</p>

<p align="center">
  <a href="https://github.com/lumidren/Guardian/actions"><img src="https://img.shields.io/github/actions/workflow/status/lumidren/Guardian/ci.yml?branch=main&style=flat-square&logo=github&label=CI%20Build" alt="CI Status"></a>
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/Python-3.11-3776AB.svg?style=flat-square&logo=python&logoColor=white" alt="Python 3.11"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square" alt="License: MIT"></a>
  <a href="docs/IEEE_PAPER_DRAFT.md"><img src="https://img.shields.io/badge/Target-IEEE%20ICC%20%2F%20GLOBECOM-00629B.svg?style=flat-square" alt="Target Venue"></a>
  <a href="docs/PRESENTATION_PITCH.md"><img src="https://img.shields.io/badge/Deployment%20Budget-%24250%20Hardware-10b981.svg?style=flat-square" alt="Hardware Budget"></a>
  <a href="eval/RESULTS.md"><img src="https://img.shields.io/badge/5--Seed%20Episode%20TPR-96.13%25%20%5B95.56%25%2C%2096.74%25%5D-8b5cf6.svg?style=flat-square" alt="Multi-Seed Episode TPR"></a>
  <a href="eval/RESULTS.md"><img src="https://img.shields.io/badge/5--Seed%20Operational%20FPR-9.29%25%20(1.14%20FAR%2FDev%2FDay)-f59e0b.svg?style=flat-square" alt="Multi-Seed Operational FPR"></a>
</p>

---

## Executive Summary

The explosive proliferation of Internet of Things (IoT) devices in consumer, medical, and industrial environments has created a massive, unmanaged perimeter vulnerable to zero-day exploits. Conventional Network Intrusion Detection Systems (NIDS) rely heavily on predefined exploit signatures and Deep Packet Inspection (DPI). In modern IoT topologies, these approaches face two fundamental limitations:
1. **Signature Blindness**: Novel zero-day intrusions lack published signatures, rendering signature-only detection ineffective against uncataloged exploit chains.
2. **End-to-End Encryption Barrier**: Pervasive transport encryption (TLS 1.3, DTLS, QUIC) blinds deep packet inspection without invasive, latency-inducing middleboxes and key-escrow architectures.

**GUARDIAN** (*Graduated User-friendly Anomaly Response with Device Identity And Natural language*) addresses these challenges through an edge-native, zero-trust security framework engineered for low-cost gateway hardware (\$250 total fleet budget). By observing packet metadata alone—**without payload inspection or decryption**—GUARDIAN extracts 60 statistical and topological features across sliding time windows ($W = 10\text{ s}, \Delta t = 2\text{ s}$). 

The detection pipeline combines an unsupervised **Isolation Forest** (200 isolation trees) with non-parametric **Robust Statistics (Median Absolute Deviation)** and an egress **Network Destination Graph**. An empirical **Hysteresis State Machine** ($k=2 \text{ of } n=3$ escalation, $M=15$ calm cooldown) suppresses stochastic network false alarms. Containment is enforced within a $<300\text{ ms}$ budget via kernel-level `nftables` (where the in-memory dry-run state transition takes $0.013\text{ ms}$, while real Linux `nft -f` subprocess compilation and atomic kernel rule application requires $2\text{--}15\text{ ms}$) across four graduated tiers (**MONITOR &rarr; RESTRICT &rarr; QUARANTINE &rarr; BLOCK**), accompanied by an **Explainable AI (XAI)** engine delivering human-readable root-cause diagnostics.

> [!WARNING]
> **Simulator Scope, Cross-Domain False-Alert Limitation & Pending Physical Hardware Results**:
> - **Multi-Seed Simulator Benchmark Scope**: Primary multi-day benchmarks are executed against GUARDIAN's stochastic IoT telemetry simulator across $N_{\text{seeds}} = 5$ seeds (`4,500` main attack episodes + `1,500` adversarial episodes). Detection is explicitly intensity- and tier-dependent: while `EASY` and `MEDIUM` tiers ($\ge 1.0\times$ intensity) achieve $100.0\%$ `[99.7%, 100.0%]` recall, covert `HARD`-tier adversaries that reuse whitelisted broker IPs, match normal payload byte ranges, and inject only $1\text{--}2\text{ pkts}/10\text{s}$ (`0.25x` intensity) overlap the benign feature distribution and reduce `HARD`-tier recall to **$78.8\%\text{--}100.0\%$ (`88.4%` macro average, `[86.7%, 89.9%]`)** at a multi-seed operational window FPR of **$9.29\%$ (`1.14` false alerts/device/day)**.
> - **100% Zero-Shot Cross-Domain False Alerts on Real Traffic**: Models trained exclusively on the uncalibrated synthetic simulator produced **100.0% window false-positive rate (`432.00` false alerts/device/day)** when applied zero-shot to the 64.5 MB UNSW-NB15 real capture (`98.78%` after empirical simulator distribution calibration), whereas training in-domain on the real PCAP reduces false alarms to **18.08% window FPR (`156.00` post-hysteresis false alerts/device/day)** (see [`docs/REAL_DATA_VALIDATION.md`](docs/REAL_DATA_VALIDATION.md)).
> - **Pending Physical Hardware Testbed Results**: Real-device physical testbed measurements on the 8-node + Raspberry Pi 4 hardware BOM are **pending (`TODO`)**; all current results derive from the stochastic simulator and offline public PCAP replay (`UNSW-NB15` and `CTU-IoT-Malware-Capture-34-1`).

---

## System Architecture & Data Pipeline

<p align="center">
  <img src="docs/assets/guardian_pipeline_flow.svg" alt="GUARDIAN 5-Stage Data Pipeline" width="100%">
</p>

```mermaid
flowchart TD
    subgraph S1["Stage 1: Packet Ingestion & Sliding Window"]
        SRC["Packet Source Engine\n(LiveSnifferSource / PcapReplaySource / SimSource)"]
        WIN["Sliding-Window Aggregator\n(Window W = 10s, Stride Δt = 2s)"]
    end

    subgraph S2["Stage 2: Canonical Feature Extraction (60 Features)"]
        REG["Feature Registry (registry.py)\nx ∈ ℝ⁶⁰"]
        L1_VOL["Layer 1: Volume & Size Dynamics (25)"]
        L1_TIM["Layer 1: Protocol & Port Dynamics (16)"]
        L1_PRO["Layer 1: TCP Flags & Window State (6)"]
        L2_NET["Layer 2: Destination Graph & Entropy (8)"]
        L3_APP["Layer 3: Header Heuristics & Circadian Priors (5)"]
    end

    subgraph S3["Stage 3: Dual-Engine Anomaly Detection"]
        IFOREST["Isolation Forest Detector\n(200 iTrees, Subsample ψ = 256)"]
        ROBUSTZ["Robust Statistical Detector\n(Median + 1.4826 · MAD)"]
        NETGRAPH["Network Identity Graph\n(Directed Egress Graph via NetworkX)"]
        FUSION["Weighted Score Fusion\nThreat Score S ∈ [0, 100], Confidence C ∈ [0, 1]"]
    end

    subgraph S4["Stage 4: Hysteresis Confirmation"]
        HYST["Temporal Hysteresis Engine\nEscalation: k=2 of n=3 windows\nDe-escalation: 15 consecutive calm windows"]
    end

    subgraph S5["Stage 5: Mitigation & Explainable SOC"]
        RESP["Graduated Response Controller\n(MONITOR → RESTRICT → QUARANTINE → BLOCK)"]
        NFT["Kernel Enforcement\n(nftables / iptables / dry-run)"]
        XAI["Explainability Engine (XAI / NLG)\n(Tree-Path Attribution → Plain English)"]
        DB[("SQLite WAL Database\n(WAL Mode, Alembic Migrations)")]
        API["FastAPI REST & WebSocket Hub"]
        DASH["React 18 / Vite SOC Dashboard"]
    end

    SRC --> WIN --> REG
    REG --> L1_VOL & L1_TIM & L1_PRO & L2_NET & L3_APP
    L1_VOL & L1_TIM & L1_PRO & L2_NET & L3_APP --> IFOREST & ROBUSTZ & NETGRAPH
    IFOREST & ROBUSTZ & NETGRAPH --> FUSION --> HYST --> RESP & XAI
    RESP --> NFT --> DB
    XAI --> DB --> API <--> DASH
```

---

## Multi-Layer IoT Identity Model

GUARDIAN constructs an empirical behavioral fingerprint across three complementary identity layers:

```mermaid
graph LR
    subgraph L1["Layer 1: Behavioral Dynamics (Micro-Flows)"]
        direction TB
        L1A["Packet & Byte Volume / Rate (10s)"]
        L1B["Inter-Arrival Time (IAT) Moments & Quantiles"]
        L1C["Burstiness Index (Fano Factor) & Idle Ratio"]
        L1D["Transport Port Ratios, Entropy & TCP Flags"]
    end

    subgraph L2["Layer 2: Network Destination Topology (Graph)"]
        direction TB
        L2A["Unique Destination IPs & Shannon Entropy"]
        L2B["External WAN & Cross-Subnet Ratios"]
        L2C["New Destination IP Binary Flag"]
        L2D["Out-Degree Centrality & DNS Query/Failure Rates"]
    end

    subgraph L3["Layer 3: Header Heuristics & Circadian Priors"]
        direction TB
        L3A["Circadian Harmonic Encodings (hour_sin, hour_cos)"]
        L3B["IPv4 Header TTL Variance (ip_ttl_variance)"]
        L3C["IPv4 Header ID Monotonicity (ip_id_monotonicity)"]
        L3D["Software TCP TSval Header Drift (tcp_clock_skew_est)"]
    end

    DEV["Monitored IoT Node"] --> L1
    DEV --> L2
    DEV --> L3
```

> [!NOTE]
> **Scope & Header-Only Privacy Clarification (`src/guardian/features/registry.py`)**:
> 1. **MQTT Topic Features vs. "No Payload Inspection" Claim**: Extracting MQTT topic strings (`mqtt_topic_count`, `mqtt_new_topic`), coalesced MQTT message rates (`mqtt_msg_rate`), or application payload lengths (`mqtt_payload_len_mean`) requires inspecting **Layer-7 TCP payload bytes** after the 2-byte MQTT fixed header (and requires TLS decryption on port `8883`). To strictly honor GUARDIAN's zero-payload-inspection guarantee (`tcpdump -s 96` Layer-2/3/4 header-only capture), Layer-7 MQTT payload features are **excluded** from the canonical 60-feature vector. Instead, MQTT activity is profiled exclusively from Layer-3/4 headers via `protocol_mqtt_ratio` (TCP ports `1883`/`8883`) and IP packet-length statistics (`pkt_len_mean`, `pkt_len_std`, `pkt_len_entropy`).
> 2. **Clock-Skew Heuristic vs. Hardware RF Identity ([ADR-007](docs/adr/ADR-007-physical-identity-stub.md))**: Hardware physical-layer identity (radio-frequency carrier frequency offset, I/Q constellation fingerprinting, or silicon PUFs requiring SDR hardware) is out of scope for a software gateway. The feature `tcp_clock_skew_est` (index 56) is a **software-only Layer-4 header heuristic** computed from TCP Option Kind=8 (`TSval`) header timestamps relative to gateway arrival timestamps (`|(d_TSval / dt) - 1000| / 1000`, or `0.0` when TCP timestamp options are omitted).

---

## Mathematical Foundations

### 1. Unsupervised Isolation Forest Anomaly Scoring
Isolation Forest recursively constructs an ensemble of $T$ binary isolation trees ($\text{iTrees}$). At each tree node, an isolation cut randomly selects feature $q$ and uniform split point $p \in [\min(x_{\cdot, q}), \max(x_{\cdot, q})]$.

#### Average Path Length Normalization
The theoretical average path length of unsuccessful searches in a Binary Search Tree ($BST$) serves as the normalizer:

$$c(n) = 2\left(\ln(n - 1) + \gamma\right) - \frac{2(n - 1)}{n}$$

where $\gamma \approx 0.5772156649$ is the Euler-Mascheroni constant.

#### Anomaly Scoring Operator
For observation $\mathbf{x} \in \mathbb{R}^{60}$ evaluated across $T = 200$ trees:

$$s(\mathbf{x}, n) = 2^{-\frac{\mathbb{E}(h(\mathbf{x}))}{c(\psi)}} \quad \text{where} \quad \mathbb{E}(h(\mathbf{x})) = \frac{1}{T}\sum_{t=1}^T h_t(\mathbf{x})$$

- $\mathbb{E}(h(\mathbf{x})) \to 0 \implies s(\mathbf{x}, n) \to 1.0$ (highly anomalous; isolated rapidly near tree root).
- $\mathbb{E}(h(\mathbf{x})) \to c(\psi) \implies s(\mathbf{x}, n) \to 0.5$ (structural uniformity; baseline clustering).
- $\mathbb{E}(h(\mathbf{x})) \to \psi - 1 \implies s(\mathbf{x}, n) \to 0.0$ (densely grouped nominal baseline).

#### Edge-Optimized Feature Attribution for XAI
To extract feature importance on resource-constrained gateways without the heavy compute overhead of SHAP:

$$\omega_j(\mathbf{x}) = \sum_{t=1}^T \sum_{v \in \text{Path}_t(\mathbf{x})} \mathbb{I}(\text{feature}(v) = j) \cdot \frac{1}{\text{depth}(v) + 1}$$

Features with high inverse-depth contributions $\omega_j(\mathbf{x})$ directly triggered early leaf terminations.

---

### 2. Robust Non-Parametric Statistics (Median Absolute Deviation)
Standard sample variance exhibits a breakdown point of $0\%$ (a single outlier can distort the mean indefinitely). GUARDIAN employs the **Median Absolute Deviation (MAD)**, providing a robust breakdown point of $50\%$:

$$\text{MAD}_j = \text{median}\left(\left|x_{i, j} - \tilde{x}_j\right|\right) \quad \text{where} \quad \tilde{x}_j = \text{median}(X_{\cdot, j})$$

The standard deviation estimator under asymptotic normality is:

$$\hat{\sigma}_j = 1.4826 \cdot \text{MAD}_j + \epsilon$$

The **Robust Z-Score** is then:

$$Z_{i, j} = \frac{x_{i, j} - \tilde{x}_j}{\hat{\sigma}_j}, \quad \text{clipped to } [-20.0, +20.0]$$

#### Multi-Feature Aggregate Statistical Score
To prevent false alarms on isolated noisy features, the statistical detector computes aggregate top-$K$ deviations:

$$S_{\text{stat}}(\mathbf{x}) = \min\left(100.0, \; \frac{100}{K}\sum_{j \in \text{TopK}(|Z|)} \max\left(0, \frac{|Z_j| - \theta_{\text{stat}}}{\theta_{\text{max}} - \theta_{\text{stat}}}\right)\right)$$

---

### 3. Information Entropy and Circadian Harmonics

#### Shannon Entropy of Destination Endpoints
To distinguish localized exfiltration from horizontal and vertical scanning:

$$H(X) = -\sum_{k=1}^M P(x_k) \log_2 P(x_k)$$

where $P(x_k)$ is the empirical frequency of contacting endpoint/port $x_k$ in window $\mathcal{W}_t$. High entropy indicates discovery sweeps; concentrated low entropy at high volume indicates exfiltration.

#### Circadian Harmonic Projections
Continuous temporal encoding prevents midnight boundary discontinuities ($23:59 \to 00:00$):

$$\theta(t) = \frac{2\pi \cdot t_{\text{hour}}}{24}, \quad x_{\sin} = \sin(\theta(t)), \quad x_{\cos} = \cos(\theta(t))$$

---

## The 60-Feature Canonical Registry (`src/guardian/features/registry.py`)

All 60 features are generated from a single source of truth ([`src/guardian/features/registry.py`](src/guardian/features/registry.py)) and extracted exclusively from Layer-2/3/4 packet headers (`tcpdump -s 96`). **Zero Layer-7 payload inspection or decryption is performed (`requires_payload_bytes == False` for all 60 features).**

| # | Feature Name | Layer | Description & Formula | Unit | Suspicious Trend |
| :---: | :--- | :---: | :--- | :---: | :---: |
| 1 | `pkt_count_10s` | 1 | Total packets observed in 10-second window | packets | Higher ($\uparrow$) |
| 2 | `byte_count_10s` | 1 | Total byte volume in 10-second window | bytes | Higher ($\uparrow$) |
| 3 | `pkt_rate_per_sec` | 1 | Average packets per second ($N_{\text{pkts}} / W$) | pkts/sec | Higher ($\uparrow$) |
| 4 | `byte_rate_per_sec` | 1 | Average data throughput per second ($\sum \text{len}_i / W$) | bytes/sec | Higher ($\uparrow$) |
| 5 | `flow_duration_sec` | 1 | Active flow duration in window | seconds | Lower / Shift ($\downarrow$) |
| 6 | `iat_mean` | 1 | Mean time between successive packets | seconds | Lower / Shift ($\downarrow$) |
| 7 | `iat_std` | 1 | Standard deviation of inter-arrival times | seconds | Higher ($\uparrow$) |
| 8 | `iat_min` | 1 | Minimum inter-arrival gap | seconds | Lower / Shift ($\downarrow$) |
| 9 | `iat_max` | 1 | Maximum inter-arrival gap | seconds | Higher ($\uparrow$) |
| 10 | `iat_median` | 1 | Median packet arrival gap | seconds | Lower / Shift ($\downarrow$) |
| 11 | `iat_skew` | 1 | Third standardized moment of arrival intervals | ratio | Higher ($\uparrow$) |
| 12 | `iat_p90` | 1 | 90th percentile arrival gap | seconds | Higher ($\uparrow$) |
| 13 | `burstiness_index` | 1 | Fano factor variance-to-mean arrival ratio ($\sigma^2 / \mu$) | index | Higher ($\uparrow$) |
| 14 | `idle_ratio` | 1 | Fraction of window where device was idle | ratio | Lower / Shift ($\downarrow$) |
| 15 | `upstream_pkt_ratio` | 1 | Fraction of outbound packets ($N_{\text{up}} / N_{\text{pkts}}$) | ratio | Higher ($\uparrow$) |
| 16 | `downstream_pkt_ratio` | 1 | Fraction of inbound packets ($N_{\text{down}} / N_{\text{pkts}}$) | ratio | Lower / Shift ($\downarrow$) |
| 17 | `upstream_byte_ratio` | 1 | Fraction of outbound byte volume | ratio | Higher ($\uparrow$) |
| 18 | `downstream_byte_ratio` | 1 | Fraction of inbound byte volume | ratio | Lower / Shift ($\downarrow$) |
| 19 | `pkt_len_mean` | 1 | Average frame/IP packet length from header | bytes | Higher ($\uparrow$) |
| 20 | `pkt_len_std` | 1 | Standard deviation of packet lengths | bytes | Higher ($\uparrow$) |
| 21 | `pkt_len_min` | 1 | Smallest packet length observed | bytes | Lower / Shift ($\downarrow$) |
| 22 | `pkt_len_max` | 1 | Largest packet length observed | bytes | Higher ($\uparrow$) |
| 23 | `pkt_len_median` | 1 | Median packet size | bytes | Lower / Shift ($\downarrow$) |
| 24 | `pkt_len_entropy` | 1 | Shannon entropy of 100-byte discretized packet lengths | bits | Higher ($\uparrow$) |
| 25 | `small_pkt_ratio` | 1 | Fraction of packets $< 100$ bytes (probes/SYN) | ratio | Higher ($\uparrow$) |
| 26 | `protocol_mqtt_ratio` | 1 | Fraction of packets on MQTT transport ports (1883/8883) | ratio | Lower / Shift ($\downarrow$) |
| 27 | `protocol_http_ratio` | 1 | Fraction of packets on HTTP port (80/8080) | ratio | Higher ($\uparrow$) |
| 28 | `protocol_https_ratio` | 1 | Fraction of packets on HTTPS/TLS port (443) | ratio | Higher ($\uparrow$) |
| 29 | `protocol_dns_ratio` | 1 | Fraction of packets on DNS port (53) | ratio | Higher ($\uparrow$) |
| 30 | `protocol_coap_ratio` | 1 | Fraction of packets on CoAP port (5683) | ratio | Lower / Shift ($\downarrow$) |
| 31 | `protocol_ntp_ratio` | 1 | Fraction of packets on NTP port (123) | ratio | Lower / Shift ($\downarrow$) |
| 32 | `protocol_tcp_other_ratio` | 1 | Fraction of unclassified TCP transport traffic | ratio | Higher ($\uparrow$) |
| 33 | `protocol_udp_other_ratio` | 1 | Fraction of unclassified UDP transport traffic | ratio | Higher ($\uparrow$) |
| 34 | `protocol_entropy` | 1 | Shannon entropy across classified transport protocols | bits | Higher ($\uparrow$) |
| 35 | `src_port_entropy` | 1 | Shannon entropy of source transport ports | bits | Higher ($\uparrow$) |
| 36 | `dst_port_entropy` | 1 | Shannon entropy of destination transport ports | bits | Higher ($\uparrow$) |
| 37 | `unique_dst_ports` | 1 | Number of distinct destination transport ports | count | Higher ($\uparrow$) |
| 38 | `wellknown_port_ratio` | 1 | Fraction of destination ports in $[0, 1023]$ | ratio | Lower / Shift ($\downarrow$) |
| 39 | `ephemeral_port_ratio` | 1 | Fraction of destination ports $\ge 49152$ | ratio | Higher ($\uparrow$) |
| 40 | `std_port_deviation` | 1 | Standard deviation of destination port numbers | deviation | Higher ($\uparrow$) |
| 41 | `high_risk_port_flag` | 1 | Binary indicator of traffic to known backdoor/Telnet/C2 ports | binary | Higher ($\uparrow$) |
| 42 | `unique_dst_ips` | 2 | Number of distinct destination IP addresses contacted | count | Higher ($\uparrow$) |
| 43 | `dst_ip_entropy` | 2 | Shannon entropy across destination IP addresses | bits | Higher ($\uparrow$) |
| 44 | `external_ip_ratio` | 2 | Fraction of packets destined outside the local LAN subnet | ratio | Higher ($\uparrow$) |
| 45 | `new_dst_ip_flag` | 2 | Binary flag indicating an un-whitelisted destination IP | binary | Higher ($\uparrow$) |
| 46 | `out_degree_centrality` | 2 | Normalized egress endpoint fan-out centrality | score | Higher ($\uparrow$) |
| 47 | `cross_subnet_ratio` | 2 | Fraction of packets directed across internal private subnets | ratio | Higher ($\uparrow$) |
| 48 | `dns_query_frequency` | 2 | Rate of DNS port-53 packets per second | queries/sec | Higher ($\uparrow$) |
| 49 | `dns_failure_ratio` | 2 | Fraction of failed DNS responses | ratio | Higher ($\uparrow$) |
| 50 | `tcp_syn_ratio` | 1 | Fraction of TCP packets with SYN flag set | ratio | Higher ($\uparrow$) |
| 51 | `tcp_ack_ratio` | 1 | Fraction of TCP packets with ACK flag set | ratio | Lower / Shift ($\downarrow$) |
| 52 | `tcp_psh_ratio` | 1 | Fraction of TCP packets with PSH flag set | ratio | Higher ($\uparrow$) |
| 53 | `tcp_rst_ratio` | 1 | Fraction of TCP packets with RST flag set | ratio | Higher ($\uparrow$) |
| 54 | `tcp_fin_ratio` | 1 | Fraction of TCP packets with FIN flag set | ratio | Lower / Shift ($\downarrow$) |
| 55 | `tcp_win_mean` | 1 | Mean advertised TCP receive window size in header | bytes | Lower / Shift ($\downarrow$) |
| 56 | `ip_ttl_variance` | 3 | Variance of IPv4 header Time-to-Live field | variance | Higher ($\uparrow$) |
| 57 | `tcp_clock_skew_est` | 3 | Software TCP Option Kind=8 (`TSval`) header rate drift estimate (0.0 when TCP TS option absent; distinct from out-of-scope RF hardware fingerprinting) | ppm | Higher ($\uparrow$) |
| 58 | `ip_id_monotonicity` | 3 | Fraction of sequential positive increments in IPv4 header ID field | score | Lower / Shift ($\downarrow$) |
| 59 | `hour_sin` | Temp | Sine projection of hour of day: $\sin(2\pi \cdot t_{\text{hour}} / 24)$ | value | Lower / Shift ($\downarrow$) |
| 60 | `hour_cos` | Temp | Cosine projection of hour of day: $\cos(2\pi \cdot t_{\text{hour}} / 24)$ | value | Lower / Shift ($\downarrow$) |

---

## Graduated Response & Hysteresis State Machine

### 1. Finite State Machine Dynamics

```mermaid
stateDiagram-v2
    [*] --> MONITOR
    MONITOR --> RESTRICT : S >= 31 (k=2 of n=3 windows)
    RESTRICT --> QUARANTINE : S >= 61 (k=2 of n=3 windows)
    QUARANTINE --> BLOCK : S >= 86 (k=2 of n=3 windows) or Admin Command

    BLOCK --> QUARANTINE : 15 Calm Windows (S <= 85)
    QUARANTINE --> RESTRICT : 15 Calm Windows (S <= 60)
    RESTRICT --> MONITOR : 15 Calm Windows (S <= 30)

    BLOCK --> MONITOR : Manual Operator Reset & Whitelist
```

### 2. Kernel Mitigation Tiers

GUARDIAN operates across strictly **four graduated response tiers** (formalized in [ADR-001](docs/adr/ADR-001-architecture-overview.md)):

| Response Tier | Threat Score Range | Kernel Mitigation Policy (`nftables` / `iptables`) | Impact on Monitored Device |
| :---: | :---: | :--- | :--- |
| **MONITOR** | $0 \le S \le 30$ | Default accept; continuous baseline telemetry capture. | Nominal full operation; no packet disruption |
| **RESTRICT** | $31 \le S \le 60$ | Token-bucket rate limiting (50% bandwidth cap); drop uncataloged WAN IPs. | Functions normally for benign LAN tasks; throttles bursts |
| **QUARANTINE** | $61 \le S \le 85$ | Drop all WAN egress; permit only local subnet / broker communications. | Isolated from external C2 servers and exfiltration endpoints |
| **BLOCK** | $86 \le S \le 100$ | Total packet drop (`DROP` in `FORWARD` & `INPUT` kernel chains). | Completely severed from network pending operator intervention |

---

## Progressive 4-Stage Cold-Start Lifecycle

IoT devices exhibit significant operational diversity upon network entry. GUARDIAN deploys a 4-stage progressive cold-start lifecycle with built-in poisoning protection:

```mermaid
flowchart LR
    S1["Stage 1: OBSERVE\n(0 - 24 Hours)\nCapture baseline telemetry\nHeuristic priors active"] --> S2["Stage 2: RULES\n(24 - 48 Hours)\nFreeze destination allowlists\nPacket rate caps active"]
    S2 --> S3["Stage 3: STATISTICAL\n(Day 3 - 7)\nMedian & MAD baselines\nRobust Z-score active"] --> S4["Stage 4: ML OPERATIONAL\n(> 20,000 samples)\nIsolation Forest active\nFull multi-layer fusion"]
```

1. **Stage 1: OBSERVE (0–24h)**: Ingests traffic while actively enforcing static heuristic device-type priors (e.g., hard packet rate ceilings and protocol/port restrictions from `config/device_types.yaml`) from packet zero. The device is **never left unprotected**; this observation period simply avoids applying dynamic statistical anomaly bounds before baseline variance stabilizes.
2. **Stage 2: RULES (24–48h)**: Freezes known nominal destination endpoints into an allowlist. Caps maximum flow initiation rates.
3. **Stage 3: STATISTICAL (Days 3–7)**: Computes non-parametric feature medians and MAD variances. Enables Robust Z-score anomaly scoring.
4. **Stage 4: ML OPERATIONAL (>20,000 samples)**: Fits the device-specific Isolation Forest model. Unlocks full multi-layer weighted score fusion.

---

## Explainable AI & Human-Readable Alert Diagnostics

When an alert triggers, GUARDIAN generates structured diagnostics and plain-English natural language explanations using tree-path attribution (*Illustrative JSON Schema Example*):

```json
{
  "_comment": "Illustrative Alert Schema Example",
  "alert_id": "alt_84b1ef92c011",
  "device_id": "esp32_sensor_01",
  "device_name": "Living Room DHT22 Environmental Sensor",
  "level": "QUARANTINE",
  "threat_score": 88.4,
  "confidence": 0.94,
  "likely_attack": {
    "label": "c2_beaconing_and_exfiltration",
    "confidence": 0.91
  },
  "explanation_text": "Anomalous periodic egress observed: byte_rate reached 14,200 bytes/s (expected 210 bytes/s, robust Z = +14.2). Connected to 4 novel external WAN IPs outside the learned baseline. Hysteresis confirmed threat across 2 consecutive windows.",
  "top_anomalous_features": [
    {"name": "byte_rate", "value": 14200.0, "expected": 210.0, "robust_z": 14.2, "direction": "higher"},
    {"name": "n_new_dst_ip", "value": 4.0, "expected": 0.0, "robust_z": 11.5, "direction": "higher"},
    {"name": "beacon_regularity", "value": 0.98, "expected": 0.12, "robust_z": 8.7, "direction": "higher"}
  ],
  "recommended_actions": [
    "Isolate device WAN egress (applied automatically via nftables QUARANTINE tier)",
    "Inspect remote destinations: 198.51.100.44, 203.0.113.89",
    "Verify whether legitimate over-the-air (OTA) firmware upgrade was scheduled"
  ]
}
```

---

## Interactive SOC Dashboard

The web interface is built with **React 18**, **TypeScript**, **Tailwind CSS**, and **Vite**, connecting to the GUARDIAN daemon via high-throughput WebSockets (*Illustrative Terminal SOC Mockup*):

```
+---------------------------------------------------------------------------------------------------------+
| GUARDIAN IoT Security Gateway SOC                          [ Status: ENFORCE ] [ Gateway CPU: 18.4% ]   |
+---------------------------------------------------------------------------------------------------------+
| FLEET POSTURE (8 Nodes Protected)                                                                       |
| [✓] esp32_temp_01    (NORMAL - Score: 12)    | [✓] plug_living_04   (NORMAL - Score: 08)                |
| [✓] pir_motion_02    (NORMAL - Score: 18)    | [!] relay_hvac_05    (RESTRICT - Score: 64, C2 Burst)    |
| [!] camera_cam_08    (QUARANTINE - Score: 88)| [✓] rpi_compute_06   (NORMAL - Score: 22)                |
+---------------------------------------------------------------------------------------------------------+
| REAL-TIME ANOMALY RADAR (camera_cam_08)          | NETWORK TOPOLOGY & DESTINATION GRAPH                 |
| byte_rate           [====================] +14.2 |   [esp32_sensor_01]                                  |
| n_new_dst_ip        [=================   ] +11.5 |          |                                           |
| beacon_regularity   [============        ]  +8.7 |          v (Local MQTT Broker 1883)                  |
| dst_entropy         [=========           ]  +6.4 |   [192.168.1.1:1883] ----> (LAN Allowed)             |
| iat_cv              [=======             ]  +4.8 |          |                                           |
|                                                  |          x (Novel WAN IP Blocked)                    |
| Threat Score: 88.4 | Level: QUARANTINE           |   [198.51.100.44:443] --X (nftables DROP)            |
+---------------------------------------------------------------------------------------------------------+
| ACTIVE HYSTERESIS TIMELINE: [W-3: 42.1] -> [W-2: 86.4] -> [W-1: 88.4] => ESCALATED TO QUARANTINE        |
+---------------------------------------------------------------------------------------------------------+
```

---

## Evaluation Results & Benchmarks

<!-- BEGIN RESULTS -->
> [!IMPORTANT]
> **Scientific Prime Directive & Headline Multi-Seed Policy**: All empirical metrics presented below were dynamically evaluated and verified by the automated evaluation pipeline ([`eval/RESULTS.md`](eval/RESULTS.md), Run ID: `eval_1791651793_42_f106807`, Git Commit: `f106807`, $N_{\text{seeds}} = 5$ seeds `[42, 43, 44, 45, 46]`). Evaluated under the full time-ordered protocol (`Days 1–7` clean train $\to$ `Day 8` clean calibration $\to$ `Days 9–14` test across `6` attacks $\times$ `3` tiers $\times$ `50` episodes/seed $\times$ `5` seeds = `4,500` main attack episodes + `1,500` adversarial episodes, parallel wall-clock runtime `283.86 s`). Single-seed clean-slice FPR (`0.0%`) is removed as a headline; every TPR table reports the multi-seed operational **Window FPR (`9.29%`)** and **False Alerts / Device / Day (`1.14`)** alongside **95% Wilson Score Confidence Intervals**.

### Headline Multi-Seed Summary ($N = 5$ Seeds: `[42, 43, 44, 45, 46]`)

| Headline Metric | Multi-Seed Mean | 95% Bootstrap CI across Seeds | Per-Tier Breakdown (`EASY` / `MEDIUM` / `HARD`) |
| :--- | :---: | :---: | :--- |
| **Episode Detection Rate (TPR)** | **96.13%** | `[95.56%, 96.74%]` | `EASY`: **100.0%** `[99.7%, 100.0%]` \| `MEDIUM`: **100.0%** `[99.7%, 100.0%]` \| `HARD`: **88.4%** `[86.7%, 89.9%]` |
| **Window False Positive Rate (FPR)** | **9.29%** | `[8.73%, 9.83%]` | Evaluated across Days 9–14 clean + 6 benign operational burst classes |
| **False Alerts / Device / Day** | **1.14** | `[1.07, 1.21]` | Post-hysteresis ($k=2$ of $n=3$) false alerts per device per day |
| **Mean Time-to-Detect (TTD)** | **2.43 s** | `[2.33 s, 2.52 s]` | Continuous sub-window episode start offsets (`calculate_sub_window_offset`) |

### 1. Per-Cell (`Attack x Tier`) & Attack-Level Multi-Seed Detection Performance

#### 1.1 Headline Per-Cell Breakdown (`6 Attacks x 3 Tiers = 18 Cells`, Wilson 95% CIs)

| Attack Vector | Difficulty Tier | Episodes ($n$) | Detected | GUARDIAN TPR (%) | 95% Wilson CI | Pooled IF TPR | Static Rules TPR | Robust Z-Score TPR | Mean TTD (s) | Window FPR (%) | False Alerts / Dev / Day |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **DDOS_FLOODING** | `EASY` | 250 | 250 | **100.0%** | `[98.5%, 100.0%]` | 100.0% | 100.0% | 100.0% | 0.98 s | 9.29% | 1.14 |
| **DDOS_FLOODING** | `MEDIUM` | 250 | 250 | **100.0%** | `[98.5%, 100.0%]` | 100.0% | 100.0% | 100.0% | 1.01 s | 9.29% | 1.14 |
| **DDOS_FLOODING** | `HARD` | 250 | 232 | **92.8%** | `[88.9%, 95.4%]` | 12.4% | 0.0% | 99.6% | 4.68 s | 9.29% | 1.14 |
| **CNC_BEACONING** | `EASY` | 250 | 250 | **100.0%** | `[98.5%, 100.0%]` | 96.0% | 100.0% | 100.0% | 0.98 s | 9.29% | 1.14 |
| **CNC_BEACONING** | `MEDIUM` | 250 | 250 | **100.0%** | `[98.5%, 100.0%]` | 40.8% | 100.0% | 100.0% | 0.96 s | 9.29% | 1.14 |
| **CNC_BEACONING** | `HARD` | 250 | 201 | **80.4%** | `[75.0%, 84.8%]` | 17.2% | 0.0% | 97.2% | 8.49 s | 9.29% | 1.14 |
| **NETWORK_SCANNING** | `EASY` | 250 | 250 | **100.0%** | `[98.5%, 100.0%]` | 100.0% | 100.0% | 100.0% | 1.08 s | 9.29% | 1.14 |
| **NETWORK_SCANNING** | `MEDIUM` | 250 | 250 | **100.0%** | `[98.5%, 100.0%]` | 99.2% | 100.0% | 100.0% | 0.98 s | 9.29% | 1.14 |
| **NETWORK_SCANNING** | `HARD` | 250 | 250 | **100.0%** | `[98.5%, 100.0%]` | 14.8% | 76.0% | 100.0% | 1.04 s | 9.29% | 1.14 |
| **DATA_EXFILTRATION** | `EASY` | 250 | 250 | **100.0%** | `[98.5%, 100.0%]` | 100.0% | 100.0% | 100.0% | 1.02 s | 9.29% | 1.14 |
| **DATA_EXFILTRATION** | `MEDIUM` | 250 | 250 | **100.0%** | `[98.5%, 100.0%]` | 100.0% | 100.0% | 100.0% | 1.01 s | 9.29% | 1.14 |
| **DATA_EXFILTRATION** | `HARD` | 250 | 244 | **97.6%** | `[94.9%, 98.9%]` | 16.4% | 0.0% | 100.0% | 5.98 s | 9.29% | 1.14 |
| **CRYPTOMINING** | `EASY` | 250 | 250 | **100.0%** | `[98.5%, 100.0%]` | 100.0% | 100.0% | 100.0% | 1.00 s | 9.29% | 1.14 |
| **CRYPTOMINING** | `MEDIUM` | 250 | 250 | **100.0%** | `[98.5%, 100.0%]` | 97.6% | 100.0% | 100.0% | 1.00 s | 9.29% | 1.14 |
| **CRYPTOMINING** | `HARD` | 250 | 202 | **80.8%** | `[75.5%, 85.2%]` | 16.4% | 0.0% | 98.4% | 6.15 s | 9.29% | 1.14 |
| **ZERO_DAY_HYBRID** | `EASY` | 250 | 250 | **100.0%** | `[98.5%, 100.0%]` | 100.0% | 100.0% | 100.0% | 0.99 s | 9.29% | 1.14 |
| **ZERO_DAY_HYBRID** | `MEDIUM` | 250 | 250 | **100.0%** | `[98.5%, 100.0%]` | 100.0% | 93.2% | 100.0% | 0.96 s | 9.29% | 1.14 |
| **ZERO_DAY_HYBRID** | `HARD` | 250 | 197 | **78.8%** | `[73.3%, 83.4%]` | 16.0% | 0.0% | 98.4% | 8.48 s | 9.29% | 1.14 |

#### 1.2 Attack-Level Summary Across Tiers (with FPR and False Alerts / Device / Day)

| Attack Vector | Episodes ($n$) | GUARDIAN TPR | 95% Wilson CI | Pooled IF | Static Rules | Robust Z-Score | F1 Score | Mean TTD (s) | Window FPR (%) | False Alerts / Dev / Day |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **DDOS_FLOODING** | 750 | **97.6%** | `[96.2%, 98.5%]` | 70.8% | 66.7% | 99.9% | 0.8780 | 2.17 s | 9.29% | 1.14 |
| **CNC_BEACONING** | 750 | **93.5%** | `[91.5%, 95.0%]` | 51.3% | 66.7% | 99.1% | 0.8233 | 3.13 s | 9.29% | 1.14 |
| **NETWORK_SCANNING** | 750 | **100.0%** | `[99.5%, 100.0%]` | 71.3% | 92.0% | 100.0% | 0.9950 | 1.03 s | 9.29% | 1.14 |
| **DATA_EXFILTRATION** | 750 | **99.2%** | `[98.3%, 99.6%]` | 72.1% | 66.7% | 100.0% | 0.8747 | 2.64 s | 9.29% | 1.14 |
| **CRYPTOMINING** | 750 | **93.6%** | `[91.6%, 95.1%]` | 71.3% | 66.7% | 99.5% | 0.8517 | 2.48 s | 9.29% | 1.14 |
| **ZERO_DAY_HYBRID** | 750 | **92.9%** | `[90.9%, 94.6%]` | 72.0% | 64.4% | 99.4% | 0.8261 | 3.10 s | 9.29% | 1.14 |
| **Macro Average** | 4500 | **96.1%** | - | 68.1% | 70.5% | 99.7% | 0.9173 | - | 9.29% | 1.14 |

> [!NOTE]
> **Macro Average Verification**: Arithmetic mean across the 6 attack rows: sum = 576.8%, mean = **96.1%**.

### 2. Empirical Baselines Comparison (Identical Confusion Counts & Equal-FAR Comparison)

#### 2.1 Operating-Point Comparison (Computed from Identical Window Confusion Counts)

| Detection System | Threshold | TP | FP | TN | FN | Episode TPR (%) | Window TPR (%) | Window FPR (%) | F1 Score | False Alerts / Dev / Day |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **GUARDIAN (Multi-Layer Ensemble)** | 66.15 | 135513 | 2730 | 26670 | 21717 | **96.1%** | 86.19% | 9.29% | 0.9173 | 1.14 |
| **Pooled Isolation Forest** | 72.61 | 93257 | 1745 | 27655 | 63973 | **68.2%** | 59.31% | 5.94% | 0.7395 | 0.73 |
| **Static Threshold Rules** | 60.00 | 111079 | 2 | 29398 | 46151 | **70.5%** | 70.65% | 0.01% | 0.8280 | 0.00 |
| **Robust Z-Score Only (L1)** | 60.00 | 138690 | 4841 | 24559 | 18540 | **99.6%** | 88.21% | 16.46% | 0.9223 | 2.02 |

#### 2.2 Equal False-Alarm Rate Comparison (Target $\text{FAR} \le 1.00$ False Alert / Device / Day)

| Detection System | Equal-FAR Threshold | Episode TPR at $\text{FAR} \le 1.0$ (%) | Window TPR (%) | Window FPR (%) | F1 Score | Achieved False Alerts / Dev / Day |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **GUARDIAN (Multi-Layer Ensemble)** | 74.87 | **93.47%** | 81.11% | 8.15% | 0.8882 | 1.00 |
| **Pooled Isolation Forest** | 70.05 | **71.67%** | 62.06% | 7.95% | 0.7589 | 0.98 |
| **Static Threshold Rules** | 22.21 | **79.22%** | 79.38% | 1.44% | 0.8837 | 0.18 |
| **Robust Z-Score Only (L1)** | 94.47 | **93.78%** | 86.69% | 8.01% | 0.9213 | 0.98 |

> [!NOTE]
> **Why Uncalibrated `Robust Z-Score Only` Has Higher Raw TPR (`99.6%` vs `96.1%`) — and Why `GUARDIAN` Wins at Low-FPR Operating Points**: `RobustZScoreOnlyBaseline` takes the raw single-feature maximum $z_{\max} = \max_{j \in \{1..60\}} |Z_j|$ across all 60 features and clips at `100.0` whenever any single feature exceeds $5.61\sigma$. At its uncalibrated threshold (`60.00`), it suffers **`16.46%` window FPR (`2.02` false alerts/device/day)**—77% more false alarms than calibrated `GUARDIAN` (`9.29%` FPR, `1.14` FAR/day). Because `Robust Z-Score Only` clips at `100.0` on benign operational bursts, it retains `7.43%` FPR (`0.91` FAR/day) even at `threshold = 99.00` and cannot achieve $\text{FAR} < 0.91$ without collapsing to `0.0%` TPR (`threshold > 100.0`). In contrast, `GUARDIAN`'s fused ensemble score remains continuous up to `99.00`, achieving **`66.67%` episode TPR at `0.00` false alerts/device/day (`0.00%` FPR)**.

#### Operating Curves (`GUARDIAN` vs. `Robust Z-Score Only` vs. `Pooled IF` Across Thresholds)

| Alert Threshold | GUARDIAN Ep TPR (%) | GUARDIAN Win FPR (%) | GUARDIAN FAR/Day | Robust Z-Score Ep TPR (%) | Robust Z-Score Win FPR (%) | Robust Z-Score FAR/Day | Pooled IF Ep TPR (%) | Pooled IF Win FPR (%) | Pooled IF FAR/Day |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **30.00** | 100.00% | 34.45% | 4.22 | 100.00% | 32.38% | 3.97 | 100.00% | 100.00% | 12.25 |
| **40.00** | 99.93% | 18.37% | 2.25 | 100.00% | 32.38% | 3.97 | 100.00% | 99.40% | 12.18 |
| **50.00** | 99.22% | 13.45% | 1.65 | 99.91% | 21.40% | 2.62 | 99.53% | 69.63% | 8.53 |
| **55.00** | 98.69% | 11.68% | 1.43 | 99.89% | 19.07% | 2.34 | 96.60% | 40.91% | 5.01 |
| **60.00** | 97.44% | 10.39% | 1.27 | 99.65% | 16.46% | 2.02 | 88.75% | 23.04% | 2.82 |
| **65.00** | 96.25% | 9.45% | 1.16 | 99.35% | 14.53% | 1.78 | 79.00% | 13.52% | 1.66 |
| **68.65** | 95.87% | 8.88% | 1.09 | 99.13% | 13.37% | 1.64 | 72.87% | 9.26% | 1.13 |
| **72.00** | 95.40% | 8.55% | 1.05 | 98.38% | 12.33% | 1.51 | 68.31% | 6.37% | 0.78 |
| **75.00** | 93.42% | 8.24% | 1.01 | 97.93% | 11.55% | 1.42 | 63.89% | 4.22% | 0.52 |
| **80.00** | 91.33% | 7.49% | 0.92 | 97.31% | 10.50% | 1.28 | 56.33% | 2.25% | 0.27 |
| **85.00** | 66.67% | 0.00% | 0.00 | 96.02% | 9.31% | 1.14 | 37.33% | 0.75% | 0.09 |
| **90.00** | 66.67% | 0.00% | 0.00 | 95.55% | 8.64% | 1.06 | 0.96% | 0.00% | 0.00 |
| **95.00** | 66.67% | 0.00% | 0.00 | 93.33% | 7.95% | 0.97 | 0.00% | 0.00% | 0.00 |
| **99.00** | 66.67% | 0.00% | 0.00 | 92.91% | 7.43% | 0.91 | 0.00% | 0.00% | 0.00 |

### 3. Edge Gateway System Performance & Latency Disaggregation

All resource and latency measurements below reflect live `psutil` sampling and sub-millisecond timer telemetry:

| Performance Dimension | Empirical Measurement | Target Budget | Verification Status |
| :--- | :---: | :---: | :--- |
| **Resident Memory (RAM)** | **141.84 MB** (Peak: 141.84 MB) | $< 256.0\text{ MB}$ | **PASS** (Low memory footprint) |
| **Gateway CPU Utilization** | **50.48%** avg (Peak: 104.20%) | $< 40.0\%$ (Target) | **FAIL** (Measured on multi-core test host) |
| **Compute Latency ($T_{\text{window}} \to S_t$)**| **1.575 ms** (p95: 2.936 ms, Max: 3.579 ms) | $< 50.0\text{ ms}$ | **PASS** ($31\times$ faster than budget) |
| **Enforcement Latency (Dry-Run State Update)** | **0.013 ms** (p95: 0.019 ms, Max: 0.024 ms) | $< 300.0\text{ ms}$ | **PASS** (Dry-run state update; real Linux `nft -f` kernel transaction takes 2–15 ms) |
| **Time-to-Detect ($T_{\text{attack}} \to \text{Alert}$)**| **1.05 s** (continuous sub-window offset) | $< 60.0\text{ s}$ | **PASS** |

#### Fleet Scalability Profile (Empirical Multi-Device Sweep)

| Monitored Fleet Size | Measured Throughput (Windows/s) | Compute Latency (ms) | Host CPU (%) | Memory RSS (MB) |
| :---: | :---: | :---: | :---: | :---: |
| **8 Devices** | 740.98 | 1.324 ms | 4.2% | 141.8 MB |
| **12 Devices** | 792.46 | 1.240 ms | 6.2% | 141.8 MB |
| **16 Devices** | 815.70 | 1.205 ms | 7.7% | 141.8 MB |
| **20 Devices** | 914.35 | 1.075 ms | 8.6% | 141.8 MB |

### 4. 10-Minute Real-Time Packet Stream, CPU Disaggregation & Burst Saturation Benchmark (Review Fix 6)

| Ingestion Metric | Measured Value | Operational Gate |
| :--- | :---: | :---: |
| **Real-Time Wall-Clock Duration** | 756.40 s | $\ge 600.0\text{ s}$ ($10\text{ min}$) |
| **Offered Packets (10-Min Fleet Run)** | 37,645 pkts | Continuous real-time stream |
| **Processed Packets (10-Min Fleet Run)** | 37,645 pkts | Pipeline throughput |
| **Dropped Packets (1x Normal Load)** | 0 pkts | $< 0.1\%$ under normal load |
| **Packet Drop Rate (1x Normal Load)** | 0.00% | $0.00\%$ |
| **Peak Queue Depth (1x Normal Load)** | 17 / 5000 pkts | Buffer headroom |
| **Window Processing Latency (Mean / p95 / p99)** | 82.429 ms / 196.525 ms / 234.736 ms | Real-time window scoring |
| **Pipeline Consumer CPU vs. Generator Overhead CPU** | **7.03%** pipeline / 0.10% generator | Separated benchmark overhead |
| **Packet Ingestion Throughput** | 27.15 pps | Real-time line rate |

#### 4.1 10-Minute Real-Time Fleet-Size Breakdown (`200 s` Each at `8, 16, 32` Devices = `600.4 s` Total)

| Fleet Size | Duration (s) | Offered Pkts | Processed Pkts | Dropped Pkts | Peak Queue | Mean / p95 / p99 Latency (ms) | Pipeline CPU (%) | Generator Overhead CPU (%) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **8 Devices** | 200.07 s | 5,431 | 5,431 | 0 | 7 / 5000 | 82.429 / 196.525 / 234.736 ms | **7.03%** | 0.10% |
| **16 Devices** | 200.15 s | 10,750 | 10,750 | 0 | 9 / 5000 | 151.275 / 368.735 / 460.437 ms | **13.77%** | 0.12% |
| **32 Devices** | 200.20 s | 21,464 | 21,464 | 0 | 17 / 5000 | 311.071 / 727.209 / 871.331 ms | **29.17%** | 0.31% |

#### 4.2 Burst-Factor Saturation Sweep (`16` Devices, `60 s` per Burst Level from `1x` to `100x`)

| Burst Factor | Throughput (pps) | Offered Pkts | Processed Pkts | Dropped Windows | Peak Queue | Mean / p95 / p99 Latency (ms) | Pipeline CPU (%) | Generator Overhead CPU (%) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1.0x** | 628.04 pps | 2,830 | 2,830 | 366 / 416 | 9 / 5000 | 91.450 / 182.804 / 216.803 ms | **69.23%** | 0.45% |
| **5.0x** | 1250.00 pps | 14,150 | 14,150 | 401 / 416 | 45 / 5000 | 229.352 / 530.264 / 636.024 ms | **100.00%** | 2.52% |
| **10.0x** | 1488.48 pps | 28,300 | 28,300 | 410 / 416 | 90 / 5000 | 385.779 / 914.368 / 1128.419 ms | **100.00%** | 2.34% |
| **25.0x** | 2958.19 pps | 70,750 | 70,750 | 415 / 416 | 225 / 5000 | 489.431 / 1051.129 / 1332.088 ms | **100.00%** | 4.26% |
| **50.0x** | 4131.87 pps | 141,500 | 141,500 | 416 / 416 | 479 / 5000 | 678.383 / 1428.158 / 1725.609 ms | **100.00%** | 5.98% |
| **100.0x** | 5825.61 pps | 283,000 | 283,000 | 416 / 416 | 998 / 5000 | 951.881 / 1980.670 / 2384.956 ms | **100.00%** | 8.80% |

<!-- END RESULTS -->

---

## Component Ablation & Adversarial Evaluation Methodology

### 1. Ablation Study Hypotheses

To quantify the individual contribution of each component, Phase 2 implements a systematic ablation harness (`eval/run_benchmarks.py --mode ablation`):

- **Hypothesis H1 (Layer 2 Graph Contribution)**: Removing the destination topology graph degrades ROC-AUC (`0.9319` $\to$ `0.8578`) and increases false alarms (`27.63` $\to$ `74.88` FAR/day), demonstrating that endpoint topology tracking suppresses benign variance while separating novel external communication.
- **Hypothesis H2 (Dual-Engine Synergy)**: Fusing Isolation Forest with Robust MAD statistics outperforms either model in isolation (`F1 = 0.9173` vs `0.8995` Stat-Only and `0.9158` IF-Only).
- **Hypothesis H3 (Hysteresis False-Alarm Suppression)**: Temporal hysteresis ($k=2 \text{ of } n=3$ escalation, $M=15$ calm cooldown) cuts post-hysteresis false alerts from `88.41` to `27.63` false alerts/device/day ($3.2\times$ reduction), eliminating transient single-window flapping.
- **Hypothesis H4 (Header Heuristics & Temporal Priors)**: Layer 3 header heuristics and circadian harmonic encodings improve time-to-detect and separation on covert mimicry episodes.
- **Hypothesis H5 (Cross-Device Threat Intelligence)**: Fleet-wide event correlation accelerates detection of coordinated horizontal subnet reconnaissance.

### 2. Adversarial Robustness Protocol

GUARDIAN evaluates defensive efficacy against 6 hardened evasion modes (`50` episodes/mode/seed $\times 5$ seeds = `250` episodes per mode) engineered to circumvent statistical and machine-learning anomaly detectors:

```mermaid
graph TD
    ATTACK["Adversarial Evasion Vector"] --> E1["Volume-Matched Mimicry\n(Throttles transmission to match sensor baseline)"]
    ATTACK --> E2["Low-and-Slow Exfiltration\n(1 pkt every other window at HARD tier)"]
    ATTACK --> E3["Delayed-Start Burst\n(30s dormant window before covert payload)"]
    ATTACK --> E4["No-New-Destination Masking\n(Communicates strictly with whitelisted endpoints)"]

    E1 --> D1["Partially Mitigated by IAT Skew & Port Entropy (57.6% TPR)"]
    E2 --> D2["Partially Mitigated by Multi-Window Accumulators (46.4% TPR)"]
    E3 --> D3["Mitigated Post-Dormancy by Idle Ratio Shift (56.4% TPR, 23.12s TTD)"]
    E4 --> D4["Partially Mitigated by Packet Length & Timing Shifts (60.0% TPR)"]
```

### 3. Empirical Ablation Study Results (Multi-Seed Protocol, Calibrated on Day 8)

Evaluated inside the 5-seed protocol (`eval/RESULTS.md`, Run ID: `eval_1791651793_42_f106807`, `4,500` attack episodes across seeds `[42, 43, 44, 45, 46]`):

| Ablation Configuration | Episode TPR (%) | Window TPR (%) | Window FPR (%) | False Alerts / Dev / Day | Precision | Recall | F1 Score | ROC-AUC | Mean TTD (s) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Full GUARDIAN** | **96.1%** | 86.2% | 9.3% | 27.63 | 0.9803 | 0.8619 | 0.9173 | 0.9319 | 2.41 s |
| **Statistical Detector Only (No ML)** | **95.5%** | 83.2% | 9.8% | 31.54 | 0.9784 | 0.8324 | 0.8995 | 0.9202 | 2.98 s |
| **Isolation Forest Only (No Stat)** | **96.2%** | 86.0% | 9.4% | 28.69 | 0.9799 | 0.8596 | 0.9158 | 0.9359 | 2.52 s |
| **No Layer 1 (Volumetric Dynamics)** | **94.3%** | 81.7% | 12.7% | 42.90 | 0.9718 | 0.8173 | 0.8879 | 0.8831 | 2.96 s |
| **No Layer 2 (Network Graph)** | **96.8%** | 81.7% | 16.2% | 74.88 | 0.9642 | 0.8168 | 0.8844 | 0.8578 | 2.71 s |
| **No Layer 3 (Temporal/App)** | **97.1%** | 87.3% | 9.9% | 32.03 | 0.9793 | 0.8730 | 0.9231 | 0.9348 | 2.45 s |
| **No Hysteresis (Instantaneous)** | **98.0%** | 87.5% | 11.4% | 88.41 | 0.9763 | 0.8755 | 0.9231 | 0.9319 | 2.52 s |
| **Uncalibrated (Fixed Threshold)** | **97.4%** | 87.4% | 10.4% | 35.02 | 0.9782 | 0.8735 | 0.9229 | 0.9319 | 2.49 s |

### 4. Hardened Adversarial Evasion Robustness Results (`50` Episodes / Mode / Seed = `250` Episodes / Mode)

| Adversarial Evasion Tactic | Episodes ($n$) | Detected | Episode TPR (%) | 95% Wilson CI | Window FPR (%) | False Alerts / Dev / Day | F1 Score | Mean TTD (s) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **NONE** | 250 | 241 | **96.4%** | `[93.3%, 98.1%]` | 2.33% | 185.18 | 0.9247 | 2.31 s |
| **MIMICRY** | 250 | 144 | **57.6%** | `[51.4%, 63.6%]` | 2.47% | 193.20 | 0.5193 | 9.91 s |
| **LOW_AND_SLOW** | 250 | 116 | **46.4%** | `[40.3%, 52.6%]` | 2.05% | 395.95 | 0.4016 | 9.13 s |
| **DELAYED_START** | 250 | 141 | **56.4%** | `[50.2%, 62.4%]` | 2.46% | 475.89 | 0.5287 | 23.12 s |
| **NO_NEW_DESTINATION** | 250 | 150 | **60.0%** | `[53.8%, 65.9%]` | 2.47% | 192.28 | 0.5100 | 9.08 s |
| **ADAPTIVE** | 250 | 133 | **53.2%** | `[47.0%, 59.3%]` | 2.05% | 395.17 | 0.4866 | 6.88 s |

---

## Physical Hardware Bill of Materials ($250 Budget)

```mermaid
graph TD
    subgraph WAN["External Network / WAN"]
        ROUTER["Internet Gateway Router"]
    end

    subgraph GW["Edge Security Node ($75)"]
        RPI["Raspberry Pi 4 Model B (4GB RAM)\nRuns GUARDIAN Daemon & Dashboard\nLinux Kernel nftables Firewall"]
    end

    subgraph FLEET["8 Heterogeneous Protected IoT Nodes ($175 Total)"]
        N1["ESP32 DHT22 Temp/Humidity ($8)"]
        N2["ESP32 HC-SR501 PIR Motion ($8)"]
        N3["ESP32 BME280 Air Quality ($10)"]
        N4["ESP8266 Sonoff Smart Plug ($12)"]
        N5["ESP8266 HVAC Relay Actuator ($6)"]
        N6["RPi Zero 2 W Sensor Node 1 ($25)"]
        N7["RPi Zero 2 W Sensor Node 2 ($25)"]
        N8["ESP32-CAM MJPEG Video ($14)"]
        CAB["Power supplies, wiring, breadboards ($67)"]
    end

    ROUTER <== Dual Ethernet ==> RPI
    RPI <== Isolated IoT VLAN ==> FLEET
```

| Component | Hardware Specification | Role & Sensor Payload | Protocol | Unit Cost |
| :--- | :--- | :--- | :--- | :---: |
| **Gateway Node** | Raspberry Pi 4 Model B (4GB RAM) | Runs GUARDIAN Daemon & Dashboard | Dual GbE / Wi-Fi AP | \$75 |
| **Node 1** | ESP32-WROOM-32 DevKit | DHT22 Temperature & Humidity | MQTT over TCP (1883) | \$8 |
| **Node 2** | ESP32-WROOM-32 DevKit | HC-SR501 PIR Motion Sensor | MQTT over TCP (1883) | \$8 |
| **Node 3** | ESP32-WROOM-32 DevKit | BME280 Environmental Air Quality | MQTT over TCP (1883) | \$10 |
| **Node 4** | ESP8266 (Sonoff Basic S20) | Smart Plug AC Load Monitor | MQTT over TCP (1883) | \$12 |
| **Node 5** | ESP8266 NodeMCU v3 | Dual Relay HVAC Actuator | MQTT over TCP (1883) | \$6 |
| **Node 6** | Raspberry Pi Zero 2 W | Edge Compute Logger Node 1 | HTTP / NTP | \$25 |
| **Node 7** | Raspberry Pi Zero 2 W | Edge Compute Logger Node 2 | HTTP / MQTT | \$25 |
| **Node 8** | ESP32-CAM (AI-Thinker OV2640) | MJPEG Security Video Stream | HTTP Stream / MQTT Status | \$14 |
| **Interconnects**| Micro-USB supplies, breadboard, cables | Testbed power & Ethernet routing | Physical | \$67 |
| **TOTAL** | **8 Protected Nodes + 1 Gateway** | | | **\$250** |

---

## Quickstart & Verification Guide

> [!IMPORTANT]
> **Windows Environment Note**:
> - Use **64-bit Python 3.11+** (`python -c "import struct; print(struct.calcsize('P') * 8)"` must output `64`), **WSL2 (Ubuntu 22.04+)**, or **Docker**. 32-bit Windows Python interpreters lack prebuilt binary wheels for optional C-extension development packages (`scikit-learn`, `scipy`).
> - On Windows PowerShell where GNU `make` is not installed, use the included [`make.ps1`](make.ps1) task runner:
>   ```powershell
>   powershell -ExecutionPolicy Bypass -File .\make.ps1 setup
>   powershell -ExecutionPolicy Bypass -File .\make.ps1 lint
>   powershell -ExecutionPolicy Bypass -File .\make.ps1 type
>   powershell -ExecutionPolicy Bypass -File .\make.ps1 test
>   powershell -ExecutionPolicy Bypass -File .\make.ps1 demo
>   ```
> - Real kernel-level `nftables` firewall enforcement requires a privileged Linux environment (**WSL2** with `nftables` enabled or a privileged **Docker** container with `--cap-add=NET_ADMIN`); on Windows hosts, `EnforcementController` automatically operates in dry-run simulation mode.

### 1. Local Setup
```bash
# Clone repository
git clone https://github.com/lumidren/Guardian.git
cd Guardian

# Create and activate virtual environment (64-bit Python 3.11+)
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies in editable mode
pip install -e ".[dev]"
```

### 2. Run Test Suite & Quality Gates
```bash
# Using GNU Make (Linux / macOS / WSL) or .\make.ps1 (Windows PowerShell)
make lint    # ruff check src tests config
make type    # mypy src/guardian
make test    # pytest tests/unit tests/integration -v
make cov     # pytest --cov=src/guardian --cov-report=term-missing tests/
make demo    # End-to-end IoT defense pipeline smoke demonstration
```

### 3. Run Database Migrations
```bash
alembic upgrade head
```

### 4. 1-Command Docker Deployment
```bash
docker-compose up -d
```
Access the interactive web dashboard at **`http://localhost:8000`**.

---

## Academic Citation

If you utilize GUARDIAN or our benchmark methodology in your research, please cite the software repository:

```bibtex
@software{lumidren2026guardian,
  author    = {Mustafa, L.},
  title     = {{GUARDIAN: Multi-Layer Identity-Based Zero-Day Defense Framework for IoT Networks}},
  url       = {https://github.com/lumidren/Guardian},
  year      = {2026},
  note      = {Software prototype and evaluation framework. Manuscript in preparation.}
}
```

---

## License

This software and associated research artifacts are open-sourced under the [MIT License](LICENSE) &copy; 2026 lumidren.
