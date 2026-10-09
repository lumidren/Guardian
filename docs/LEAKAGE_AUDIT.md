# GUARDIAN Leakage and Label Audit Report (Milestone P3-1)

**Audit Date**: October 2026  
**Author**: lumidren  
**Scope**: Verification of label isolation, non-semantic artifact separation, broken-detector controls, and pure-attack-window background mixing.

---

## 1. Executive Summary: Why Phase 2 Scored 100% Detection

The Phase 2 evaluation produced an empirical 100.0% True Positive Rate across all attack vectors with 0.00s time-to-detect. As formalized in the **Phase 3 Prime Directive**:
> *"An evaluation that cannot fail proves nothing. A detector that scores perfectly on everything is not a strong detector. It is a sign that the test is too easy, or that labels leak into the detection path."*

Our systematic leakage audit investigated four potential causes for this score:

1. **Did labels leak into the feature extraction or detection models?**
   - **Finding**: **NO.** Static source code analysis confirmed strict label isolation (`test_label_isolation` PASSED). Production feature extractors, Isolation Forest scoring, statistical baseline profiles, and threat scoring contain zero imports or references to `GroundTruthEpisode`, `has_attack`, `AttackType`, or attack metadata.

2. **Did non-semantic packet header artifacts leak attack identity?**
   - **Finding**: **NO.** A decision stump classifier trained exclusively on non-semantic fields (IP ID modulo, sub-second timestamp fractions, source port bands) achieved balanced accuracy below 65%, well below the leakage threshold of 95% (`test_non_semantic_fields_artifact_audit` PASSED). Attack packets share normal IP stack formatting.

3. **Did attack windows contain isolated attacks without background noise?**
   - **Finding**: **NO.** Audit of 18 test episodes across all 6 attack vectors confirmed that 100% of attack windows contained running background traffic (2 to 11 normal benign packets per window, mixed with attack packets).

4. **Root Cause Identified (Finding G1 & G9)**:
   - **Extreme Attack Intensity**: In the initial Phase 2 benchmark runner, attack episodes were generated at `AttackIntensity.HIGH` (e.g. 850–1400 SYN packets or 120 port probes per 10s window). For low-rate IoT devices whose nominal baseline is 1–8 packets per 10 seconds, these synthetic attacks were massively distinct from normal baselines, making detection trivial for any anomaly detector.
   - **Window-Level vs. Episode-Level Metric**: The Phase 2 headline metric measured window-level TPR on windows containing attack packets, rather than strict episode-level detection within a realistic time deadline.
   - **Window Alignment**: Episodes generated with `start_time = 10.0s` aligned exactly with sliding window boundaries ($W=10\text{s}, \text{stride}=2\text{s}$), producing $0.00\text{ s}$ time-to-detect by window construction.
   - **Absence of Difficulty Tiers**: The simulator lacked subtle, parameter-matched evasion modes that stay within normal device rates (addressed in Milestone P3-2).

---

## 2. Controls Battery Verification

To guarantee that the evaluation harness is capable of failing when detection fails, Phase 3 implements an automated controls battery executed on every evaluation (`src/guardian/eval/controls.py`):

| Control Type | Required Theoretical Behavior | Measured Value in P3-1 Audit | Gate Status |
| :--- | :--- | :---: | :---: |
| **Always-Alert Control** | Dummy detector alerting on all windows must yield $\text{TPR} = 100.0\%$, $\text{FPR} = 100.0\%$. | $\text{TPR} = 100.0\%$, $\text{FPR} = 100.0\%$ | **PASS** |
| **Never-Alert Control** | Dummy detector alerting on zero windows must yield $\text{TPR} = 0.0\%$, $\text{FPR} = 0.0\%$. | $\text{TPR} = 0.0\%$, $\text{FPR} = 0.0\%$ | **PASS** |
| **Random-Score Detector** | Uniform random scoring $U[0, 1]$ must score near chance on ROC-AUC ($0.40 \le \text{AUC} \le 0.60$). | $\text{ROC-AUC} = 0.4912$ | **PASS** |
| **Shuffled-Label Control** | Shuffling ground truth labels in time must collapse TPR to approximately the FPR ($|\text{TPR} - \text{FPR}| \le 0.25$). | $\text{TPR} = 0.5200$, $\text{FPR} = 0.4800$ ($\Delta = 0.0400$) | **PASS** |

---

## 3. Label Isolation Audit Results

Static analysis scanned all production modules across `src/guardian/`:
- `src/guardian/capture/`
- `src/guardian/features/`
- `src/guardian/ml/`
- `src/guardian/enforcement/`
- `src/guardian/storage/`
- `src/guardian/xai/`

**Result**: 0 violations found. Ground truth definitions exist exclusively under `src/guardian/eval/` and `simulation/`.

---

## 4. Pure Attack Window Check & Background Mixing Audit

To verify that attacks are never evaluated in artificial isolation, 18 attack episodes (3 episodes per attack class across 8 device types) were evaluated. In all 18 cases, attack windows contained both legitimate device telemetry and injected attack packets:

| Attack Vector | Episode ID | Device | Pre-Attack Normal Score | Peak Attack Score | Normal Pkts/Window | Attack Pkts/Window | Verification |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **DDoS Flooding** | `ep_audit_ddos_flooding_1` | `dev_02_motion` | 34.8 | 37.0 | 3 | 853 | `VERIFIED_MIXED` |
| **DDoS Flooding** | `ep_audit_ddos_flooding_2` | `dev_03_env` | 34.6 | 37.0 | 7 | 890 | `VERIFIED_MIXED` |
| **DDoS Flooding** | `ep_audit_ddos_flooding_3` | `dev_04_plug` | 35.0 | 37.0 | 4 | 856 | `VERIFIED_MIXED` |
| **C&C Beaconing** | `ep_audit_cnc_beaconing_1` | `dev_03_env` | 34.6 | 37.0 | 7 | 26 | `VERIFIED_MIXED` |
| **C&C Beaconing** | `ep_audit_cnc_beaconing_2` | `dev_04_plug` | 35.0 | 37.0 | 5 | 29 | `VERIFIED_MIXED` |
| **C&C Beaconing** | `ep_audit_cnc_beaconing_3` | `dev_05_relay` | 34.6 | 37.0 | 2 | 28 | `VERIFIED_MIXED` |
| **Network Scanning** | `ep_audit_network_scanning_1` | `dev_04_plug` | 38.4 | 41.0 | 4 | 120 | `VERIFIED_MIXED` |
| **Network Scanning** | `ep_audit_network_scanning_2` | `dev_05_relay` | 37.8 | 41.0 | 2 | 120 | `VERIFIED_MIXED` |
| **Network Scanning** | `ep_audit_network_scanning_3` | `dev_06_compute1` | 38.2 | 41.0 | 8 | 120 | `VERIFIED_MIXED` |
| **Data Exfiltration** | `ep_audit_data_exfiltration_1` | `dev_05_relay` | 34.8 | 37.0 | 3 | 412 | `VERIFIED_MIXED` |
| **Data Exfiltration** | `ep_audit_data_exfiltration_2` | `dev_06_compute1` | 34.6 | 37.0 | 10 | 401 | `VERIFIED_MIXED` |
| **Data Exfiltration** | `ep_audit_data_exfiltration_3` | `dev_07_compute2` | 34.6 | 37.0 | 11 | 407 | `VERIFIED_MIXED` |
| **Cryptomining** | `ep_audit_cryptomining_1` | `dev_06_compute1` | 49.2 | 55.0 | 8 | 81 | `VERIFIED_MIXED` |
| **Cryptomining** | `ep_audit_cryptomining_2` | `dev_07_compute2` | 49.0 | 55.0 | 8 | 87 | `VERIFIED_MIXED` |
| **Cryptomining** | `ep_audit_cryptomining_3` | `dev_08_camera` | 49.0 | 55.0 | 2 | 85 | `VERIFIED_MIXED` |
| **Zero-Day Hybrid** | `ep_audit_zero_day_hybrid_1` | `dev_07_compute2` | 34.8 | 37.0 | 10 | 850 | `VERIFIED_MIXED` |
| **Zero-Day Hybrid** | `ep_audit_zero_day_hybrid_2` | `dev_08_camera` | 34.6 | 37.0 | 2 | 850 | `VERIFIED_MIXED` |
| **Zero-Day Hybrid** | `ep_audit_zero_day_hybrid_3` | `dev_01_temp` | 34.6 | 37.0 | 6 | 850 | `VERIFIED_MIXED` |

---

## 5. Next Steps for Phase 3 Execution

Having ruled out label leakage and confirmed validity controls, the remaining tasks to achieve realistic, honest evaluation numbers are:
1. **Milestone P3-2 (Simulator Realism v2)**: Implement 3 difficulty tiers (Easy, Medium, Hard), true rate-matched mimicry, low-and-slow exfiltration over hours, and hard negatives (firmware updates, reboot storms).
2. **Milestone P3-3 (Evaluation v2)**: Restore episode-level detection rate within 60s as headline metric, enforce 5 random seeds, report 95% bootstrap confidence intervals, and ensure realistic time-to-detect bounds.
