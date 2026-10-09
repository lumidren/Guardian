"""
Feature attribution and anomaly explainer for GUARDIAN.
Analyzes multi-layer deviations to identify root causes and classify attack mechanisms.
"""

from dataclasses import dataclass

from ..features.definitions import FEATURE_REGISTRY
from ..ml.statistical_baseline import DeviationDetail
from .templates import AttackClassification


@dataclass
class FeatureAttribution:
    feature_name: str
    human_name: str
    observed_value: float
    normal_value: float
    deviation_pct: float
    severity: str          # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    explanation_text: str
    unit: str


class AnomalyExplainer:
    def __init__(self):
        pass

    def explain(
        self,
        features: dict[str, float],
        baseline_means: dict[str, float],
        ml_attribution: dict[str, float],
        statistical_deviations: list[DeviationDetail],
        top_k: int = 5
    ) -> tuple[list[FeatureAttribution], AttackClassification]:
        """
        Produce top-k feature attribution explanations and classify likely attack pattern.
        """
        # Merge statistical deviations and ML feature weights
        seen_features = set()
        candidates = []

        # First add statistical deviations
        for dev in statistical_deviations:
            f_name = dev.feature_name
            seen_features.add(f_name)
            meta = FEATURE_REGISTRY.get(f_name)
            human_name = meta.human_name if meta else f_name
            unit = meta.unit if meta else ""
            pct = dev.percentage_change
            abs_z = abs(dev.z_score)

            if abs_z >= 4.0 or abs(pct) >= 500.0 or f_name in ("new_dst_ip_flag", "high_risk_port_flag"):
                sev = "CRITICAL"
            elif abs_z >= 2.5 or abs(pct) >= 150.0:
                sev = "HIGH"
            elif abs_z >= 1.5:
                sev = "MEDIUM"
            else:
                sev = "LOW"

            explanation = self._build_feature_sentence(f_name, dev.observed_value, dev.baseline_mean, pct, unit)

            candidates.append((abs_z + (ml_attribution.get(f_name, 0.0) * 10.0), FeatureAttribution(
                feature_name=f_name,
                human_name=human_name,
                observed_value=dev.observed_value,
                normal_value=dev.baseline_mean,
                deviation_pct=pct,
                severity=sev,
                explanation_text=explanation,
                unit=unit
            )))

        # Also add any top ML attribution features if not already added
        for f_name, weight in sorted(ml_attribution.items(), key=lambda x: x[1], reverse=True)[:5]:
            if f_name not in seen_features and weight > 0.05:
                seen_features.add(f_name)
                val = features.get(f_name, 0.0)
                norm = baseline_means.get(f_name, val)
                pct = ((val - norm) / max(1e-4, abs(norm))) * 100.0
                meta = FEATURE_REGISTRY.get(f_name)
                human_name = meta.human_name if meta else f_name
                unit = meta.unit if meta else ""

                sev = "HIGH" if weight > 0.15 else "MEDIUM"
                explanation = self._build_feature_sentence(f_name, val, norm, pct, unit)

                candidates.append((weight * 10.0, FeatureAttribution(
                    feature_name=f_name,
                    human_name=human_name,
                    observed_value=val,
                    normal_value=norm,
                    deviation_pct=pct,
                    severity=sev,
                    explanation_text=explanation,
                    unit=unit
                )))

        # Sort candidate attributions
        candidates.sort(key=lambda c: c[0], reverse=True)
        top_attributions = [c[1] for c in candidates[:top_k]]

        # Classify attack type
        classification = self._classify_attack(features, baseline_means, top_attributions)

        return top_attributions, classification

    def _build_feature_sentence(self, name: str, val: float, normal: float, pct: float, unit: str) -> str:
        if name == "new_dst_ip_flag":
            return "Communicated with a novel external IP address never previously seen in device history."
        elif name == "high_risk_port_flag":
            return "Active transmission over known exploit/backdoor port."
        elif name in ("pkt_count_10s", "pkt_rate_per_sec"):
            dir_str = "increase" if pct >= 0 else "reduction"
            return f"Packet traffic shifted from normal {normal:.1f} to {val:.1f} {unit} ({abs(pct):.0f}% {dir_str})."
        elif name == "byte_count_10s":
            dir_str = "surge" if pct >= 0 else "drop"
            return f"Byte throughput showed a {abs(pct):.0f}% {dir_str} ({val:,.0f} bytes vs baseline {normal:,.0f} bytes)."
        elif name == "external_ip_ratio":
            return f"External Internet traffic jumped to {val*100:.1f}% of total flow (normal: {normal*100:.1f}%)."
        elif name in ("protocol_http_ratio", "protocol_https_ratio"):
            return f"HTTP/HTTPS web protocol ratio altered to {val*100:.1f}% (normal baseline: {normal*100:.1f}%)."
        elif name == "unique_dst_ports":
            return f"Probing {int(val)} distinct destination ports simultaneously (baseline: {int(normal)})."
        elif name == "unique_dst_ips":
            return f"Connected to {int(val)} distinct destination endpoints (baseline: {int(normal)})."
        else:
            return f"Measured {val:.2f} {unit} compared to baseline {normal:.2f} {unit} ({pct:+.1f}% shift)."

    def _classify_attack(
        self,
        features: dict[str, float],
        baseline_means: dict[str, float],
        top_attrs: list[FeatureAttribution]
    ) -> AttackClassification:
        """
        Classifies anomaly into attack taxonomies matching Table 8 in GUARDIAN report.
        """
        pkt_count = features.get("pkt_count_10s", 0.0)
        norm_pkts = baseline_means.get("pkt_count_10s", 1.0)
        new_ip = features.get("new_dst_ip_flag", 0.0) > 0.5
        dst_ports = features.get("unique_dst_ports", 1.0)
        dst_ips = features.get("unique_dst_ips", 1.0)
        http_ratio = features.get("protocol_http_ratio", 0.0)
        mqtt_ratio = features.get("protocol_mqtt_ratio", 0.0)
        syn_ratio = features.get("tcp_syn_ratio", 0.0)
        byte_rate = features.get("byte_rate_per_sec", 0.0)

        # 1. DDoS Flooding: Massive traffic surge (>10x) or high SYN ratio
        if pkt_count > max(500, norm_pkts * 10) or (syn_ratio > 0.60 and pkt_count > 200):
            return AttackClassification.DDOS_FLOODING

        # 2. Network Scanning: Many distinct destination ports or IPs
        if dst_ports >= 5 or dst_ips >= 5:
            return AttackClassification.NETWORK_SCANNING

        # 3. Zero-Day Hybrid: Camera / device acting outside hours, communicating with new IP, protocol change
        # (Matches Section 2.2.3 Robot Vacuum Scenario exactly!)
        if new_ip and (http_ratio > 0.40 and mqtt_ratio < 0.60) and pkt_count > norm_pkts * 3:
            return AttackClassification.ZERO_DAY_HYBRID

        # 4. Data Exfiltration: Sustained large outbound throughput to external IP
        if byte_rate > 50000 and features.get("external_ip_ratio", 0) > 0.5:
            return AttackClassification.DATA_EXFILTRATION

        # 5. C&C Beaconing: Periodic communication with new external endpoint
        if new_ip and features.get("external_ip_ratio", 0) > 0.3:
            return AttackClassification.CNC_BEACONING

        # 6. Cryptomining: high risk port or compute pattern
        if features.get("high_risk_port_flag", 0) > 0.5:
            return AttackClassification.CRYPTOMINING

        if len(top_attrs) > 0:
            return AttackClassification.ZERO_DAY_HYBRID

        return AttackClassification.BENIGN_ANOMALY
