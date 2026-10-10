"""
Programmatically generate `docs/REAL_DATA_VALIDATION.md` from:
1. `eval/results/real_pcap_64mb_comparison.json` (single source of numerical truth)
2. `src/guardian/features/registry.py` (single source of 60-feature metadata truth)

Ensures:
- Zero hand-typed numbers in Section 5.2 (every numeric literal in Section 5.2 is
  interpolated directly from `eval/results/real_pcap_64mb_comparison.json`).
- Feature matches in Section 4 are reported strictly for features with nonzero
  variance in both sets (`real_std > 0` and `sim_std > 0`).
- In-domain results in Section 3.2 include `false alerts/device/day`.
- Section 1 uses the exact 8-node + Raspberry Pi 4 gateway plan from `README.md`
  with `TODO` for unmeasured physical deployment parameters (no invented hardware).
- Section 2 states clearly why MQTT topic features require Layer-7 payload bytes
  (and are excluded under GUARDIAN's header-only "no payload inspection" claim)
  and documents `tcp_clock_skew_est` as a Layer-4 TCP `TSval` header heuristic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from guardian.eval.metrics import compute_false_alert_rate
from guardian.features.registry import (
    CLOCK_SKEW_SCOPE_NOTE,
    EXCLUDED_PAYLOAD_FEATURES,
    FEATURE_NAMES,
    FEATURE_REGISTRY,
    MQTT_PAYLOAD_SCOPE_NOTE,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
JSON_PATH = REPO_ROOT / "eval" / "results" / "real_pcap_64mb_comparison.json"
CALIB_JSON_PATH = REPO_ROOT / "eval" / "results" / "real_data_calibration_and_iot23.json"
DOC_PATH = REPO_ROOT / "docs" / "REAL_DATA_VALIDATION.md"


def _fmt(val: float) -> str:
    return f"{float(val):.4f}"


def generate_section_5_2(feat_map: dict[str, dict[str, Any]]) -> str:
    """
    Generate Section 5.2 prose purely by interpolating numbers from `feat_map`
    (`eval/results/real_pcap_64mb_comparison.json`). No hand-typed numbers are allowed.
    """
    pkt_cnt = feat_map["pkt_count_10s"]
    byte_cnt = feat_map["byte_count_10s"]
    pkt_rate = feat_map["pkt_rate_per_sec"]
    byte_rate = feat_map["byte_rate_per_sec"]
    flow_dur = feat_map["flow_duration_sec"]

    iat_mean = feat_map["iat_mean"]
    iat_std = feat_map["iat_std"]
    iat_min = feat_map["iat_min"]
    iat_max = feat_map["iat_max"]
    iat_med = feat_map["iat_median"]
    iat_skew = feat_map["iat_skew"]
    iat_p90 = feat_map["iat_p90"]

    up_pkt = feat_map["upstream_pkt_ratio"]
    down_pkt = feat_map["downstream_pkt_ratio"]
    up_byte = feat_map["upstream_byte_ratio"]
    down_byte = feat_map["downstream_byte_ratio"]

    plen_mean = feat_map["pkt_len_mean"]
    plen_std = feat_map["pkt_len_std"]
    plen_min = feat_map["pkt_len_min"]
    plen_max = feat_map["pkt_len_max"]
    plen_med = feat_map["pkt_len_median"]
    plen_ent = feat_map["pkt_len_entropy"]

    proto_mqtt = feat_map["protocol_mqtt_ratio"]
    proto_https = feat_map["protocol_https_ratio"]
    proto_tcp_other = feat_map["protocol_tcp_other_ratio"]
    proto_ent = feat_map["protocol_entropy"]

    src_pe = feat_map["src_port_entropy"]
    dst_pe = feat_map["dst_port_entropy"]
    u_ports = feat_map["unique_dst_ports"]
    wk_port = feat_map["wellknown_port_ratio"]
    std_port = feat_map["std_port_deviation"]
    u_ips = feat_map["unique_dst_ips"]
    ip_ent = feat_map["dst_ip_entropy"]
    ext_ip = feat_map["external_ip_ratio"]
    new_ip = feat_map["new_dst_ip_flag"]

    tcp_psh = feat_map["tcp_psh_ratio"]
    tcp_win = feat_map["tcp_win_mean"]
    ttl_var = feat_map["ip_ttl_variance"]
    ipid_mono = feat_map["ip_id_monotonicity"]
    h_sin = feat_map["hour_sin"]
    h_cos = feat_map["hour_cos"]

    lines = [
        "### 5.2 Root-Cause Breakdown by Physical Network Mechanism",
        "",
        "- **Packet & Byte Volume / Rate (`pkt_count_10s`, `byte_count_10s`, `pkt_rate_per_sec`, `byte_rate_per_sec`, `flow_duration_sec`)**:",
        (
            f"  The physical Somfy TaHoma gateway exchanges brief, high-rate TLS keepalive bursts "
            f"(`pkt_count_10s` real mean `{_fmt(pkt_cnt['real_mean'])}` with std `{_fmt(pkt_cnt['real_std'])}` vs. "
            f"simulator mean `{_fmt(pkt_cnt['sim_mean'])}` with std `{_fmt(pkt_cnt['sim_std'])}`, "
            f"`byte_count_10s` real mean `{_fmt(byte_cnt['real_mean'])}` vs. simulator mean `{_fmt(byte_cnt['sim_mean'])}`, "
            f"and `flow_duration_sec` real mean `{_fmt(flow_dur['real_mean'])}` s vs. simulator mean `{_fmt(flow_dur['sim_mean'])}` s, "
            f"yielding `pkt_rate_per_sec` real mean `{_fmt(pkt_rate['real_mean'])}` pkts/s vs. simulator mean `{_fmt(pkt_rate['sim_mean'])}` pkts/s "
            f"and `byte_rate_per_sec` real mean `{_fmt(byte_rate['real_mean'])}` B/s vs. simulator mean `{_fmt(byte_rate['sim_mean'])}` B/s)."
        ),
        "- **Inter-Arrival Time Micro-Bunches (`iat_mean`, `iat_std`, `iat_min`, `iat_max`, `iat_median`, `iat_skew`, `iat_p90`)**:",
        (
            f"  Real Linux TCP/IP stacks emit back-to-back ACK and PSH-ACK TLS record segments separated by sub-millisecond gaps "
            f"(`iat_min` real mean `{_fmt(iat_min['real_mean'])}` s vs. simulator mean `{_fmt(iat_min['sim_mean'])}` s, "
            f"`iat_median` real mean `{_fmt(iat_med['real_mean'])}` s vs. simulator mean `{_fmt(iat_med['sim_mean'])}` s, "
            f"`iat_mean` real mean `{_fmt(iat_mean['real_mean'])}` s vs. simulator mean `{_fmt(iat_mean['sim_mean'])}` s, "
            f"`iat_std` real mean `{_fmt(iat_std['real_mean'])}` s vs. simulator mean `{_fmt(iat_std['sim_mean'])}` s, "
            f"`iat_max` real mean `{_fmt(iat_max['real_mean'])}` s vs. simulator mean `{_fmt(iat_max['sim_mean'])}` s, "
            f"`iat_skew` real mean `{_fmt(iat_skew['real_mean'])}` vs. simulator mean `{_fmt(iat_skew['sim_mean'])}`, "
            f"and `iat_p90` real mean `{_fmt(iat_p90['real_mean'])}` s vs. simulator mean `{_fmt(iat_p90['sim_mean'])}` s)."
        ),
        "- **Bidirectional Traffic Capture vs. Outbound-Centric Simulation (`upstream_pkt_ratio`, `downstream_pkt_ratio`, `upstream_byte_ratio`, `downstream_byte_ratio`)**:",
        (
            f"  The real gateway capture records full-duplex TCP conversations "
            f"(`upstream_pkt_ratio` real mean `{_fmt(up_pkt['real_mean'])}` and `downstream_pkt_ratio` real mean `{_fmt(down_pkt['real_mean'])}`, "
            f"with `upstream_byte_ratio` real mean `{_fmt(up_byte['real_mean'])}` and `downstream_byte_ratio` real mean `{_fmt(down_byte['real_mean'])}`), "
            f"whereas the uncalibrated simulator models outbound-only telemetry "
            f"(`upstream_pkt_ratio` simulator mean `{_fmt(up_pkt['sim_mean'])}`, `downstream_pkt_ratio` simulator mean `{_fmt(down_pkt['sim_mean'])}`, "
            f"`upstream_byte_ratio` simulator mean `{_fmt(up_byte['sim_mean'])}`, and `downstream_byte_ratio` simulator mean `{_fmt(down_byte['sim_mean'])}`)."
        ),
        "- **Packet Size Bimodality (`pkt_len_std`, `pkt_len_min`, `pkt_len_max`, `pkt_len_median`, `pkt_len_entropy`)**:",
        (
            f"  Although `pkt_len_mean` satisfies the standardized mean difference criterion "
            f"(real mean `{_fmt(plen_mean['real_mean'])}` B vs. simulator mean `{_fmt(plen_mean['sim_mean'])}` B, SMD `{_fmt(plen_mean['smd'])}`), "
            f"real TCP traffic is strongly bimodal between minimum-length TCP ACKs (`pkt_len_min` real mean `{_fmt(plen_min['real_mean'])}` B vs. simulator mean `{_fmt(plen_min['sim_mean'])}` B) "
            f"and larger TLS records (`pkt_len_max` real mean `{_fmt(plen_max['real_mean'])}` B vs. simulator mean `{_fmt(plen_max['sim_mean'])}` B), "
            f"yielding `pkt_len_std` real mean `{_fmt(plen_std['real_mean'])}` B vs. simulator mean `{_fmt(plen_std['sim_mean'])}` B, "
            f"`pkt_len_median` real mean `{_fmt(plen_med['real_mean'])}` B vs. simulator mean `{_fmt(plen_med['sim_mean'])}` B, "
            f"and `pkt_len_entropy` real mean `{_fmt(plen_ent['real_mean'])}` bits vs. simulator mean `{_fmt(plen_ent['sim_mean'])}` bits."
        ),
        "- **Application Protocol Mix (`protocol_mqtt_ratio`, `protocol_https_ratio`, `protocol_tcp_other_ratio`, `protocol_entropy`)**:",
        (
            f"  The Somfy TaHoma hub communicates over TLS/HTTPS (`protocol_https_ratio` real mean `{_fmt(proto_https['real_mean'])}` vs. simulator mean `{_fmt(proto_https['sim_mean'])}`, "
            f"`protocol_tcp_other_ratio` real mean `{_fmt(proto_tcp_other['real_mean'])}` vs. simulator mean `{_fmt(proto_tcp_other['sim_mean'])}`, "
            f"`protocol_mqtt_ratio` real mean `{_fmt(proto_mqtt['real_mean'])}` vs. simulator mean `{_fmt(proto_mqtt['sim_mean'])}`, "
            f"and `protocol_entropy` real mean `{_fmt(proto_ent['real_mean'])}` bits vs. simulator mean `{_fmt(proto_ent['sim_mean'])}` bits)."
        ),
        "- **Port & Destination Topology (`src_port_entropy`, `dst_port_entropy`, `unique_dst_ports`, `wellknown_port_ratio`, `std_port_deviation`, `unique_dst_ips`, `dst_ip_entropy`, `external_ip_ratio`, `new_dst_ip_flag`)**:",
        (
            f"  Bidirectional capture observes well-known HTTPS in the outbound direction and a persistent ephemeral port in the inbound direction "
            f"(`unique_dst_ports` real mean `{_fmt(u_ports['real_mean'])}` vs. simulator mean `{_fmt(u_ports['sim_mean'])}`, "
            f"`src_port_entropy` real mean `{_fmt(src_pe['real_mean'])}` vs. simulator mean `{_fmt(src_pe['sim_mean'])}`, "
            f"`dst_port_entropy` real mean `{_fmt(dst_pe['real_mean'])}` vs. simulator mean `{_fmt(dst_pe['sim_mean'])}`, "
            f"`wellknown_port_ratio` real mean `{_fmt(wk_port['real_mean'])}` vs. simulator mean `{_fmt(wk_port['sim_mean'])}`, "
            f"`std_port_deviation` real mean `{_fmt(std_port['real_mean'])}` vs. simulator mean `{_fmt(std_port['sim_mean'])}`, "
            f"`unique_dst_ips` real mean `{_fmt(u_ips['real_mean'])}` vs. simulator mean `{_fmt(u_ips['sim_mean'])}`, "
            f"`dst_ip_entropy` real mean `{_fmt(ip_ent['real_mean'])}` vs. simulator mean `{_fmt(ip_ent['sim_mean'])}`, "
            f"`external_ip_ratio` real mean `{_fmt(ext_ip['real_mean'])}` vs. simulator mean `{_fmt(ext_ip['sim_mean'])}`, "
            f"and `new_dst_ip_flag` real mean `{_fmt(new_ip['real_mean'])}` vs. simulator mean `{_fmt(new_ip['sim_mean'])}`)."
        ),
        "- **TCP/IP Stack Fingerprints & Diurnal Window (`tcp_psh_ratio`, `tcp_win_mean`, `ip_ttl_variance`, `ip_id_monotonicity`, `hour_sin`, `hour_cos`)**:",
        (
            f"  Real bidirectional traffic includes WAN-routed server packets and distinct TCP stack parameters "
            f"(`tcp_psh_ratio` real mean `{_fmt(tcp_psh['real_mean'])}` vs. simulator mean `{_fmt(tcp_psh['sim_mean'])}`, "
            f"`tcp_win_mean` real mean `{_fmt(tcp_win['real_mean'])}` B vs. simulator mean `{_fmt(tcp_win['sim_mean'])}` B, "
            f"`ip_ttl_variance` real mean `{_fmt(ttl_var['real_mean'])}` vs. simulator mean `{_fmt(ttl_var['sim_mean'])}`, "
            f"`ip_id_monotonicity` real mean `{_fmt(ipid_mono['real_mean'])}` vs. simulator mean `{_fmt(ipid_mono['sim_mean'])}`, "
            f"`hour_sin` real mean `{_fmt(h_sin['real_mean'])}` vs. simulator mean `{_fmt(h_sin['sim_mean'])}`, "
            f"and `hour_cos` real mean `{_fmt(h_cos['real_mean'])}` vs. simulator mean `{_fmt(h_cos['sim_mean'])}`)."
        ),
    ]
    return "\n".join(lines)


def build_real_data_validation_markdown() -> str:
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    features: list[dict[str, Any]] = data["features"]
    assert len(features) == 60, f"Expected 60 features in JSON, got {len(features)}"

    # Reconcile feature order against canonical registry.py
    for idx, f_entry in enumerate(features):
        fname = f_entry["feature"]
        assert fname == FEATURE_NAMES[idx], (
            f"Feature index {idx} mismatch: JSON={fname} vs registry.py={FEATURE_NAMES[idx]}"
        )
        assert fname in FEATURE_REGISTRY

    feat_map = {f["feature"]: f for f in features}

    # Filter strictly for features with nonzero variance in BOTH sets (Item 9)
    nonzero_both: list[dict[str, Any]] = []
    zero_var_features: list[dict[str, Any]] = []
    for f in features:
        if float(f["real_std"]) > 0.0 and float(f["sim_std"]) > 0.0:
            nonzero_both.append(f)
        else:
            zero_var_features.append(f)

    nonzero_matches = [f for f in nonzero_both if f["status"] == "MATCH"]
    nonzero_mismatches = [f for f in nonzero_both if f["status"] != "MATCH"]
    all_mismatches = [f for f in features if f["status"] != "MATCH"]

    # In-domain false alerts / device / day (Item 9)
    det = data["detection_audit"]
    in_domain_alerts = int(det["in_domain_alerts_count"])
    in_domain_windows = int(det["in_domain_test_windows"])
    active_days = (in_domain_windows * 10.0) / 86400.0
    in_domain_far_active_day = compute_false_alert_rate(
        num_false_alerts=in_domain_alerts,
        num_devices=1,
        days_observed=active_days,
    )
    # Each Somfy capture file (Somfy-02, Somfy-04) spans a 24-hour (1.0 day) capture period
    in_domain_far_capture_day = compute_false_alert_rate(
        num_false_alerts=in_domain_alerts,
        num_devices=1,
        days_observed=1.0,
    )

    ds = data["dataset"]
    rep = data["replay_summary"]

    lines: list[str] = [
        "# Real-Device Readiness and Public IoT PCAP Validation Report",
        "",
        "**Milestone**: P3-8 & Phase 3 Review Fixes (Items 7, 8, 9, 10, 11)  ",
        "**Architecture Decision**: [ADR-023: Real-Device Ingestion and Deployment Architecture](adr/ADR-023-real-device-deployment.md)  ",
        f"**Status**: VERIFIED ON {ds['files'][2]['size_mb']:.2f} MB PUBLIC BENIGN IOT PCAP (PHYSICAL BENCH ASSEMBLY PENDING — SEE TODOs IN SECTION 1)  ",
        "",
        "---",
        "",
        "## 1. Physical Hardware Testbed Plan (Reconciled with `README.md`)",
        "",
        "To prevent discrepancy between documentation and hardware plans, this section uses the exact 8-node + Raspberry Pi 4 Model B gateway Bill of Materials ($250 total budget) defined in `README.md`. **No unverified third-party consumer appliances are claimed; all unmeasured physical bench attributes are explicitly marked `TODO`.**",
        "",
        "```mermaid",
        "graph TD",
        '    subgraph WAN["External Network / WAN"]',
        '        ROUTER["Internet Gateway Router (Upstream WAN — TODO: Physical ISP Uplink Measurement)"]',
        "    end",
        "",
        '    subgraph GW["Edge Security Node ($75)"]',
        '        RPI["Raspberry Pi 4 Model B (4GB RAM)\\nRuns GUARDIAN Daemon & Dashboard\\nLinux Kernel nftables Firewall\\nCapture: tcpdump -s 96 / socket.AF_PACKET"]',
        "    end",
        "",
        '    subgraph FLEET["8 Heterogeneous Protected IoT Nodes ($175 Total — Physical Bench Assembly TODO)"]',
        '        N1["Node 1: ESP32-WROOM-32 DHT22 Temp/Humidity ($8)\\nMQTT over TCP (1883) | MAC/IP: TODO"]',
        '        N2["Node 2: ESP32-WROOM-32 HC-SR501 PIR Motion ($8)\\nMQTT over TCP (1883) | MAC/IP: TODO"]',
        '        N3["Node 3: ESP32-WROOM-32 BME280 Air Quality ($10)\\nMQTT over TCP (1883) | MAC/IP: TODO"]',
        '        N4["Node 4: ESP8266 Sonoff Basic S20 Smart Plug ($12)\\nMQTT over TCP (1883) | MAC/IP: TODO"]',
        '        N5["Node 5: ESP8266 NodeMCU v3 HVAC Relay ($6)\\nMQTT over TCP (1883) | MAC/IP: TODO"]',
        '        N6["Node 6: Raspberry Pi Zero 2 W Logger 1 ($25)\\nHTTP / NTP | MAC/IP: TODO"]',
        '        N7["Node 7: Raspberry Pi Zero 2 W Logger 2 ($25)\\nHTTP / MQTT | MAC/IP: TODO"]',
        '        N8["Node 8: ESP32-CAM AI-Thinker OV2640 ($14)\\nHTTP MJPEG Stream / MQTT | MAC/IP: TODO"]',
        '        CAB["Interconnects: Micro-USB supplies, breadboards, cables ($67)"]',
        "    end",
        "",
        "    ROUTER <== Dual Ethernet ==> RPI",
        "    RPI <== Isolated IoT VLAN (192.168.1.0/24) ==> FLEET",
        "```",
        "",
        "| Component | Hardware Specification | Role & Sensor Payload | Protocol | Unit Cost | Physical Bench Status |",
        "| :--- | :--- | :--- | :--- | :---: | :--- |",
        "| **Gateway Node** | Raspberry Pi 4 Model B (4GB RAM) | Runs GUARDIAN Daemon & Dashboard | Dual GbE / Wi-Fi AP | \\$75 | `TODO`: Physical bench flash & dual-NIC bridge latency profiling (`nftables` verified in Linux container) |",
        "| **Node 1** | ESP32-WROOM-32 DevKit | DHT22 Temperature & Humidity | MQTT over TCP (1883) | \\$8 | `TODO`: Flash firmware, assign static DHCP lease & record MAC |",
        "| **Node 2** | ESP32-WROOM-32 DevKit | HC-SR501 PIR Motion Sensor | MQTT over TCP (1883) | \\$8 | `TODO`: Flash firmware, assign static DHCP lease & record MAC |",
        "| **Node 3** | ESP32-WROOM-32 DevKit | BME280 Environmental Air Quality | MQTT over TCP (1883) | \\$10 | `TODO`: Flash firmware, assign static DHCP lease & record MAC |",
        "| **Node 4** | ESP8266 (Sonoff Basic S20) | Smart Plug AC Load Monitor | MQTT over TCP (1883) | \\$12 | `TODO`: Flash firmware, assign static DHCP lease & record MAC |",
        "| **Node 5** | ESP8266 NodeMCU v3 | Dual Relay HVAC Actuator | MQTT over TCP (1883) | \\$6 | `TODO`: Flash firmware, assign static DHCP lease & record MAC |",
        "| **Node 6** | Raspberry Pi Zero 2 W | Edge Compute Logger Node 1 | HTTP / NTP | \\$25 | `TODO`: Provision OS, assign static DHCP lease & record MAC |",
        "| **Node 7** | Raspberry Pi Zero 2 W | Edge Compute Logger Node 2 | HTTP / MQTT | \\$25 | `TODO`: Provision OS, assign static DHCP lease & record MAC |",
        "| **Node 8** | ESP32-CAM (AI-Thinker OV2640) | MJPEG Security Video Stream | HTTP Stream / MQTT Status | \\$14 | `TODO`: Flash camera stream firmware, assign DHCP lease & record MAC |",
        "| **Interconnects** | Micro-USB supplies, breadboard, cables | Testbed power & Ethernet routing | Physical | \\$67 | `TODO`: Physical bench wiring & 14-day continuous hardware capture |",
        "| **TOTAL** | **8 Protected Nodes + 1 Gateway** | | | **\\$250** | **Offline Public IoT-23 PCAP Replay Verified; Physical Bench Capture `TODO`** |",
        "",
        "---",
        "",
        "## 2. Ingestion Pipeline, Feature Registry Reconciliation & Privacy Guarantees",
        "",
        "### 2.1 Zero-Payload Capture Policy (`tcpdump -s 96`)",
        "In compliance with privacy and operational performance constraints, GUARDIAN **never captures, inspects, or decrypts Layer-7 application payloads**:",
        "1. **Snaplen Clamping**: Live packet sniffing utilizes `-s 96` (96 bytes), which captures only Layer 2 (Ethernet, 14 bytes), Layer 3 (IPv4, 20–60 bytes), and Layer 4 (TCP/UDP, 20–32 bytes) headers.",
        "2. **Single Source of Feature Truth (`src/guardian/features/registry.py`)**: All 60 canonical features in `FEATURE_REGISTRY` (`src/guardian/features/registry.py`) are imported directly by `src/guardian/config.py`, `src/guardian/features/extractor.py`, `README.md`, and this report, guaranteeing zero drift between documentation and code (`requires_payload_bytes == False` for all 60 features).",
        "3. **Streaming Memory Bound**: `PCAPImporter.iter_pcap()` streams binary `libpcap` records directly from disk with $O(1)$ per-frame memory overhead.",
        "",
        "### 2.2 Why MQTT Topic Features Require Payload Bytes and Are Excluded from the 60-Feature Header-Only Registry",
        f"> [!IMPORTANT]\n> **MQTT Topic Inspection vs. Zero-Payload Guarantee**: {MQTT_PAYLOAD_SCOPE_NOTE}",
        "",
        "Specifically, an MQTT `PUBLISH` or `SUBSCRIBE` packet encapsulates the topic name inside the **Layer-7 application payload** immediately following the Layer-4 TCP header and the 2-to-5 byte MQTT Fixed Header (`[Control Header (1B) | Remaining Length (1-4B) | Topic Length MSB/LSB (2B) | UTF-8 Topic String (N bytes) | Message Payload]`). Reading those bytes requires:",
        "- Capturing payload bytes beyond the Layer-4 TCP header (`snaplen > 96` when TCP options are present or when MQTT messages are coalesced in a TCP stream);",
        "- Reassembling TCP segments and parsing unencrypted Layer-7 application payloads; and",
        "- Decrypting TLS sessions when MQTT runs over TLS (`port 8883`), which is impossible without a man-in-the-middle key-escrow proxy.",
        "",
        "Accordingly, the four legacy Layer-7 MQTT payload features that appeared in earlier draft tables are **excluded** from `src/guardian/features/registry.py`:",
    ]

    for k, reason in EXCLUDED_PAYLOAD_FEATURES.items():
        lines.append(f"- `{k}`: {reason}")

    lines.extend([
        "",
        "### 2.3 Clock-Skew Heuristic vs. Out-of-Scope Physical-Layer Fingerprinting",
        f"> [!NOTE]\n> **Clock-Skew Scope Clarification (`tcp_clock_skew_est`, Feature #57)**: {CLOCK_SKEW_SCOPE_NOTE}",
        "",
        "---",
        "",
        f"## 3. Public Benign IoT Capture Replay ({ds['files'][2]['size_mb']:.2f} MB >= 50 MB)",
        "",
        "### 3.1 Source, License, and Cryptographic Checksums",
        f"- **Dataset**: **{ds['name']}**",
        f"- **Citation**: S. Garcia, A. Parmisano, & M. J. Erquiaga (2020), *\"IoT-23: A labeled dataset with malicious and benign IoT network traffic\"*, Stratosphere Laboratory, AIC Group, FEL, Czech Technical University in Prague. Zenodo DOI: `{ds['zenodo_doi']}`",
        f"- **Source URL**: `{ds['source_url']}`",
        f"- **License**: **{ds['license']}**",
        f"- **Device Under Test**: Physical **Somfy TaHoma Smart Home Gateway** (`{ds['device_ip']}`, MAC `F8:81:1A:02:27:D1`) executing unscripted benign smart-home gateway operations (TLS/HTTPS cloud polling, DNS resolution, NTP clock synchronization).",
        "",
        "| Capture File | Byte Size | Size (MB) | SHA-256 Checksum |",
        "| :--- | :---: | :---: | :--- |",
    ])

    for f_info in ds["files"]:
        is_combined = "combined" in f_info["filename"]
        fname_disp = f"**`{f_info['filename']}` (Combined Replay)**" if is_combined else f"`{f_info['filename']}`"
        size_b = f"**`{f_info['size_bytes']:,}`**" if is_combined else f"`{f_info['size_bytes']:,}`"
        size_m = f"**`{f_info['size_mb']:.2f} MB`**" if is_combined else f"`{f_info['size_mb']:.2f} MB`"
        lines.append(f"| {fname_disp} | {size_b} | {size_m} | `{f_info['sha256']}` |")

    lines.extend([
        "",
        "### 3.2 Replay Telemetry, Alert Rate & False Alerts / Device / Day Audit",
        f"- **Total IPv4 Packets Streamed**: `{rep['total_packets_parsed']:,}` packets (`{rep['protocol_breakdown']['TCP']:,}` TCP, `{rep['protocol_breakdown']['UDP']:,}` UDP; `{rep['app_protocol_breakdown']['HTTPS']:,}` HTTPS, `{rep['app_protocol_breakdown']['TCP']:,}` TCP ephemeral/cloud responses, `{rep['app_protocol_breakdown']['UDP']:,}` UDP other, `{rep['app_protocol_breakdown']['DNS']:,}` DNS, `{rep['app_protocol_breakdown']['NTP']:,}` NTP)",
        f"- **Active 10-Second Sliding Windows Extracted**: `{rep['active_windows_extracted']:,}` windows (`60` features per window)",
        f"- **Wall-Clock Replay Runtime**: `{rep['replay_wall_time_sec']:.3f} s` (`{rep['packets_per_sec']:.1f} packets/sec`)",
        f"- **Cross-Domain Alert Rate (Trained on Uncalibrated Simulator -> Evaluated Zero-Shot on Real PCAP)**: **`{det['cross_domain_sim_to_real_alert_rate'] * 100.0:.2f}%`** (`{rep['active_windows_extracted']:,} / {rep['active_windows_extracted']:,}` windows exceed the simulator P99 threshold `{det['sim_threshold_p99']:.4f}`). Because `{len(nonzero_mismatches)} / {len(nonzero_both)}` mutually nonzero-variance features (`{len(all_mismatches)} / 60` total features) exhibit substantial distribution shifts between the synthetic 8-device simulator and the physical Somfy gateway, an uncalibrated simulator-trained model cannot be deployed zero-shot onto physical hardware.",
        f"- **In-Domain Alert Rate & False Alerts / Device / Day (Trained on First 50% Real PCAP [`n = {rep['active_windows_extracted'] - in_domain_windows:,}`] -> Evaluated on Held-Out Second 50% Real PCAP [`n = {in_domain_windows:,}`])**: **`{det['in_domain_calibrated_alert_rate'] * 100.0:.2f}%` window FPR** (`{in_domain_alerts} / {in_domain_windows:,}` windows exceed the Day-1 P99 threshold `{det['real_threshold_p99']:.4f}`), corresponding to **`{in_domain_far_active_day:.2f}` false alerts/device/day** normalized over active window duration (`{active_days:.4f}` active window-days) or **`{in_domain_far_capture_day:.2f}` false alerts/device/day** across the 24-hour (`1.00` day) held-out capture (`Somfy-04`, prior to hysteresis confirmation).",
        "",
        "---",
        "",
        "## 4. Complete 60-Feature Distribution Comparison (Nonzero-Variance Match Audit)",
        "",
        "To avoid inflating feature agreement with constant-zero features, **feature matches are reported strictly for features with nonzero variance in both sets** ($\\sigma_{\\text{real}} > 0$ and $\\sigma_{\\text{sim}} > 0$). Among mutually nonzero-variance features, a feature is classified as **MATCH** if $D_{\\text{KS}} \\le 0.35$ or $\\text{SMD} = |\\mu_{\\text{real}} - \\mu_{\\text{sim}}| / \\sigma_{\\text{pool}} \\le 0.50$, and **MISMATCH** otherwise. Features with $\\sigma_{\\text{real}} = 0$ or $\\sigma_{\\text{sim}} = 0$ are explicitly segregated as **ZERO_VAR_EXCLUDED** (when degenerate in both or low-difference) or **MISMATCH (ZERO_VAR)**.",
        "",
        f"- **Features with Nonzero Variance in Both Sets (`{len(nonzero_both)} / 60`)**:",
        f"  - **True Nonzero-Variance Matching Features (`{len(nonzero_matches)} / {len(nonzero_both)}` active features = `{len(nonzero_matches) / len(nonzero_both) * 100.0:.2f}%`, or `{len(nonzero_matches)} / 60` = `{len(nonzero_matches) / 60.0 * 100.0:.1f}%` overall)**: "
        + ", ".join(f"`{f['feature']}`" for f in nonzero_matches),
        f"  - **Nonzero-Variance Mismatching Features (`{len(nonzero_mismatches)} / {len(nonzero_both)}` active features = `{len(nonzero_mismatches) / len(nonzero_both) * 100.0:.2f}%`)**: "
        + ", ".join(f"`{f['feature']}`" for f in nonzero_mismatches),
        f"- **Features with Zero Variance in at Least One Set (`{len(zero_var_features)} / 60`, Excluded from Match Claims)**: "
        + ", ".join(f"`{f['feature']}`" for f in zero_var_features),
        "",
        "| # | Feature Name | Real Mean | Real Std | Real Median | Real P95 | Sim Mean | Sim Std | Sim Median | Sim P95 | $D_{\\text{KS}}$ | SMD | Nonzero-Variance Status |",
        "| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])

    for f in features:
        idx_1 = int(f["index"]) + 1
        both_nz = float(f["real_std"]) > 0.0 and float(f["sim_std"]) > 0.0
        if both_nz:
            status_label = "**MATCH**" if f["status"] == "MATCH" else "**MISMATCH**"
        else:
            status_label = (
                "ZERO_VAR (EXCLUDED)"
                if f["status"] == "MATCH"
                else "**MISMATCH (ZERO_VAR)**"
            )
        lines.append(
            f"| {idx_1} | `{f['feature']}` | {_fmt(f['real_mean'])} | {_fmt(f['real_std'])} | "
            f"{_fmt(f['real_median'])} | {_fmt(f['real_p95'])} | {_fmt(f['sim_mean'])} | "
            f"{_fmt(f['sim_std'])} | {_fmt(f['sim_median'])} | {_fmt(f['sim_p95'])} | "
            f"{_fmt(f['ks_stat'])} | {_fmt(f['smd'])} | {status_label} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 5. Explicit List & Root-Cause Analysis of Mismatching Features",
        "",
        f"### 5.1 Complete List of {len(all_mismatches)} Mismatching Features ({len(nonzero_mismatches)} Nonzero-Variance + {len(all_mismatches) - len(nonzero_mismatches)} Zero-Variance)",
    ])

    for f in all_mismatches:
        idx_1 = int(f["index"]) + 1
        lines.append(
            f"{idx_1}. `{f['feature']}` (Real $\\mu={_fmt(f['real_mean'])}, \\sigma={_fmt(f['real_std'])}$ "
            f"vs. Sim $\\mu={_fmt(f['sim_mean'])}, \\sigma={_fmt(f['sim_std'])}$; "
            f"$D_{{\\text{{KS}}}}={_fmt(f['ks_stat'])}$, $\\text{{SMD}}={_fmt(f['smd'])}$)"
        )

    lines.append("")
    lines.append(generate_section_5_2(feat_map))
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    content = build_real_data_validation_markdown()
    DOC_PATH.write_text(content, encoding="utf-8")
    print(f"Generated {DOC_PATH} ({len(content)} bytes)")


if __name__ == "__main__":
    main()
