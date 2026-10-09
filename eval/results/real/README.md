# Real IoT Device Validation Directory

This directory stores raw packet captures, extracted feature matrices, and evaluation reports collected from real physical IoT hardware testbeds running GUARDIAN Gateway.

## Testbed Specification
- **Gateway Node**: Raspberry Pi 4 Model B (4 GB RAM, 64-bit ARM Cortex-A72 @ 1.5 GHz) running Raspberry Pi OS (Debian 12 Bookworm, Linux kernel 6.6+).
- **Physical IoT Nodes**:
  - `esp32_sensor_01`: ESP32 NodeMCU (Xtensa dual-core 240 MHz) with DHT22 temperature/humidity sensor (MQTT over TCP 1883).
  - `plug_living_04`: TP-Link Kasa HS100 Smart Plug (Wi-Fi 802.11b/g/n, local proprietary TCP protocol).
  - `pir_motion_02`: ESP32 PIR motion detector (CoAP/UDP 5683).
  - `camera_cam_08`: Wyze Cam v3 / RTSP IP camera (H.264 video stream over TCP 554 / HTTPS 443).
- **Network Topology**:
  - Isolated physical VLAN / Wi-Fi SSID (`192.168.1.0/24`).
  - Raspberry Pi 4 acting as dual-homed Linux router/gateway (`eth0`: uplink WAN, `wlan0`: hostapd AP for IoT fleet).

## Data Ingestion & PCAP Procedure
Captures are gathered via `tcpdump` with snaplen capping payload size:
```bash
sudo tcpdump -i wlan0 -s 96 -w eval/results/real/fleet_baseline_24h.pcap
```
Ingested into GUARDIAN via:
```python
from guardian.capture.pcap_importer import PCAPImporter

importer = PCAPImporter()
packets = importer.import_pcap("eval/results/real/fleet_baseline_24h.pcap")
```
