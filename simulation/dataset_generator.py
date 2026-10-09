"""
Baseline dataset generator and model trainer for GUARDIAN (Section 4.3.1).
Generates 40,000+ normal behavioral samples across the 8 IoT devices and trains initial baselines.
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Tuple
import numpy as np

from ..config import config, FEATURE_NAMES
from ..capture.packet_parser import ParsedPacket
from ..capture.flow_tracker import FlowTracker
from ..features.extractor import FeatureExtractor
from ..ml.isolation_forest import IsolationForestDetector
from ..ml.statistical_baseline import StatisticalBaseline
from .fleet_emulator import IoTFleetEmulator, DEFAULT_FLEET_SPECS, IoTDeviceSpec


class BaselineDatasetGenerator:
    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or config.DATA_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.models_dir = config.MODELS_DIR
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.emulator = IoTFleetEmulator()
        self.extractor = FeatureExtractor()

    def generate_and_train_all(self, total_target_samples: int = 40000) -> Dict[str, dict]:
        """
        Generate 40,000+ baseline samples and train per-device Isolation Forest and Statistical baselines.
        Returns training summary metrics per device.
        """
        samples_per_device = total_target_samples // len(DEFAULT_FLEET_SPECS)
        summary = {}

        print(f"[Dataset Generator] Generating {total_target_samples:,} normal samples across 8 devices...")
        t_start = time.time()

        for dev in DEFAULT_FLEET_SPECS:
            dev_start = time.time()
            feature_vectors = []
            tracker = FlowTracker(window_size_seconds=10.0)

            # Whitelist normal destinations
            for dest in dev.normal_destinations:
                tracker.register_known_destination(dev.ip_address, dest)

            # Simulate 150 windows (each window contains multiple packets, producing 40,000+ total raw packets across fleet)
            n_windows = max(80, samples_per_device // int(dev.normal_packet_rate))
            current_sim_time = time.time() - (n_windows * 10.0)

            total_packets_collected = 0
            for w in range(n_windows):
                current_sim_time += 10.0
                hour = int((current_sim_time / 3600.0) % 24)

                pkts = self.emulator.generate_normal_window_packets(
                    device=dev,
                    window_duration=10.0,
                    current_time=current_sim_time,
                    hour_override=hour
                )
                total_packets_collected += len(pkts)

                for p in pkts:
                    tracker.ingest_packet(p)

                flow_summary = tracker.get_window_summary(dev.ip_address, current_timestamp=current_sim_time)
                if flow_summary:
                    vec = self.extractor.extract_vector(flow_summary)
                    feature_vectors.append(vec)

            X = np.array(feature_vectors, dtype=np.float64)

            # 1. Fit Isolation Forest
            iforest = IsolationForestDetector(n_estimators=100, subsample_size=min(256, len(feature_vectors)))
            iforest.fit(X, device_id=dev.id)
            model_path = self.models_dir / f"{dev.id}_iforest.json"
            iforest.save(model_path)

            # 2. Fit Statistical Baseline
            stat_base = StatisticalBaseline()
            stat_base.fit(X)

            # 3. Save baseline statistics
            stats_data = {
                "device_id": dev.id,
                "ip_address": dev.ip_address,
                "total_packets": total_packets_collected,
                "sample_windows": len(feature_vectors),
                "means": stat_base.means,
                "stds": stat_base.stds,
                "model_path": str(model_path)
            }
            stats_path = self.output_dir / f"{dev.id}_baseline.json"
            with open(stats_path, "w", encoding="utf-8") as f:
                json.dump(stats_data, f, indent=2)

            duration = time.time() - dev_start
            summary[dev.id] = {
                "name": dev.name,
                "ip": dev.ip_address,
                "raw_packets": total_packets_collected,
                "windows": len(feature_vectors),
                "train_time_sec": round(duration, 2),
                "model_file": str(model_path.name)
            }
            print(f"  ✓ {dev.name}: {total_packets_collected:,} pkts, {len(feature_vectors)} windows ({duration:.2f}s)")

        total_time = time.time() - t_start
        print(f"[Dataset Generator] Completed training all 8 models in {total_time:.2f} seconds.")
        return summary
