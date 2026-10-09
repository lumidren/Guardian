"""
Virtual IoT Fleet and Attack Simulation Suite for GUARDIAN.
Simulates 8 distinct IoT devices and 6 attack scenarios matching the IEEE specification.
"""

from .attack_suite import AttackSuite, AttackType
from .dataset_generator import BaselineDatasetGenerator
from .fleet_emulator import DEFAULT_FLEET_SPECS, IoTDeviceSpec, IoTFleetEmulator

__all__ = [
    "IoTDeviceSpec",
    "IoTFleetEmulator",
    "DEFAULT_FLEET_SPECS",
    "AttackSuite",
    "AttackType",
    "BaselineDatasetGenerator",
]
