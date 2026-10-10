"""
Backward-compatible re-export of the canonical 60-feature registry from `registry.py`.
"""

from .registry import (
    CLOCK_SKEW_SCOPE_NOTE,
    EXCLUDED_PAYLOAD_FEATURES,
    FEATURE_NAMES,
    FEATURE_REGISTRY,
    MQTT_PAYLOAD_SCOPE_NOTE,
    FeatureMetadata,
    LayerType,
    render_readme_feature_table,
)

__all__ = [
    "CLOCK_SKEW_SCOPE_NOTE",
    "EXCLUDED_PAYLOAD_FEATURES",
    "FEATURE_NAMES",
    "FEATURE_REGISTRY",
    "MQTT_PAYLOAD_SCOPE_NOTE",
    "FeatureMetadata",
    "LayerType",
    "render_readme_feature_table",
]
