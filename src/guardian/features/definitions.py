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
    get_canonical_feature_registry,
    render_readme_feature_table,
    validate_registry_invariants,
)

__all__ = [
    "CLOCK_SKEW_SCOPE_NOTE",
    "EXCLUDED_PAYLOAD_FEATURES",
    "FEATURE_NAMES",
    "FEATURE_REGISTRY",
    "MQTT_PAYLOAD_SCOPE_NOTE",
    "FeatureMetadata",
    "LayerType",
    "get_canonical_feature_registry",
    "render_readme_feature_table",
    "validate_registry_invariants",
]
