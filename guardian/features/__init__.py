"""
Behavioral Feature Extraction Layer for GUARDIAN.
Extracts 60 multi-layer identity features from IoT flow streams.
"""

from .definitions import FEATURE_REGISTRY, FeatureMetadata, LayerType
from .extractor import FeatureExtractor

__all__ = ["FEATURE_REGISTRY", "FeatureMetadata", "LayerType", "FeatureExtractor"]
