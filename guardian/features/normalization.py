"""
Online and batch normalizers for continuous feature streams.
"""

from typing import Dict, Optional
import numpy as np
from ..config import FEATURE_NAMES


class StreamingNormalizer:
    def __init__(self, eps: float = 1e-6):
        self.eps = eps
        self.means: Dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
        self.vars: Dict[str, float] = {name: 1.0 for name in FEATURE_NAMES}
        self.counts: Dict[str, int] = {name: 0 for name in FEATURE_NAMES}

    def update(self, features: Dict[str, float]):
        """Welford's algorithm for online mean and variance update."""
        for name, x in features.items():
            if name not in self.means:
                continue
            count = self.counts[name] + 1
            self.counts[name] = count
            delta = x - self.means[name]
            self.means[name] += delta / count
            delta2 = x - self.means[name]
            self.vars[name] += delta * delta2

    def transform(self, features: Dict[str, float]) -> Dict[str, float]:
        """Z-score normalize features based on accumulated statistics."""
        normalized = {}
        for name, x in features.items():
            count = self.counts.get(name, 0)
            if count > 1:
                variance = self.vars[name] / (count - 1)
                std = np.sqrt(max(self.eps, variance))
                normalized[name] = float((x - self.means[name]) / std)
            else:
                normalized[name] = 0.0
        return normalized
