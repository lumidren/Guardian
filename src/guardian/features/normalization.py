"""
Online and batch normalizers for continuous feature streams.
"""

import numpy as np

from .registry import FEATURE_NAMES


class StreamingNormalizer:
    def __init__(self, eps: float = 1e-6, drop_zero_variance: bool = False) -> None:
        self.eps = eps
        self.drop_zero_variance = drop_zero_variance
        self.means: dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
        self.vars: dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
        self.counts: dict[str, int] = {name: 0 for name in FEATURE_NAMES}

    def update(self, features: dict[str, float]) -> None:
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

    def active_features(self) -> list[str]:
        """Return list of feature names with sample variance strictly exceeding eps."""
        active: list[str] = []
        for name in FEATURE_NAMES:
            cnt = self.counts.get(name, 0)
            if cnt > 1 and (self.vars[name] / (cnt - 1)) > self.eps:
                active.append(name)
        return active

    def transform(
        self,
        features: dict[str, float],
        drop_zero_variance: bool | None = None,
    ) -> dict[str, float]:
        """Z-score normalize features based on accumulated statistics, optionally dropping zero-variance features."""
        drop_zv = self.drop_zero_variance if drop_zero_variance is None else drop_zero_variance
        normalized: dict[str, float] = {}
        for name, x in features.items():
            count = self.counts.get(name, 0)
            if count > 1:
                variance = self.vars[name] / (count - 1)
                if drop_zv and variance <= self.eps:
                    continue
                std = np.sqrt(max(self.eps, variance))
                normalized[name] = float((x - self.means[name]) / std)
            elif not drop_zv:
                normalized[name] = 0.0
        return normalized


# Alias for backward compatibility
FeatureNormalizer = StreamingNormalizer
