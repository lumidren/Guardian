"""
Evaluation framework package for GUARDIAN.
"""

from .calibration import (
    Calibrator,
    FrozenOperatingPointError,
    OperatingPoint,
)
from .metrics import (
    BinaryMetrics,
    BootstrapCI,
    bootstrap_ci,
    compute_binary_metrics,
    compute_false_alert_rate,
    compute_pr_auc,
    compute_roc_auc,
)
from .runner import (
    ArtifactMissingError,
    EpisodeEvaluationResult,
    EvaluationMetricsReport,
    EvaluationRunner,
)
from .scenario import (
    AttackIntensity,
    EvasionMode,
    GroundTruthEpisode,
    ScenarioBuilder,
    SplitType,
    StreamWindow,
)

__all__ = [
    "BinaryMetrics",
    "BootstrapCI",
    "compute_binary_metrics",
    "compute_roc_auc",
    "compute_pr_auc",
    "compute_false_alert_rate",
    "bootstrap_ci",
    "SplitType",
    "AttackIntensity",
    "EvasionMode",
    "GroundTruthEpisode",
    "StreamWindow",
    "ScenarioBuilder",
    "Calibrator",
    "FrozenOperatingPointError",
    "OperatingPoint",
    "ArtifactMissingError",
    "EpisodeEvaluationResult",
    "EvaluationMetricsReport",
    "EvaluationRunner",
]
