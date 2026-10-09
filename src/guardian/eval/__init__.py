"""
Evaluation framework package for GUARDIAN.
"""

from .ablations import (
    AblationConfig,
    AblationResult,
    AblationRunner,
    get_standard_ablation_battery,
)
from .baselines import (
    PooledIsolationForestBaseline,
    RobustZScoreOnlyBaseline,
    StaticThresholdBaseline,
)
from .benchmarks import (
    LatencyBenchmark,
    LatencyReport,
    LoadTestReport,
    RealTimeLoadBenchmark,
    ScalabilityBenchmark,
    ScalabilityPoint,
    ScalabilityReport,
    SystemResourceBenchmark,
    SystemResourceReport,
    generate_scaled_fleet,
)
from .caching import (
    ModelBundle,
    ModelCacheManager,
    ModelSidecarData,
    TamperedBundleError,
)
from .calibration import (
    Calibrator,
    FrozenOperatingPointError,
    OperatingPoint,
)
from .guard import (
    PlausibilityGuard,
    PlausibilityReport,
)
from .metrics import (
    BinaryMetrics,
    BootstrapCI,
    EpisodeDetectionMetrics,
    aggregate_multi_seed_results,
    bootstrap_ci,
    check_evaluation_cross_table_consistency,
    compute_binary_metrics,
    compute_episode_detection_metrics,
    compute_false_alert_rate,
    compute_pr_auc,
    compute_roc_auc,
)
from .root_cause import (
    run_intensity_root_cause,
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
    calculate_sub_window_offset,
)
from .sensitivity import (
    OperatingCurvePoint,
    SensitivityAnalyzer,
    SensitivityReport,
)

__all__ = [
    "BinaryMetrics",
    "BootstrapCI",
    "EpisodeDetectionMetrics",
    "compute_binary_metrics",
    "compute_roc_auc",
    "compute_pr_auc",
    "compute_false_alert_rate",
    "compute_episode_detection_metrics",
    "check_evaluation_cross_table_consistency",
    "aggregate_multi_seed_results",
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
    "ModelBundle",
    "ModelSidecarData",
    "ModelCacheManager",
    "TamperedBundleError",
    "StaticThresholdBaseline",
    "PooledIsolationForestBaseline",
    "RobustZScoreOnlyBaseline",
    "AblationConfig",
    "AblationResult",
    "AblationRunner",
    "get_standard_ablation_battery",
    "OperatingCurvePoint",
    "SensitivityAnalyzer",
    "SensitivityReport",
    "generate_scaled_fleet",
    "SystemResourceReport",
    "SystemResourceBenchmark",
    "LatencyReport",
    "LatencyBenchmark",
    "ScalabilityPoint",
    "ScalabilityReport",
    "ScalabilityBenchmark",
    "LoadTestReport",
    "RealTimeLoadBenchmark",
    "PlausibilityReport",
    "PlausibilityGuard",
    "run_intensity_root_cause",
    "calculate_sub_window_offset",
]
