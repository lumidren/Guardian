"""
Evaluation framework package for GUARDIAN.
"""

from .metrics import (
    BinaryMetrics,
    BootstrapCI,
    bootstrap_ci,
    compute_binary_metrics,
    compute_false_alert_rate,
    compute_pr_auc,
    compute_roc_auc,
)

__all__ = [
    "BinaryMetrics",
    "BootstrapCI",
    "compute_binary_metrics",
    "compute_roc_auc",
    "compute_pr_auc",
    "compute_false_alert_rate",
    "bootstrap_ci",
]
