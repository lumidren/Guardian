"""
Explainable AI (XAI) and Natural Language Generation (NLG) engine for GUARDIAN.
Transforms complex behavioral mathematical deviations into plain-English human-actionable reports.
"""

from .explainer import AnomalyExplainer, FeatureAttribution
from .nlg_engine import ExplainableAlertReport, NLGEngine
from .templates import ATTACK_REMEDIATIONS, AttackClassification

__all__ = [
    "FeatureAttribution",
    "AnomalyExplainer",
    "NLGEngine",
    "ExplainableAlertReport",
    "AttackClassification",
    "ATTACK_REMEDIATIONS",
]
