"""
Explainable AI (XAI) and Natural Language Generation (NLG) engine for GUARDIAN.
Transforms complex behavioral mathematical deviations into plain-English human-actionable reports.
"""

from .explainer import FeatureAttribution, AnomalyExplainer
from .nlg_engine import NLGEngine, ExplainableAlertReport
from .templates import AttackClassification, ATTACK_REMEDIATIONS

__all__ = [
    "FeatureAttribution",
    "AnomalyExplainer",
    "NLGEngine",
    "ExplainableAlertReport",
    "AttackClassification",
    "ATTACK_REMEDIATIONS",
]
