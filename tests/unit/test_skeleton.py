"""
Initial smoke test for M0 scaffolding verification.
"""

import importlib


def test_core_packages_importable():
    packages = [
        "guardian",
        "guardian.common",
        "guardian.sources",
        "guardian.simulator",
        "guardian.flows",
        "guardian.features",
        "guardian.profiles",
        "guardian.detection",
        "guardian.explain",
        "guardian.response",
        "guardian.response.backends",
        "guardian.intel",
        "guardian.identity",
        "guardian.pipeline",
        "guardian.api",
        "guardian.api.routes",
        "guardian.db",
        "guardian.eval",
    ]
    for pkg in packages:
        mod = importlib.import_module(pkg)
        assert mod is not None
