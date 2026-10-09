"""
Smoke tests verifying quickstart and clean importability of GUARDIAN from src layout.
"""

import guardian
from guardian.api.app import create_app
from guardian.config import config
from guardian.enforcement.controller import EnforcementController
from guardian.features.definitions import FEATURE_REGISTRY
from guardian.features.extractor import FeatureExtractor
from guardian.intelligence.cross_device import CrossDeviceThreatIntelligence
from guardian.ml.threat_scorer import ThreatScorer


def test_package_metadata() -> None:
    assert guardian.__version__ == "1.0.0"
    assert guardian.__author__ == "lumidren"
    assert guardian.__license__ == "MIT"


def test_core_components_instantiation() -> None:
    extractor = FeatureExtractor()
    assert extractor is not None
    assert len(FEATURE_REGISTRY) == 60

    scorer = ThreatScorer()
    assert scorer is not None

    enforcer = EnforcementController()
    assert enforcer is not None

    intel = CrossDeviceThreatIntelligence()
    assert intel is not None


def test_gateway_app_factory() -> None:
    app = create_app()
    assert app.title == "GUARDIAN IoT Security Gateway"
    assert app.version == "1.0.0"


def test_config_paths() -> None:
    assert config.BASE_DIR.exists()
    assert config.DATA_DIR.exists()
    assert config.MODELS_DIR.exists()
