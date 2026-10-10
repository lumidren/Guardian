<#
.SYNOPSIS
    GUARDIAN Windows PowerShell Task Runner (make.ps1).
    Mirrors the GNU Makefile targets for Windows environments without GNU Make.

.EXAMPLE
    .\make.ps1 setup
    .\make.ps1 lint
    .\make.ps1 type
    .\make.ps1 test
    .\make.ps1 cov
    .\make.ps1 eval
    .\make.ps1 demo
#>

param(
    [Parameter(Position = 0)]
    [ValidateSet(
        "setup",
        "export-requirements",
        "lint",
        "type",
        "test",
        "cov",
        "eval",
        "demo",
        "api",
        "paper-assets",
        "check-commits",
        "clean",
        "help"
    )]
    [string]$Target = "help"
)

$ErrorActionPreference = "Stop"
$env:PYTHONPATH = "src;."

switch ($Target) {
    "setup" {
        Write-Host "[GUARDIAN] Installing editable package and dev dependencies..." -ForegroundColor Cyan
        python -m pip install -e ".[dev]"
    }
    "export-requirements" {
        Write-Host "[GUARDIAN] Exporting runtime dependencies to requirements.txt..." -ForegroundColor Cyan
        python -c "import tomllib; data=tomllib.load(open('pyproject.toml', 'rb')); print('\n'.join(data['project']['dependencies']))" | Out-File -Encoding utf8 requirements.txt
    }
    "lint" {
        Write-Host "[GUARDIAN] Running Ruff linter..." -ForegroundColor Cyan
        ruff check src tests config
    }
    "type" {
        Write-Host "[GUARDIAN] Running Mypy strict type checker..." -ForegroundColor Cyan
        mypy src/guardian
    }
    "test" {
        Write-Host "[GUARDIAN] Running unit and integration test suites..." -ForegroundColor Cyan
        pytest tests/unit tests/integration -v
    }
    "cov" {
        Write-Host "[GUARDIAN] Running test suite with coverage analysis..." -ForegroundColor Cyan
        pytest --cov=src/guardian --cov-report=term-missing --cov-report=html tests/
    }
    "eval" {
        Write-Host "[GUARDIAN] Running empirical evaluation suite..." -ForegroundColor Cyan
        python -m guardian.eval.report
    }
    "demo" {
        Write-Host "[GUARDIAN] Running end-to-end IoT defense pipeline demonstration..." -ForegroundColor Cyan
        python -c "
import time
from simulation.fleet_emulator import DEFAULT_FLEET_SPECS, IoTFleetEmulator
from simulation.attack_suite import AttackSuite, AttackType
from guardian.capture.flow_tracker import FlowTracker
from guardian.features.extractor import FeatureExtractor
from guardian.ml.isolation_forest import IsolationForestDetector
from guardian.ml.statistical_baseline import StatisticalBaseline
from guardian.ml.threat_scorer import ThreatScorer
from guardian.enforcement.controller import EnforcementController
from guardian.xai.nlg_engine import NLGEngine
from guardian.config import config

dev = DEFAULT_FLEET_SPECS[0]
print(f'1. Protecting Device: {dev.name} ({dev.ip_address}) [{dev.hardware}]')
ft = FlowTracker(window_size_seconds=10.0)
for d in dev.normal_destinations:
    ft.register_known_destination(dev.ip_address, d)
ext = FeatureExtractor()
model = IsolationForestDetector.load(config.MODELS_DIR / f'{dev.id}_iforest.json')
baseline = StatisticalBaseline()
import json
with open(config.DATA_DIR / f'{dev.id}_baseline.json', encoding='utf-8') as f:
    bdata = json.load(f)
baseline.means = bdata.get('means', {})
baseline.stds = bdata.get('stds', {})
baseline.is_ready = True
scorer = ThreatScorer()
enforcer = EnforcementController()
nlg = NLGEngine()
em = IoTFleetEmulator()
suite = AttackSuite()

now = time.time()
norm_pkts = em.generate_normal_window_packets(dev, 10.0, now)
for p in norm_pkts:
    ft.ingest_packet(p)
sum_norm = ft.get_window_summary(dev.ip_address, now)
f_norm = ext.extract(sum_norm)
v_norm = ext.extract_vector(sum_norm)
ml_n, _ = model.score_sample(v_norm)
st_n, _ = baseline.evaluate(f_norm)
ass_n = scorer.assess(ml_n, st_n, f_norm)
print(f'2. Normal Baseline Window -> Threat Score: {ass_n.threat_score}/100 ({ass_n.threat_level.value})')

ft.device_buffers[dev.ip_address].clear()
atk_pkts = suite.inject_attack(AttackType.CNC_BEACONING, dev, 10.0, now + 10.0, tier='EASY')
for p in norm_pkts + atk_pkts:
    ft.ingest_packet(p)
sum_atk = ft.get_window_summary(dev.ip_address, now + 10.0)
f_atk = ext.extract(sum_atk)
v_atk = ext.extract_vector(sum_atk)
ml_a, attr = model.score_sample(v_atk)
st_a, devs = baseline.evaluate(f_atk)
ass_a = scorer.assess(ml_a, st_a, f_atk)
enf_state = enforcer.enforce(dev.id, dev.ip_address, ass_a)
report = nlg.generate_report(dev.id, dev.name, ass_a, f_atk, baseline.means, attr, devs)
print(f'3. Attack Injected (CNC_BEACONING) -> Threat Score: {ass_a.threat_score}/100 ({ass_a.threat_level.value})')
print(f'4. Enforcement Level Applied: {enf_state.current_level.value}')
print(f'5. XAI Alert Summary:\n{report.plain_text_summary}')
"
    }
    "api" {
        Write-Host "[GUARDIAN] Starting FastAPI Gateway Server on http://127.0.0.1:8000..." -ForegroundColor Cyan
        uvicorn guardian.api.app:create_app --factory --host 127.0.0.1 --port 8000 --reload
    }
    "paper-assets" {
        Write-Host "[GUARDIAN] Exporting IEEE paper tables and assets..." -ForegroundColor Cyan
        python -m guardian.eval.report --export-paper-assets
    }
    "check-commits" {
        git log --oneline -n 20
    }
    "clean" {
        Write-Host "[GUARDIAN] Cleaning caches and coverage artifacts..." -ForegroundColor Cyan
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue .pytest_cache, .coverage, htmlcov, .mypy_cache, .ruff_cache
    }
    default {
        Write-Host "Usage: .\make.ps1 <setup|lint|type|test|cov|eval|demo|api|paper-assets|check-commits|clean>" -ForegroundColor Yellow
    }
}
