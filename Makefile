# GUARDIAN Makefile - Automated Quality Gates & Workflows

PYTHON ?= python
PIP ?= pip
PYTEST ?= pytest
RUFF ?= ruff
MYPY ?= mypy

.PHONY: setup lint type test cov run-sim eval demo api ui paper-assets check-commits clean export-requirements

setup:
	$(PIP) install -e ".[dev]"

export-requirements:
	$(PYTHON) -c "import tomllib; data=tomllib.load(open('pyproject.toml', 'rb')); print('\n'.join(data['project']['dependencies']))" > requirements.txt

lint:
	$(RUFF) check src tests config

type:
	$(MYPY) src/guardian

test:
	$(PYTEST) tests/unit tests/integration -v

cov:
	$(PYTEST) --cov=src/guardian --cov-report=term-missing --cov-report=html tests/

run-sim:
	$(PYTHON) -m guardian.simulator.scenario --scenario config/guardian.yaml

eval:
	$(PYTHON) -m guardian.eval.report

demo:
	$(PYTHON) -m guardian.eval.report --quick

api:
	uvicorn guardian.api.main:app --host 127.0.0.1 --port 8000 --reload

ui:
	cd dashboard && npm run dev

paper-assets:
	$(PYTHON) -m guardian.eval.report --export-paper-assets

check-commits:
	git log --oneline -n 20

clean:
	rm -rf .pytest_cache .coverage htmlcov .mypy_cache
