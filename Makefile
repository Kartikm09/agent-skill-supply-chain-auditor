PYTHON ?= python3

.PHONY: setup lint compile test sample benchmark verify clean

setup:
	$(PYTHON) -m pip install -r requirements-dev.txt -e .

lint:
	$(PYTHON) -m ruff check src scripts tests
	$(PYTHON) -m ruff format --check src scripts tests

compile:
	$(PYTHON) -m compileall -q src scripts tests

test:
	$(PYTHON) -m pytest

sample:
	$(PYTHON) -m skill_auditor scan fixtures/vulnerable/broad-mcp \
		--output-dir reports/sample --format all --fail-on none
	cp reports/sample/scan-report.json dashboard/data/sample-scan.json

benchmark:
	$(PYTHON) scripts/evaluate_fixtures.py \
		--manifest fixtures/labels.json --output-dir reports/evaluation

verify: lint compile test sample benchmark
	$(PYTHON) scripts/check_report_determinism.py
	$(PYTHON) scripts/secret_scan.py
	$(PYTHON) scripts/validate_repository.py

clean:
	rm -rf .pytest_cache .ruff_cache build dist src/*.egg-info reports/local
