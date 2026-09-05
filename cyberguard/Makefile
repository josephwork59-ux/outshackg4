PY ?= python3
export PYTHONPATH := $(CURDIR)

.PHONY: help demo test scan lint clean

help:
	@echo "make demo   - run the seeded scenario end-to-end and check acceptance criteria"
	@echo "make test   - run the unit test suite (needs pytest)"
	@echo "make scan   - run a scan from demo/scenario.json via the CLI"
	@echo "make lint   - byte-compile every module (syntax check, no deps)"
	@echo "make clean  - remove generated reports and caches"

demo:
	$(PY) -m demo.run_demo

test:
	$(PY) -m pytest -q

scan:
	@$(PY) -m cli scan --config demo/scenario.json; \
	rc=$$?; \
	if [ $$rc -eq 2 ]; then echo "(exit 2: high/critical findings present - expected for the demo)"; exit 0; fi; \
	exit $$rc

lint:
	$(PY) -m compileall -q agents contracts llm orchestrator tools cli.py

clean:
	rm -rf reports/*.json reports/*.md .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} +
