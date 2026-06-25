.PHONY: install test scan redteam lint clean

install:
	python -m pip install -e ".[dev]"

test:
	PYTHONPATH=src python -m pytest -q

scan:
	PYTHONPATH=src python -m airte.mcp_audit.scanner examples/vulnerable_mcp_server.py

redteam:
	PYTHONPATH=src python -m airte.redteam.harness --target echo --suite all

lint:
	ruff check src tests || true

clean:
	rm -rf .pytest_cache **/__pycache__ reports/*.json
