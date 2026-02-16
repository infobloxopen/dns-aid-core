# DNS-AID Core Makefile
# Usage: make [target]

.PHONY: install install-dev test test-cov lint type-check format clean build changelog help

help:
	@echo "DNS-AID Core Development Commands"
	@echo ""
	@echo "  make install      Install package"
	@echo "  make install-dev  Install with dev dependencies"
	@echo "  make test         Run unit tests"
	@echo "  make test-cov     Run tests with coverage"
	@echo "  make lint         Run ruff linter"
	@echo "  make type-check   Run mypy type checker"
	@echo "  make format       Format code with ruff"
	@echo "  make clean        Remove build artifacts"
	@echo "  make build        Build distribution package"
	@echo "  make changelog    Preview changelog for next release"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev,cli,mcp,route53,jws]"
	pre-commit install

test:
	pytest tests/unit/ -v

test-cov:
	pytest tests/unit/ --cov=dns_aid --cov-report=term-missing --cov-report=html

lint:
	ruff check src/ tests/

type-check:
	mypy src/dns_aid

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

build: clean
	python -m build

changelog:  ## Preview changelog for next release
	git-cliff --latest --strip header
