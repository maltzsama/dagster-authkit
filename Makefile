# =============================================================================
# dagster-authkit - Makefile
# Professional development workflow automation
# =============================================================================

.PHONY: help clean install dev test lint format build publish venv venv-activate venv-deactivate check-venv helm-check

# Default target - shows available commands
help:
	@echo ""
	@echo "╔════════════════════════════════════════════════════════════════╗"
	@echo "║           dagster-authkit - Development Commands              ║"
	@echo "╚════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "📦 Environment Management:"
	@echo "  make venv              Create UV virtual environment"
	@echo "  make install           Install production dependencies"
	@echo "  make dev               Install development dependencies"
	@echo "  make clean             Remove build artifacts and cache"
	@echo ""
	@echo "🔧 Development:"
	@echo "  make test              Run test suite"
	@echo "  make test-cov          Run tests with coverage report"
	@echo "  make lint              Check code quality"
	@echo "  make format            Auto-format code"
	@echo "  make check             Run all checks (lint + test)"
	@echo "  make helm-check        Lint and render the Helm chart"
	@echo ""
	@echo "📚 Database Management:"
	@echo "  make init-db           Initialize SQLite database with admin"
	@echo "  make list-users        List all users in database"
	@echo ""
	@echo "🚀 Build & Release:"
	@echo "  make build             Build distribution packages"
	@echo "  make publish-test      Publish to TestPyPI"
	@echo "  make publish           Publish to PyPI (production)"
	@echo ""
	@echo "💡 Tip: Run 'make venv && make dev' to get started"
	@echo ""

# =============================================================================
# Environment Management
# =============================================================================

# Check if UV is installed
check-uv:
	@command -v uv >/dev/null 2>&1 || { \
		echo "❌ UV not found. Installing..."; \
		curl -LsSf https://astral.sh/uv/install.sh | sh; \
	}

# Create virtual environment with UV
venv: check-uv
	@echo "🔨 Creating virtual environment with UV..."
	@uv venv
	@echo "✅ Virtual environment created at .venv/"
	@echo ""
	@echo "💡 To activate:"
	@echo "   source .venv/bin/activate    (Linux/macOS)"
	@echo "   .venv\\Scripts\\activate      (Windows)"
	@echo ""

# Install production dependencies only
install: check-uv
	@echo "📦 Installing production dependencies..."
	@uv pip install -e .
	@echo "✅ Production dependencies installed"

# Install development dependencies
dev: check-uv
	@echo "📦 Installing development dependencies..."
	@uv pip install -e ".[dev,all]"
	@echo "✅ Development environment ready"
	@echo ""
	@echo "🎯 You can now:"
	@echo "   make test       - Run tests"
	@echo "   make lint       - Check code quality"
	@echo "   make format     - Format code"
	@echo ""

# Sync dependencies from pyproject.toml
sync: check-uv
	@echo "🔄 Syncing dependencies..."
	@uv pip sync
	@echo "✅ Dependencies synchronized"

# =============================================================================
# Code Quality
# =============================================================================

# Run test suite
test: check-venv
	@echo "🧪 Running tests..."
	@uv run pytest tests/ -v

# Run tests with coverage
test-cov: check-venv
	@echo "🧪 Running tests with coverage..."
	@uv run pytest tests/ --cov=dagster_authkit --cov-report=html --cov-report=term
	@echo ""
	@echo "📊 Coverage report generated at htmlcov/index.html"

# Lint code
lint: check-venv
	@echo "🔍 Checking code quality..."
	@uv run ruff check dagster_authkit/ tests/ || true
	@uv run black --check dagster_authkit/ tests/ || true
	@echo "✅ Lint check complete"

# Auto-format code
format: check-venv
	@echo "✨ Formatting code..."
	@uv run black dagster_authkit/ tests/
	@uv run ruff check --fix dagster_authkit/ tests/ || true
	@echo "✅ Code formatted"

# Run all checks
check: lint test
	@echo ""
	@echo "✅ All checks passed!"

# =============================================================================
# Database Management
# =============================================================================

# Initialize database with admin user
init-db: check-venv
	@echo "🗄️  Initializing database..."
	@uv run dagster-authkit init-db --with-admin
	@echo "✅ Database initialized"

# List all users
list-users: check-venv
	@echo "👥 Listing users..."
	@uv run dagster-authkit list-users

# Add user (usage: make add-user USER=username)
add-user: check-venv
	@if [ -z "$(USER)" ]; then \
		echo "❌ Error: USER parameter required"; \
		echo "Usage: make add-user USER=username"; \
		exit 1; \
	fi
	@echo "➕ Adding user '$(USER)'..."
	@uv run dagster-authkit add-user $(USER) --admin

# =============================================================================
# Cleanup
# =============================================================================

# Clean all build artifacts and cache
clean:
	@echo "🧹 Cleaning build artifacts..."
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@rm -rf build/ dist/ .eggs/ 2>/dev/null || true
	@rm -rf .pytest_cache/ .coverage htmlcov/ 2>/dev/null || true
	@rm -rf .ruff_cache/ .mypy_cache/ 2>/dev/null || true
	@echo "✅ Cleanup complete"

# Deep clean - removes venv too
clean-all: clean
	@echo "🧹 Deep cleaning (including venv)..."
	@rm -rf .venv/ uv.lock 2>/dev/null || true
	@echo "✅ Deep cleanup complete"

# Lint the Helm chart and render every CI scenario (needs helm; uses
# kubeconform for schema validation when it is installed)
helm-check:
	@.github/scripts/helm-check.sh

# =============================================================================
# Build & Release
# =============================================================================

# Build distribution packages
build: clean check-uv
	@echo "📦 Building distribution packages..."
	@uv build
	@echo "✅ Build complete: dist/"
	@ls -lh dist/

# Check distribution packages
check-dist: check-uv
	@echo "🔍 Checking distribution packages..."
	@uv run twine check dist/*
	@echo "✅ Distribution packages are valid"

# Publish to TestPyPI
publish-test: build check-dist
	@echo "🚀 Publishing to TestPyPI..."
	@echo "⚠️  This will upload to test.pypi.org"
	@read -p "Continue? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		uv run twine upload --repository testpypi dist/*; \
		echo "✅ Published to TestPyPI"; \
	else \
		echo "❌ Cancelled"; \
	fi

# Publish to PyPI (production)
publish: build check-dist
	@echo "🚀 Publishing to PyPI (PRODUCTION)..."
	@echo "⚠️  WARNING: This will publish to the official PyPI!"
	@echo "   Make sure you:"
	@echo "   1. Updated version in pyproject.toml"
	@echo "   2. Updated CHANGELOG.md"
	@echo "   3. Committed all changes"
	@echo ""
	@read -p "Continue? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		uv run twine upload dist/*; \
		echo "✅ Published to PyPI"; \
		echo ""; \
		echo "🎉 Don't forget to:"; \
		echo "   git tag -a v$$(grep '^version' pyproject.toml | cut -d'"' -f2) -m 'Release v$$(grep '^version' pyproject.toml | cut -d'"' -f2)'"; \
		echo "   git push origin v$$(grep '^version' pyproject.toml | cut -d'"' -f2)"; \
	else \
		echo "❌ Cancelled"; \
	fi

# =============================================================================
# Utilities
# =============================================================================

# Check if virtual environment is activated
check-venv:
	@if [ -z "$$VIRTUAL_ENV" ] && [ ! -d ".venv" ]; then \
		echo "❌ No virtual environment found"; \
		echo "Run 'make venv' first"; \
		exit 1; \
	fi

# Show current version
version:
	@echo "📌 Current version:"
	@grep '^version' pyproject.toml | cut -d'"' -f2

# Show project info
info:
	@echo ""
	@echo "📋 Project Information:"
	@echo "  Name:    dagster-authkit"
	@echo "  Version: $$(grep '^version' pyproject.toml | cut -d'"' -f2)"
	@echo "  Python:  $$(cat .python-version 2>/dev/null || echo 'not set')"
	@echo "  UV:      $$(uv --version 2>/dev/null || echo 'not installed')"
	@echo ""
	@if [ -d ".venv" ]; then \
		echo "  Venv:    ✅ .venv/ exists"; \
	else \
		echo "  Venv:    ❌ not created (run 'make venv')"; \
	fi
	@echo ""