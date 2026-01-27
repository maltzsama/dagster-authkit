# ========================================
# Dagster AuthKit - Root Makefile
# ========================================

.PHONY: help install dev test lint format clean build docker-up docker-down docker-logs

# ========================================
# Help
# ========================================

help:
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║         Dagster AuthKit - Development Commands         ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "📦 Installation & Setup:"
	@echo "  make install         - Install package in editable mode"
	@echo "  make install-dev     - Install with dev dependencies"
	@echo "  make install-all     - Install with all extras (SQL, Redis, LDAP)"
	@echo ""
	@echo "🔧 Development:"
	@echo "  make dev             - Start dev environment (PostgreSQL + Redis)"
	@echo "  make test            - Run tests"
	@echo "  make lint            - Run linter (ruff)"
	@echo "  make format          - Format code (black)"
	@echo ""
	@echo "🐳 Docker:"
	@echo "  make docker-up       - Start dev stack (docker-compose)"
	@echo "  make docker-down     - Stop dev stack"
	@echo "  make docker-logs     - Show container logs"
	@echo "  make docker-shell    - Open shell in Dagster container"
	@echo "  make docker-clean    - Remove all volumes and data"
	@echo ""
	@echo "🏗️  Build & Distribution:"
	@echo "  make build           - Build package (wheel + sdist)"
	@echo "  make clean           - Clean build artifacts"
	@echo ""
	@echo "📚 Examples:"
	@echo "  make example-ldap    - Go to LDAP example directory"
	@echo "  make example-sqlite  - Go to SQLite quickstart directory"
	@echo ""

# ========================================
# Installation
# ========================================

install:
	@echo "📦 Installing dagster-authkit (editable mode)..."
	pip install -e .

install-dev:
	@echo "📦 Installing dagster-authkit with dev dependencies..."
	pip install -e ".[dev,sqlite]"

install-all:
	@echo "📦 Installing dagster-authkit with ALL extras..."
	pip install -e ".[all,dev]"

# ========================================
# Development
# ========================================

dev: docker-up
	@echo ""
	@echo "✅ Dev environment ready!"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Initialize database: dagster-authkit init-db --with-admin"
	@echo "  2. Start Dagster:       dagster-authkit -h 0.0.0.0 -p 3000 --empty-workspace"
	@echo "  3. Open browser:        http://localhost:3000"
	@echo ""

test:
	@echo "🧪 Running tests..."
	pytest tests/ -v

lint:
	@echo "🔍 Running linter (ruff)..."
	ruff check dagster_authkit/

format:
	@echo "✨ Formatting code (black)..."
	black dagster_authkit/ tests/

# ========================================
# Docker (Dev Stack)
# ========================================

docker-up:
	@echo "🐳 Starting dev stack (PostgreSQL + Redis)..."
	docker-compose up -d
	@echo "⏳ Waiting for services to be ready..."
	@sleep 5
	@echo "✅ Services are up!"
	@echo ""
	@echo "Services:"
	@echo "  - PostgreSQL: localhost:5432"
	@echo "  - Redis:      localhost:6379"
	@echo ""

docker-down:
	@echo "🛑 Stopping dev stack..."
	docker-compose down

docker-logs:
	@docker-compose logs -f

docker-shell:
	@echo "🐚 Opening shell in Dagster container..."
	@docker-compose exec dagster bash

docker-clean:
	@echo "⚠️  WARNING: This will delete ALL volumes and data!"
	@read -p "Are you sure? [y/N]: " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo "🗑️  Cleaning up..."
	docker-compose down -v
	@echo "✅ Cleaned"

# ========================================
# Build & Distribution
# ========================================

build: clean
	@echo "🏗️  Building package..."
	python -m build
	@echo "✅ Build complete! Check dist/"

clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "✅ Cleaned"

# ========================================
# Examples (Shortcuts)
# ========================================

example-ldap:
	@echo "📂 Opening LDAP example directory..."
	@cd examples/ldap && $(SHELL)

example-sqlite:
	@echo "📂 Opening SQLite quickstart directory..."
	@cd examples/quickstart-sqlite && $(SHELL)

# ========================================
# Database Management (CLI shortcuts)
# ========================================

init-db:
	@echo "🗄️  Initializing database..."
	dagster-authkit init-db --with-admin

add-user:
	@echo "👤 Adding user..."
	dagster-authkit add-user

list-users:
	@echo "📋 Listing users..."
	dagster-authkit list-users

# ========================================
# CI/CD Helpers
# ========================================

ci-test: install-dev lint test
	@echo "✅ CI tests passed!"

ci-build: clean build
	@echo "✅ CI build complete!"