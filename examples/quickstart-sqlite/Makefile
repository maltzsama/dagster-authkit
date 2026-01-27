# ========================================
# Dagster AuthKit - SQLite Quickstart
# ========================================

.PHONY: help up down logs restart shell clean test-health test-login open

help:
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║      Dagster AuthKit - SQLite Quickstart               ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Quick Commands:"
	@echo "  make up              - Start Dagster (SQLite backend)"
	@echo "  make down            - Stop containers"
	@echo "  make logs            - Show logs (follow mode)"
	@echo "  make restart         - Restart everything"
	@echo ""
	@echo "Utilities:"
	@echo "  make shell           - Open bash in container"
	@echo "  make test-health     - Test health endpoint"
	@echo "  make test-login      - Test login page"
	@echo "  make open            - Open browser to Dagster UI"
	@echo "  make clean           - Remove ALL data (SQLite DB)"
	@echo ""

up:
	@echo "🚀 Starting SQLite Quickstart..."
	@docker-compose up -d
	@echo ""
	@echo "⏳ Waiting for Dagster to initialize..."
	@sleep 8
	@echo ""
	@echo "✅ Dagster AuthKit is running!"
	@echo ""
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  🌐 URL:    http://localhost:3000"
	@echo "  👤 User:   admin"
	@echo "  🔑 Pass:   (check logs above for auto-generated password)"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo ""
	@echo "💡 Tip: Run 'make logs' to see startup logs"
	@echo "💡 Tip: Run 'make open' to open browser"
	@echo ""

down:
	@echo "🛑 Stopping containers..."
	@docker-compose down
	@echo "✅ Stopped"

logs:
	@docker-compose logs -f dagster

restart:
	@echo "🔄 Restarting..."
	@$(MAKE) down
	@sleep 2
	@$(MAKE) up

shell:
	@echo "🐚 Opening bash shell..."
	@docker-compose exec dagster bash

test-health:
	@echo "🏥 Testing health endpoint..."
	@echo ""
	@curl -s http://localhost:3000/auth/health | python -m json.tool || echo "❌ Health check failed"

test-login:
	@echo "🧪 Testing login page..."
	@echo ""
	@curl -sI http://localhost:3000/auth/login | head -n 1

open:
	@echo "🌐 Opening browser..."
	@command -v open >/dev/null 2>&1 && open http://localhost:3000 || \
	 command -v xdg-open >/dev/null 2>&1 && xdg-open http://localhost:3000 || \
	 echo "❌ Could not detect browser. Open manually: http://localhost:3000"

clean:
	@echo "⚠️  WARNING: This will DELETE the SQLite database!"
	@read -p "Are you sure? [y/N]: " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo ""
	@echo "🗑️  Stopping containers and removing volumes..."
	@docker-compose down -v
	@echo "🗑️  Removing local database file..."
	@rm -f dagster_auth.db
	@echo "✅ All data removed!"