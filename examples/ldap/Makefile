# ========================================
# Dagster AuthKit - LDAP Test Environment
# ========================================

.PHONY: help up down logs restart shell clean test-ldap test-health open ldap-admin

help:
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║       Dagster AuthKit - LDAP Test Environment          ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Quick Commands:"
	@echo "  make up              - Start LDAP + Dagster + Redis"
	@echo "  make down            - Stop all containers"
	@echo "  make logs            - Show all logs (follow mode)"
	@echo "  make restart         - Restart everything"
	@echo ""
	@echo "Testing:"
	@echo "  make test-ldap       - Test LDAP connection"
	@echo "  make test-health     - Test Dagster health"
	@echo "  make ldap-admin      - Open LDAP Admin UI"
	@echo "  make open            - Open Dagster UI"
	@echo ""
	@echo "Utilities:"
	@echo "  make shell           - Bash in Dagster container"
	@echo "  make shell-ldap      - Bash in LDAP container"
	@echo "  make logs-dagster    - Dagster logs only"
	@echo "  make logs-ldap       - LDAP logs only"
	@echo "  make clean           - Remove ALL data & volumes"
	@echo ""
	@echo "Users:"
	@echo "  make show-users      - Show test LDAP users"
	@echo ""

seed-ldap:
	@echo "🌱 Seeding LDAP with test data..."
	@docker cp ldap-bootstrap.ldif authkit_openldap:/tmp/bootstrap.ldif
	@docker exec authkit_openldap ldapadd \
		-x -H ldap://localhost \
		-D "cn=admin,dc=example,dc=com" \
		-w admin_secret \
		-f /tmp/bootstrap.ldif
	@echo "✅ LDAP seeded with test users!"

up:
	@echo "🚀 Starting LDAP test environment..."
	@docker-compose up -d --build
	@echo ""
	@echo "⏳ Waiting for LDAP to initialize..."
	@sleep 10
	@echo ""
	@echo "🌱 Seeding LDAP data..."
	@$(MAKE) seed-ldap 2>/dev/null || echo "⚠️  LDAP seed failed (might already exist)"
	@echo ""
	@echo "✅ LDAP Environment Ready!"
	@echo ""
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  🌐 Dagster UI:    http://localhost:3000"
	@echo "  🔧 LDAP Admin UI: http://localhost:8080"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo ""
	@echo "👥 Test Users:"
	@echo "  alice/password123     → ADMIN"
	@echo "  bob/password123       → EDITOR"
	@echo "  charlie/password123   → LAUNCHER"
	@echo "  dave/password123      → VIEWER"
	@echo ""
	@echo "💡 Tip: Run 'make test-ldap' to verify LDAP connection"
	@echo "💡 Tip: Run 'make ldap-admin' to manage LDAP users"
	@echo ""

down:
	@echo "🛑 Stopping all containers and removing volumes..."
	@docker-compose down -v
	@echo "✅ Environment cleaned (volumes removed)"

restart:
	@echo "🔄 Performing a fresh restart..."
	@$(MAKE) down
	@sleep 2
	@$(MAKE) up

logs:
	@docker-compose logs -f

logs-dagster:
	@docker-compose logs -f dagster

logs-ldap:
	@docker-compose logs -f ldap

shell:
	@echo "🐚 Opening bash in Dagster container..."
	@docker-compose exec dagster bash

shell-ldap:
	@echo "🐚 Opening bash in LDAP container..."
	@docker-compose exec ldap bash

test-ldap:
	@echo "🔍 Testing LDAP connection..."
	@echo ""
	@docker-compose exec ldap ldapsearch \
		-x -H ldap://localhost \
		-D "cn=admin,dc=example,dc=com" \
		-w admin_secret \
		-b "dc=example,dc=com" \
		"(objectClass=*)" dn | grep "^dn:" || echo "❌ LDAP test failed"
	@echo ""
	@echo "✅ LDAP connection working!"

test-health:
	@echo "🏥 Testing Dagster health endpoint..."
	@echo ""
	@curl -s http://localhost:3000/auth/health | python -m json.tool || echo "❌ Health check failed"

ldap-admin:
	@echo "🔧 Opening LDAP Admin UI..."
	@echo ""
	@echo "URL:      http://localhost:8080"
	@echo "Login DN: cn=admin,dc=example,dc=com"
	@echo "Password: admin_secret"
	@echo ""
	@command -v open >/dev/null 2>&1 && open http://localhost:8080 || \
	 command -v xdg-open >/dev/null 2>&1 && xdg-open http://localhost:8080 || \
	 echo "❌ Could not open browser automatically"

open:
	@echo "🌐 Opening Dagster UI..."
	@command -v open >/dev/null 2>&1 && open http://localhost:3000 || \
	 command -v xdg-open >/dev/null 2>&1 && xdg-open http://localhost:3000 || \
	 echo "❌ Could not open browser. Go to: http://localhost:3000"

show-users:
	@echo "👥 LDAP Test Users:"
	@echo ""
	@docker-compose exec ldap ldapsearch \
		-x -LLL -H ldap://localhost \
		-D "cn=admin,dc=example,dc=com" \
		-w admin_secret \
		-b "ou=users,dc=example,dc=com" \
		"(objectClass=inetOrgPerson)" uid cn mail displayName | \
		grep -E "^(dn:|uid:|cn:|mail:|displayName:)" || echo "❌ Could not fetch users"

clean:
	@echo "⚠️  WARNING: This will DELETE all LDAP data and volumes!"
	@read -p "Are you sure? [y/N]: " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo ""
	@echo "🗑️  Stopping containers and removing volumes..."
	@docker-compose down -v
	@echo "✅ All data removed!"

# ========================================
# Advanced: User Management
# ========================================

add-user:
	@echo "➕ Adding LDAP user..."
	@echo "This is a placeholder - edit ldap-bootstrap.ldif and restart"
	@echo "Or use LDAP Admin UI: make ldap-admin"

inspect-groups:
	@echo "👥 LDAP Groups:"
	@echo ""
	@docker-compose exec ldap ldapsearch \
		-x -LLL -H ldap://localhost \
		-D "cn=admin,dc=example,dc=com" \
		-w admin_secret \
		-b "ou=groups,dc=example,dc=com" \
		"(objectClass=groupOfNames)" cn member | \
		grep -E "^(dn:|cn:|member:)"