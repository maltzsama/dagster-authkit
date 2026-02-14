# examples/authelia/Makefile

.PHONY: up down logs clean restart health test-headers

up:
	@echo "🚀 Starting Authelia + Dagster stack..."
	docker-compose up --build -d
	@echo ""
	@echo "✅ Stack is up!"
	@echo ""
	@echo "📍 Access URLs:"
	@echo "   Dagster:         http://127.0.0.1:3000"
	@echo "   Authelia:        http://127.0.0.1:9091"
	@echo ""
	@echo "👤 Test Users (password: password123):"
	@echo "   Username: admin    → Role.ADMIN"
	@echo "   Username: editor   → Role.EDITOR"
	@echo "   Username: launcher → Role.LAUNCHER"
	@echo "   Username: viewer   → Role.VIEWER"
	@echo ""
	@echo "⏳ Wait ~20s for LDAP seed to complete..."
	@echo ""
	@echo "🔍 Check status:"
	@echo "   make logs-ldap     # LDAP initialization"

down:
	@echo "🛑 Stopping stack..."
	docker-compose down

logs:
	docker-compose logs -f dagster authelia

logs-ldap:
	docker-compose logs -f ldap ldap-seed

clean:
	@echo "🧹 Cleaning up volumes..."
	docker-compose down -v
	rm -rf authelia/db.sqlite3 authelia/notification.txt

restart: down up

health:
	@echo "🏥 Health check..."
	@docker-compose ps