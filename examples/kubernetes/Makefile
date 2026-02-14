NAMESPACE = authkit-demo

.PHONY: up down restart logs-authelia logs-caddy logs-dagster build-dagster connect

all: up

# 1. Builda a imagem
build:
	@echo "🏗️  [1/3] Buildando imagem do Dagster (contexto local)..."
	@eval $$(minikube docker-env) && docker build -t dagster-authkit:local --build-arg EXTRAS=sqlite ../../

# 2. Sobe toda a infraestrutura
up:
	@echo "🚀 [2/3] Subindo infraestrutura no Kubernetes..."
	# Garante que o namespace existe
	@kubectl create namespace $(NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -
	
	@echo "🗄️  Subindo LDAP..."
	@kubectl apply -f k8s/ldap/
	
	@echo "🛡️  Subindo Authelia..."
	@kubectl apply -f k8s/authelia/

	@echo "📊 Subindo Dagster..."
	@kubectl apply -f k8s/dagster/
	
	@echo "🌐 Subindo Caddy (LoadBalancer)..."
	@kubectl apply -f k8s/caddy/
	
	@echo ""
	@echo "✅ Build e Deploy finalizados!"
	@echo "⚠️  PRÓXIMO PASSO OBRIGATÓRIO:"
	@echo "   Abra OUTRO terminal e rode: make connect"
	@echo ""

# 3. O comando que faltava: O Túnel de Rede
connect:
	@echo "🔌 Iniciando túnel de rede (precisa de sudo)..."
	@echo "🛑 Mantenha este terminal aberto!"
	@minikube tunnel

down:
	@echo "🔥 Destruindo tudo..."
	kubectl delete namespace $(NAMESPACE)

restart:
	@echo "♻️  Reiniciando deployments..."
	kubectl rollout restart deployment -n $(NAMESPACE)

# Logs
logs-authelia:
	kubectl logs -l app=authelia -n $(NAMESPACE) -f
logs-caddy:
	kubectl logs -l app=caddy -n $(NAMESPACE) -f
logs-dagster:
	kubectl logs -l app=dagster -n $(NAMESPACE) -f