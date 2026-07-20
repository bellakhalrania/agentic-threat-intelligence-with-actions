# ============================================================
# Makefile — Agentic Threat Intelligence Platform
# Production deployment commands for Docker Compose (single host)
# ============================================================

.PHONY: help build up down restart logs ps clean backup restore \
        ssl-setup deploy health test shell

SHELL := /bin/bash
COMPOSE_FILES := -f docker-compose.yml -f docker-compose.prod.yml

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ---- Build & Deploy ----

build: ## Build production Docker images
	docker compose $(COMPOSE_FILES) build --no-cache

build-cached: ## Build using cached layers (faster)
	docker compose $(COMPOSE_FILES) build

up: ## Start all services in production mode
	docker compose $(COMPOSE_FILES) up -d

down: ## Stop all services
	docker compose $(COMPOSE_FILES) down

restart: down up ## Restart all services

logs: ## Tail logs from all services
	docker compose $(COMPOSE_FILES) logs -f

logs-threat-intel: ## Tail threat-intel service logs
	docker compose $(COMPOSE_FILES) logs -f threat-intel

logs-neo4j: ## Tail Neo4j service logs
	docker compose $(COMPOSE_FILES) logs -f neo4j

logs-nginx: ## Tail Nginx service logs
	docker compose $(COMPOSE_FILES) logs -f nginx

ps: ## List running services
	docker compose $(COMPOSE_FILES) ps

# ---- Health & Monitoring ----

health: ## Check health of all services
	@echo "=== Threat Intel API ==="
	@curl -s http://localhost:8000/health | python3 -m json.tool || echo "API not reachable"
	@echo ""
	@echo "=== Neo4j ==="
	@docker exec threat-intel-neo4j cypher-shell -u neo4j -p $$(grep NEO4J_PASSWORD .env | cut -d= -f2) "RETURN 'Neo4j OK' AS status" 2>/dev/null || echo "Neo4j not reachable"
	@echo ""
	@echo "=== Nginx ==="
	@docker exec threat-intel-nginx nginx -t 2>&1 || echo "Nginx config error"

# ---- Data Management ----

backup: ## Backup all persistent data volumes
	@echo "Creating backup..."
	@mkdir -p backups
	@docker run --rm -v threat_intel_data:/data -v $$(pwd)/backups:/backup alpine tar czf /backup/threat_intel_data_$$(date +%Y%m%d_%H%M%S).tar.gz -C /data .
	@docker run --rm -v neo4j_data:/data -v $$(pwd)/backups:/backup alpine tar czf /backup/neo4j_data_$$(date +%Y%m%d_%H%M%S).tar.gz -C /data .
	@echo "Backup complete: backups/"

restore: ## Restore data from backup (usage: make restore FILE=backups/backup_file.tar.gz)
	@if [ -z "$(FILE)" ]; then \
		echo "Usage: make restore FILE=backups/backup_file.tar.gz"; \
		exit 1; \
	fi
	@echo "Restoring from $(FILE)..."
	@docker run --rm -v threat_intel_data:/data -v $$(pwd)/backups:/backup alpine tar xzf /backup/$(FILE) -C /data
	@echo "Restore complete. Restart services with: make restart"

# ---- SSL / Security ----

ssl-setup: ## Generate self-signed SSL certificate for development/testing
	@mkdir -p nginx/ssl
	@openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
		-keyout nginx/ssl/key.pem \
		-out nginx/ssl/cert.pem \
		-subj "/C=TN/ST=Tunisia/L=Tunis/O=ThreatIntel/CN=localhost" 2>/dev/null
	@echo "Self-signed SSL certificate generated in nginx/ssl/"
	@echo "WARNING: For production, replace with Let's Encrypt certificates!"

ssl-letsencrypt: ## Generate Let's Encrypt SSL certificate (requires domain + port 80)
	@if [ -z "$(DOMAIN)" ]; then \
		echo "Usage: make ssl-letsencrypt DOMAIN=your-domain.com EMAIL=admin@your-domain.com"; \
		exit 1; \
	fi
	@docker run --rm -p 80:80 -v $$(pwd)/nginx/ssl:/etc/letsencrypt \
		certbot/certbot certonly --standalone \
		-d $(DOMAIN) --email $(EMAIL) --agree-tos --non-interactive
	@echo "Certificate obtained. Update nginx/conf.d/default.conf with the correct paths."

htpasswd: ## Create htpasswd file for admin access (usage: make htpasswd USER=admin)
	@if [ -z "$(USER)" ]; then \
		echo "Usage: make htpasswd USER=admin"; \
		exit 1; \
	fi
	@mkdir -p nginx/htpasswd
	@docker run --rm -it -v $$(pwd)/nginx/htpasswd:/htpasswd httpd:alpine htpasswd -c /htpasswd/admin $(USER)
	@echo "htpasswd file created for user: $(USER)"

# ---- Full Deployment ----

deploy: ssl-setup build up ## Full deployment: SSL setup → build → start
	@echo ""
	@echo "============================================"
	@echo "  Deployment complete!"
	@echo "  API: https://localhost"
	@echo "  Docs: https://localhost/docs"
	@echo "  Neo4j: http://localhost:7474"
	@echo "============================================"

deploy-full: ssl-letsencrypt build up ## Full deployment with Let's Encrypt
	@echo ""
	@echo "============================================"
	@echo "  Deployment complete!"
	@echo "  API: https://$(DOMAIN)"
	@echo "  Docs: https://$(DOMAIN)/docs"
	@echo "============================================"

# ---- Development ----

dev: ## Start in development mode (hot-reload)
	docker compose up -d
	@echo "Development mode started. API: http://localhost:8000"

dev-logs: ## Tail development logs
	docker compose logs -f

# ---- Utilities ----

clean: ## Remove all containers, volumes, and images
	docker compose $(COMPOSE_FILES) down -v --rmi all
	@echo "All containers, volumes, and images removed."

shell: ## Open a shell in the threat-intel container
	docker exec -it threat-intel-platform /bin/bash

test: ## Run tests inside the container
	docker compose $(COMPOSE_FILES) run --rm threat-intel python -m pytest tests/ -v

prune: ## Docker system prune (clean up unused resources)
	docker system prune -af --volumes