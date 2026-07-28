.PHONY: help bootstrap export import status clean apply-blueprints test-auth apply-branding remove-branding

# Configuration
AUTHENTIK_URL ?= http://localhost:9000
AUTHENTIK_CONTAINER ?= authentik-server-prod
SCRIPTS_DIR := ./scripts
CONFIG_DIR := ./config
BLUEPRINTS_DIR := ./blueprints

help: ## Show this help message
	@echo "AfterDark Authentik Management CLI"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

bootstrap: ## Complete bootstrap - setup admin, create tokens, configure OAuth
	@echo "🚀 Bootstrapping Authentik..."
	@bash $(SCRIPTS_DIR)/bootstrap_authentik.sh

export: check-token ## Export current configuration to JSON
	@echo "📦 Exporting Authentik configuration..."
	@python3 $(SCRIPTS_DIR)/authentik_client.py --url $(AUTHENTIK_URL) export --output $(CONFIG_DIR)

import: check-token ## Import configuration from JSON (dry-run, manual apply needed)
	@echo "📥 Importing configuration..."
	@python3 $(SCRIPTS_DIR)/authentik_client.py --url $(AUTHENTIK_URL) import --input $(CONFIG_DIR)

apply-blueprints: ## Apply all custom blueprints
	@echo "📋 Applying blueprints..."
	@for blueprint in $(BLUEPRINTS_DIR)/*.yaml; do \
		echo "  Applying $$(basename $$blueprint)..."; \
		docker cp "$$blueprint" $(AUTHENTIK_CONTAINER):/blueprints/custom/$$(basename $$blueprint); \
	done
	@echo "✓ Blueprints copied to container"
	@echo "  Trigger import in Authentik UI or use API"

status: ## Show Authentik status and configuration
	@echo "📊 Authentik Status"
	@echo "===================="
	@echo ""
	@echo "Container Status:"
	@docker ps --filter "name=authentik" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
	@echo ""
	@echo "URL: $(AUTHENTIK_URL)"
	@echo ""
	@if [ -f .env ]; then \
		echo "Configuration:"; \
		grep -v "^#" .env | sed 's/^/  /'; \
	else \
		echo "⚠️  No .env file found. Run 'make bootstrap' first."; \
	fi

list-apps: check-token ## List all applications
	@python3 $(SCRIPTS_DIR)/authentik_client.py --url $(AUTHENTIK_URL) list applications

list-providers: check-token ## List all providers
	@python3 $(SCRIPTS_DIR)/authentik_client.py --url $(AUTHENTIK_URL) list providers

list-flows: check-token ## List all flows
	@python3 $(SCRIPTS_DIR)/authentik_client.py --url $(AUTHENTIK_URL) list flows

list-users: check-token ## List all users
	@python3 $(SCRIPTS_DIR)/authentik_client.py --url $(AUTHENTIK_URL) list users

list-groups: check-token ## List all groups
	@python3 $(SCRIPTS_DIR)/authentik_client.py --url $(AUTHENTIK_URL) list groups

test-auth: check-token ## Test authentication with current credentials
	@echo "🔐 Testing Authentik authentication..."
	@curl -s -H "Authorization: Bearer $$(grep AUTHENTIK_TOKEN .env | cut -d= -f2)" \
		$(AUTHENTIK_URL)/api/v3/core/applications/ | jq -r '.results | length' > /dev/null && \
		echo "✓ Authentication successful" || echo "✗ Authentication failed"

reset-password: ## Reset admin password (prompts for username)
	@read -p "Enter username: " username; \
	read -s -p "Enter new password: " password; \
	echo ""; \
	docker exec $(AUTHENTIK_CONTAINER) python -m manage shell << PYTHON_EOF \
		from authentik.core.models import User; \
		user = User.objects.get(username='$$username'); \
		user.set_password('$$password'); \
		user.save(); \
		print(f'✓ Password changed for {user.username}'); \
	PYTHON_EOF

create-user: ## Create a new user (interactive)
	@bash $(SCRIPTS_DIR)/create_users.sh --interactive

create-users: ## Create default AfterDark user accounts
	@bash $(SCRIPTS_DIR)/create_users.sh

setup-oauth: ## Setup OAuth2 apps for AfterDark services
	@bash $(SCRIPTS_DIR)/setup_oauth_apps.sh

setup-oauth-interactive: ## Setup OAuth2 app (interactive)
	@bash $(SCRIPTS_DIR)/setup_oauth_apps.sh --interactive

logs: ## Tail Authentik logs
	@docker logs -f $(AUTHENTIK_CONTAINER) 2>&1 | grep -v "^{" || true

apply-branding: ## Apply custom AfterDark branding (removes background images)
	@echo "🎨 Applying custom branding..."
	@bash $(SCRIPTS_DIR)/apply_branding.sh

remove-branding: ## Remove custom branding and restore defaults
	@echo "🔄 Removing custom branding..."
	@docker exec $(AUTHENTIK_CONTAINER) rm -f /web/dist/custom.css /templates/custom/base.html 2>/dev/null || true
	@docker restart $(AUTHENTIK_CONTAINER)
	@echo "✓ Custom branding removed"

clean: ## Remove exported configuration files
	@echo "🧹 Cleaning up..."
	@rm -rf $(CONFIG_DIR)/*.json
	@echo "✓ Cleaned configuration exports"

check-token: ## Internal: Check if API token is configured
	@if [ ! -f .env ] || ! grep -q "AUTHENTIK_TOKEN" .env; then \
		echo "⚠️  No API token found. Run 'make bootstrap' first."; \
		exit 1; \
	fi

install-deps: ## Install Python dependencies
	@echo "📦 Installing dependencies..."
	@pip3 install requests

.DEFAULT_GOAL := help
