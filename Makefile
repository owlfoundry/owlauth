PYTHON_DIR := sdks/python
TYPESCRIPT_DIR := sdks/typescript
RUST_SDK_DIR := sdks/rust
DOCS_DIR := docs
SERVER_WEB_DIR := crates/owlauth-server/web
DEV_COMPOSE := docker compose --file dev/compose.yml
ACTIONLINT := go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7

.PHONY: install
install: ## Install locked development dependencies
	@cargo fetch --locked
	@uv sync --all-packages --locked
	@pnpm install --frozen-lockfile

.PHONY: format
format: ## Format Rust and Python sources
	@cargo fmt --all
	@uv run --locked ruff format $(PYTHON_DIR)

.PHONY: check
check: web-verify ## Run formatting, lint, package metadata, and workflow checks
	@cargo fmt --all --check
	@cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
	@uv lock --check
	@uv run --locked ruff check $(PYTHON_DIR)
	@uv run --locked ruff format --check $(PYTHON_DIR)
	@pnpm --filter @owlauth/server-web check
	@pnpm --filter @owlauth/client check
	@python3 scripts/check-markdown-links.py
	@pnpm --filter @owlauth/docs build
	@test -f $(DOCS_DIR)/.vitepress/dist/sitemap.xml
	@grep -q 'https://owlauth.owlfoundry.org/' $(DOCS_DIR)/.vitepress/dist/sitemap.xml
	@grep -qx 'Sitemap: https://owlauth.owlfoundry.org/sitemap.xml' $(DOCS_DIR)/.vitepress/dist/robots.txt
	@pnpm --filter @owlauth/docs run deploy --dry-run
	@scripts/release/test-verify-release.sh
	@python3 scripts/release/test-changelog.py
	@sh -n scripts/install.sh
	@scripts/test-installers.sh
	@cmp scripts/install.sh crates/owlauth-cli/assets/install.sh
	@cmp scripts/install.ps1 crates/owlauth-cli/assets/install.ps1
	@$(ACTIONLINT)

.PHONY: test
test: web-build ## Run Rust, Python, and TypeScript unit tests
	@cargo test --workspace --all-features --locked
	@uv run --locked pytest
	@pnpm --filter @owlauth/server-web test
	@pnpm --filter @owlauth/client test

.PHONY: build
build: web-build ## Build the server, CLI, SDK distributions, and documentation
	@cargo build --release --locked --package owlauth-server --package owlauth-cli
	@cd $(PYTHON_DIR) && rm -rf dist && uv run --locked hatchling build -d dist
	@pnpm --filter @owlauth/client build
	@pnpm --filter @owlauth/docs build

.PHONY: package-check
package-check: web-build ## Verify exact registry distribution contents
	@cd $(PYTHON_DIR) && uv run --locked twine check dist/*
	@cargo package --manifest-path crates/owlauth-types/Cargo.toml --locked --allow-dirty
	@cargo package --manifest-path crates/owlauth-cli/Cargo.toml --locked --allow-dirty
	@cargo package --manifest-path $(RUST_SDK_DIR)/Cargo.toml --locked --allow-dirty
	@scripts/test-server-package.sh
	@cd $(TYPESCRIPT_DIR) && npm pack --dry-run --json | jq -e '.[0].files | any(.path == "LICENSE")'

.PHONY: openapi
openapi: ## Export complete Runtime and Control OpenAPI documents
	@mkdir -p target/openapi
	@cargo run --quiet --locked --package owlauth-types --bin export-openapi -- runtime target/openapi/runtime.json
	@cargo run --quiet --locked --package owlauth-types --bin export-openapi -- control target/openapi/control.json

.PHONY: web-contracts
web-contracts: ## Regenerate committed hosted-web contract types
	@pnpm --filter @owlauth/server-web contracts:generate

.PHONY: web-check
web-check: ## Lint, type-check, and test hosted-web sources and build scripts
	@pnpm --filter @owlauth/server-web check

.PHONY: web-build
web-build: ## Rebuild deterministic Runtime and Control embedded assets
	@pnpm --filter @owlauth/server-web build

.PHONY: web-e2e
web-e2e: web-build ## Run the real PostgreSQL/Rust/browser provisioning-readiness journey
	@pnpm --filter @owlauth/server-web test:e2e

.PHONY: web-verify
web-verify: web-build ## Rebuild hosted-web assets and reject committed contract or asset drift
	@git diff --exit-code -- $(SERVER_WEB_DIR)/src/generated $(SERVER_WEB_DIR)/dist

.PHONY: docs
docs: ## Serve documentation locally
	@pnpm --filter @owlauth/docs dev

.PHONY: docs-build
docs-build: ## Build documentation for deployment
	@pnpm --filter @owlauth/docs build

.PHONY: docs-deploy
docs-deploy: ## Deploy documentation to Cloudflare Workers
	@pnpm --filter @owlauth/docs run deploy

.PHONY: dev
dev: ## Build web assets, start local infrastructure, and run Runtime plus Control
	@test -f .env || { echo "Missing .env; run: cp .env.example .env" >&2; exit 1; }
	@$(MAKE) web-build
	@$(MAKE) dev-up
	@mkdir -p .local/owlauth/signers .local/owlauth/configuration-secrets
	@set -a; . ./.env; set +a; exec cargo run --locked --package owlauth-server

.PHONY: dev-up
dev-up: ## Start healthy local PostgreSQL and Redis services
	@$(DEV_COMPOSE) up --detach --wait

.PHONY: dev-down
dev-down: ## Stop local development infrastructure
	@$(DEV_COMPOSE) down --remove-orphans

.PHONY: dev-reset
dev-reset: ## Recreate local infrastructure and remove all local data
	@$(DEV_COMPOSE) down --volumes --remove-orphans
	@$(DEV_COMPOSE) up --detach --wait

.PHONY: dev-logs
dev-logs: ## Follow local PostgreSQL and Redis logs
	@$(DEV_COMPOSE) logs --follow --tail=100

.PHONY: dev-status
dev-status: ## Show local infrastructure status and health
	@$(DEV_COMPOSE) ps

.PHONY: dev-postgres
dev-postgres: ## Open psql in the local PostgreSQL container
	@$(DEV_COMPOSE) exec postgres psql --username "$${OWLAUTH_DEV_POSTGRES_USER:-owlauth}" --dbname "$${OWLAUTH_DEV_POSTGRES_DB:-owlauth}"

.PHONY: dev-redis
dev-redis: ## Open redis-cli in the local Redis container
	@$(DEV_COMPOSE) exec redis redis-cli

.PHONY: test-containers
test-containers: ## Run Docker-backed server integration tests (skip if Docker is unavailable)
	@cargo test --locked --package owlauth-server --test container_infrastructure -- --nocapture

.PHONY: docker-build
docker-build: ## Build and smoke-test the local server image
	@docker build --tag owlauth:dev .
	@scripts/docker/smoke-server-image.sh owlauth:dev

.PHONY: help
help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help
