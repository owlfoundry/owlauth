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
check: web-verify markdown-check ## Run formatting, lint, package metadata, and workflow checks
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
	@grep -q 'https://owlauth-docs.owlfoundry.org/' $(DOCS_DIR)/.vitepress/dist/sitemap.xml
	@grep -qx 'Sitemap: https://owlauth-docs.owlfoundry.org/sitemap.xml' $(DOCS_DIR)/.vitepress/dist/robots.txt
	@pnpm --filter @owlauth/docs run deploy --dry-run
	@scripts/release/test-verify-release.sh
	@python3 scripts/release/test-changelog.py
	@sh -n scripts/install.sh
	@bash -n scripts/run-web-e2e.sh
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
	@cd $(PYTHON_DIR) && rm -rf dist && uv run --locked hatchling build -t wheel -d dist
	@pnpm --filter @owlauth/client build
	@pnpm --filter @owlauth/docs build

.PHONY: package-check
package-check: web-build ## Build once and inspect local registry package candidates
	@rm -rf dist/package-check && mkdir -p dist/package-check/python dist/package-check/typescript
	@cd $(PYTHON_DIR) && uv run --locked hatchling build -t wheel -d ../../dist/package-check/python
	@wheel="$$(find dist/package-check/python -maxdepth 1 -type f -name '*.whl')"; \
		test "$$(find dist/package-check/python -maxdepth 1 -type f | wc -l | tr -d ' ')" = 1; \
		uv run --locked twine check "$$wheel"; \
		uv run --locked python scripts/sdk_artifact.py inspect --component python --archive "$$wheel"
	@pnpm --filter @owlauth/client build
	@cd $(TYPESCRIPT_DIR) && npm pack --pack-destination ../../dist/package-check/typescript
	@tarball="$$(find dist/package-check/typescript -maxdepth 1 -type f -name '*.tgz')"; \
		test "$$(find dist/package-check/typescript -maxdepth 1 -type f | wc -l | tr -d ' ')" = 1; \
		uv run --locked python scripts/sdk_artifact.py inspect --component typescript --archive "$$tarball"
	@cargo package --manifest-path crates/owlauth-types/Cargo.toml --locked --allow-dirty
	@cargo package --manifest-path $(RUST_SDK_DIR)/Cargo.toml --locked --allow-dirty --no-verify
	@version="$$(sed -n 's/^version = "\([^"]*\)"$$/\1/p' $(RUST_SDK_DIR)/Cargo.toml | head -n 1)"; \
		uv run --locked python scripts/sdk_artifact.py inspect --component rust \
			--archive "target/package/owlauth-client-$${version}.crate"
	@scripts/test-cli-package.sh
	@scripts/test-server-package.sh

.PHONY: openapi
openapi: ## Export complete Runtime, Client, and Control OpenAPI documents
	@mkdir -p target/openapi
	@cargo run --quiet --locked --package owlauth-types --bin export-openapi -- runtime target/openapi/runtime.json
	@cargo run --quiet --locked --package owlauth-types --bin export-openapi -- client target/openapi/client.json
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
web-e2e: web-build ## Qualify exact SDK candidates in the real PostgreSQL/Rust/browser journey
	@pnpm --filter @owlauth/server-web test:e2e

.PHONY: web-verify
web-verify: web-build ## Rebuild hosted-web assets and reject committed contract or asset drift
	@git diff --exit-code -- $(SERVER_WEB_DIR)/src/generated $(SERVER_WEB_DIR)/dist

.PHONY: markdown-check
markdown-check: ## Check Markdown formatting with the pinned pre-commit hook
	@uv run --locked pre-commit run mdformat --all-files

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
dev: ## Build web assets, start local infrastructure, and run all three planes
	@test -f .env || { echo "Missing .env; run: cp .env.example .env" >&2; exit 1; }
	@$(MAKE) web-build
	@$(MAKE) dev-up
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
