PYTHON_DIR := sdks/python
TYPESCRIPT_DIR := sdks/typescript
RUST_SDK_DIR := sdks/rust
DOCS_DIR := docs

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
check: ## Run formatting, lint, package metadata, and workflow checks
	@cargo fmt --all --check
	@cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
	@uv lock --check
	@uv run --locked ruff check $(PYTHON_DIR)
	@uv run --locked ruff format --check $(PYTHON_DIR)
	@pnpm --filter @owlauth/client check
	@pnpm --filter @owlauth/docs build
	@test -f $(DOCS_DIR)/.vitepress/dist/sitemap.xml
	@grep -q 'https://owlauth.owlfoundry.org/' $(DOCS_DIR)/.vitepress/dist/sitemap.xml
	@grep -qx 'Sitemap: https://owlauth.owlfoundry.org/sitemap.xml' $(DOCS_DIR)/.vitepress/dist/robots.txt
	@pnpm --filter @owlauth/docs run deploy --dry-run
	@scripts/release/test-verify-release.sh
	@actionlint

.PHONY: test
test: ## Run Rust, Python, and TypeScript unit tests
	@cargo test --workspace --all-features --locked
	@uv run --locked pytest
	@pnpm --filter @owlauth/client test

.PHONY: build
build: ## Build the server, SDK distributions, and documentation
	@cargo build --release --locked --package owlauth
	@cd $(PYTHON_DIR) && rm -rf dist && uv run --locked hatchling build -d dist
	@pnpm --filter @owlauth/client build
	@pnpm --filter @owlauth/docs build

.PHONY: package-check
package-check: ## Verify exact SDK distribution contents
	@cd $(PYTHON_DIR) && uv run --locked twine check dist/*
	@cargo package --manifest-path $(RUST_SDK_DIR)/Cargo.toml --locked --allow-dirty
	@cd $(TYPESCRIPT_DIR) && npm pack --dry-run --json | jq -e '.[0].files | any(.path == "LICENSE")'

.PHONY: openapi
openapi: ## Generate the current OpenAPI document on stdout
	@cargo run --quiet --locked --package owlauth -- --openapi

.PHONY: docs
docs: ## Serve documentation locally
	@pnpm --filter @owlauth/docs dev

.PHONY: docs-build
docs-build: ## Build documentation for deployment
	@pnpm --filter @owlauth/docs build

.PHONY: docs-deploy
docs-deploy: ## Deploy documentation to Cloudflare Workers
	@pnpm --filter @owlauth/docs run deploy

.PHONY: docker-build
docker-build: ## Build and smoke-test the local server image
	@docker build --tag owlauth:dev .
	@scripts/docker/smoke-server-image.sh owlauth:dev

.PHONY: help
help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help
