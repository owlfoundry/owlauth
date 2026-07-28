PYTHON_DIR := sdks/python
TYPESCRIPT_DIR := sdks/typescript
RUST_SDK_DIR := sdks/rust
DOCS_DIR := docs

.PHONY: install
install: ## Install locked development dependencies
	@cargo fetch --locked
	@uv sync --project $(PYTHON_DIR) --locked
	@npm --prefix $(TYPESCRIPT_DIR) ci
	@npm --prefix $(DOCS_DIR) ci

.PHONY: format
format: ## Format Rust and Python sources
	@cargo fmt --all
	@uv run --project $(PYTHON_DIR) ruff format $(PYTHON_DIR)

.PHONY: check
check: ## Run formatting, lint, package metadata, and workflow checks
	@cargo fmt --all --check
	@cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
	@uv lock --project $(PYTHON_DIR) --check
	@uv run --project $(PYTHON_DIR) ruff check $(PYTHON_DIR)
	@uv run --project $(PYTHON_DIR) ruff format --check $(PYTHON_DIR)
	@npm --prefix $(TYPESCRIPT_DIR) run check
	@npm --prefix $(DOCS_DIR) run build
	@scripts/release/test-verify-release.sh
	@actionlint

.PHONY: test
test: ## Run Rust, Python, and TypeScript unit tests
	@cargo test --workspace --all-features --locked
	@uv run --project $(PYTHON_DIR) pytest
	@npm --prefix $(TYPESCRIPT_DIR) test

.PHONY: build
build: ## Build the server, SDK distributions, and documentation
	@cargo build --release --locked --package owlauth
	@cd $(PYTHON_DIR) && rm -rf dist && uv run --locked hatchling build -d dist
	@npm --prefix $(TYPESCRIPT_DIR) run build
	@npm --prefix $(DOCS_DIR) run build

.PHONY: package-check
package-check: ## Verify exact SDK distribution contents
	@cd $(PYTHON_DIR) && uv run --locked twine check dist/*
	@cargo package --manifest-path $(RUST_SDK_DIR)/Cargo.toml --locked --allow-dirty
	@npm --prefix $(TYPESCRIPT_DIR) pack --dry-run

.PHONY: openapi
openapi: ## Generate the current OpenAPI document on stdout
	@cargo run --quiet --locked --package owlauth -- --openapi

.PHONY: docs
docs: ## Serve documentation locally
	@npm --prefix $(DOCS_DIR) run dev

.PHONY: docs-build
docs-build: ## Build documentation for deployment
	@npm --prefix $(DOCS_DIR) run build

.PHONY: docs-deploy
docs-deploy: ## Deploy documentation to Cloudflare Workers
	@npm --prefix $(DOCS_DIR) run deploy

.PHONY: help
help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help
