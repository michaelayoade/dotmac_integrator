.DEFAULT_GOAL := help
.PHONY: help install lint format-check type-check test check migrate run outdated

help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n",$$1,$$2}'

install: ## Install pinned dependencies (needs registry credentials)
	poetry install

lint: ## Ruff lint
	poetry run ruff check .

format-check: ## Formatting is a gate, not a recipe line — CI runs it as its own job
	poetry run ruff format --check .

type-check: ## mypy strict
	poetry run mypy

test: ## Architecture + unit tests (no database)
	poetry run pytest tests -q --ignore=tests/composition

check: lint format-check type-check test ## Everything CI runs except the database job

migrate: ## Apply every composed lineage AS THE OWNER. Never run on boot.
	# `heads`, PLURAL — `head` upgrades ONE branch and reports success, which
	# with two composed lineages means a half-migrated database that looks fine.
	poetry run alembic upgrade heads

run: ## Development server
	poetry run uvicorn --factory dotmac_integrator.assembly:create_app \
		--host $${HOST:-127.0.0.1} --port $${PORT:-8080} --reload

outdated: ## Show newer releases of the pinned Dotmac distributions
	poetry show --outdated dotmac-kernel dotmac-integration || true
