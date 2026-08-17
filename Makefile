.DEFAULT_GOAL := help
.PHONY: help install poetry-lock-check lint format-check type-check test check migrate run outdated \
        image image-audit compose-up compose-down bootstrap-operator

# Every value is an overridable knob with a documented default (AGENTS.md
# § "Everything by config"). Nothing below hardcodes a registry, tag or port.
INTEGRATOR_IMAGE ?= registry.dotmac.io/dotmac/integrator
INTEGRATOR_TAG   ?= dev
IMAGE            ?= $(INTEGRATOR_IMAGE):$(INTEGRATOR_TAG)

help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n",$$1,$$2}'

install: ## Install pinned dependencies (needs registry credentials)
	poetry install

poetry-lock-check: ## Exact Poetry pin + committed lock; never regenerates
	python3 scripts/check_poetry_toolchain.py --active
	poetry check --lock

lint: ## Ruff lint
	poetry run ruff check .

format-check: ## Formatting is a gate, not a recipe line — CI runs it as its own job
	poetry run ruff format --check .

type-check: ## mypy strict
	poetry run mypy

test: ## Architecture + unit tests (no database)
	poetry run pytest tests -q --ignore=tests/composition

check: poetry-lock-check lint format-check type-check test ## Everything CI runs except the database job

migrate: ## Apply every composed lineage AS THE OWNER. Never run on boot.
	# NOT the bare `alembic` CLI: it resolves version_locations before env.py
	# runs, finds no revisions, and exits 0 against an empty database.
	# `heads` is plural — `head` would upgrade one of the two lineages.
	poetry run python -m dotmac_integrator.migrate upgrade heads

run: ## Development server
	poetry run uvicorn --factory dotmac_integrator.assembly:create_app \
		--host $${HOST:-127.0.0.1} --port $${PORT:-8080} --reload

outdated: ## Show newer releases of the pinned Dotmac distributions
	poetry show --outdated | awk '$$1 ~ /^dotmac-/' || true

bootstrap-operator: ## Create/reset the first operator. OWNER credentials, out of band.
	# The operations surface is guarded, so the first operator cannot be made
	# through it — and there is no HTTP self-registration path for a platform
	# actor, ever. Password from OPERATOR_PASSWORD or a prompt; never argv.
	poetry run python -m dotmac_integrator.bootstrap_operator --email "$(EMAIL)"

image: ## Build the runtime image. Registry token via a BuildKit secret, never a layer.
	@test -n "$$POETRY_HTTP_BASIC_FORGEJO_PASSWORD" || \
		{ echo "POETRY_HTTP_BASIC_FORGEJO_PASSWORD is unset (OpenBao: secret/dotmac/forgejo/read-token)"; exit 1; }
	DOCKER_BUILDKIT=1 docker build \
		--secret id=forgejo_token,env=POETRY_HTTP_BASIC_FORGEJO_PASSWORD \
		-t $(IMAGE) .

image-audit: ## What CI asserts about the built image: non-root, no boot migration, pins.
	./scripts/audit_image.sh $(IMAGE)

compose-up: ## Migration job to completion, THEN the runtime. Never the other order.
	docker compose up -d --wait

compose-down: ## Stop the runtime. Data survives; this deployment owns no volume.
	docker compose down
