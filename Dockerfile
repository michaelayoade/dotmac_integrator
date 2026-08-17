# syntax=docker/dockerfile:1.7
#
# The Integrator image. Two stages, one non-root runtime, and NO migration on
# boot.
#
# ## The registry credential never enters a layer
#
# The Dotmac distributions come from the private index, which needs a
# credential. `ARG` and `ENV` both survive into image metadata, and an
# `--index-url` carrying a password survives into the layer that ran it — so
# the token arrives through a BuildKit secret mount, which is present for one
# RUN and is in no layer afterwards:
#
#     DOCKER_BUILDKIT=1 docker build \
#       --secret id=forgejo_token,env=POETRY_HTTP_BASIC_FORGEJO_PASSWORD .
#
# The identity is `ci-reader` (read:package). The publish token is never used
# by this repository: an image build that could overwrite a released artefact
# is a supply-chain risk with no upside.
#
# ## Migrations are not here
#
# There is no entrypoint script, no `alembic upgrade`, and no "migrate if
# needed" check. `scripts/entrypoint.sh` does not exist on purpose. Migrations
# run as the OWNER role in a separate job that must COMPLETE before any runtime
# container starts (see docker-compose.yml). A container that migrates on boot
# runs DDL once per replica, races itself during a rolling deploy, and needs
# owner credentials in the runtime environment — where a compromised web
# process can read them.

ARG PYTHON_VERSION=3.12

# ── Builder ─────────────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_HTTP_BASIC_FORGEJO_USERNAME=ci-reader

# /app, not /build. A virtualenv is not relocatable: `poetry install` writes
# absolute paths into `pyvenv.cfg` and into every console-script shebang, so a
# venv built in /build and copied to /app has `uvicorn` pointing at an
# interpreter that does not exist. The failure is a container that exits
# immediately with "no such file or directory" naming a path nothing in the
# image mentions.
WORKDIR /app
COPY pyproject.toml poetry.lock README.md ./
COPY scripts/check_poetry_toolchain.py ./scripts/check_poetry_toolchain.py
COPY .github/bootstrap/poetry-requirements-py312.txt ./poetry-requirements.txt
# pyproject owns the Poetry version.  The generated bootstrap and committed
# lock must agree before installation, then PATH must resolve to that exact
# hash-verified tool before it may install the application dependencies.
RUN python scripts/check_poetry_toolchain.py --bootstrap poetry-requirements.txt \
    && python -m pip install --disable-pip-version-check --no-cache-dir \
         --require-hashes --only-binary=:all: -r poetry-requirements.txt \
    && python scripts/check_poetry_toolchain.py \
         --bootstrap poetry-requirements.txt --active \
    && poetry check --lock

# `--only main` — no pytest, ruff or mypy in a runtime image.
# `--no-root` — the application is put on PYTHONPATH in the runtime stage
# instead of installed. Installing it here would write a path entry pointing at
# the source, which is copied into the runtime stage instead.
RUN --mount=type=secret,id=forgejo_token,required=true \
    POETRY_HTTP_BASIC_FORGEJO_PASSWORD="$(cat /run/secrets/forgejo_token)" \
    poetry install --only main --no-root

# ── Runtime ─────────────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS runtime

# A fixed high UID rather than whatever `useradd` picks: a volume mounted for
# secret material is chowned by the host, and an ambient UID makes that
# ownership depend on the base image's user list.
ARG APP_UID=10001
ARG APP_GID=10001

RUN groupadd --gid "${APP_GID}" app \
 && useradd --uid "${APP_UID}" --gid "${APP_GID}" --create-home --shell /usr/sbin/nologin app

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY --from=builder --chown=app:app /app/.venv /app/.venv
COPY --chown=app:app src ./src
COPY --chown=app:app alembic.ini ./alembic.ini
COPY --chown=app:app migrations ./migrations

# NOT root. Everything above this line runs as root and everything after it
# does not; there is no `USER root` later, and CI asserts the built image's
# default user is unprivileged.
USER app

EXPOSE 8080

# The RUNTIME command. It binds a port; it does not touch DDL.
#
# `sh -c` with `exec`, not a bare exec-form array: HOST and PORT are knobs with
# documented defaults like every other value in this deployment, and an array
# cannot expand a variable. `exec` replaces the shell so uvicorn is PID 1 and
# receives SIGTERM directly — without it the shell holds PID 1, swallows the
# signal, and every deploy ends in a ten-second kill instead of a graceful
# drain (which is where the lifespan releases its leases).
#
# The migration job overrides this with
#   python -m dotmac_integrator.migrate upgrade heads
# and runs with MIGRATION_DATABASE_URL, as the owner role, to completion.
CMD ["sh", "-c", "exec uvicorn --factory dotmac_integrator.assembly:create_app --host \"${HOST:-0.0.0.0}\" --port \"${PORT:-8080}\""]
