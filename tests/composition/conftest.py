"""The scratch database every composition test shares.

Moved out of `test_the_lineages_compose.py` when a second composition module
needed it: a fixture imported from one test module into another is a fixture
whose lifetime nobody can reason about, and pytest already has a place for
shared ones.
"""

from __future__ import annotations

import os
import subprocess
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


def _admin_url() -> str:
    url = os.getenv("TEST_MIGRATION_DATABASE_URL")
    if not url:
        pytest.skip("TEST_MIGRATION_DATABASE_URL unset — needs PostgreSQL")
    return url


@pytest.fixture(scope="module")
def migrated() -> Iterator[str]:
    """A scratch database, migrated through every composed lineage.

    Scratch rather than the CI database itself so a failure leaves nothing
    behind, and so the roles below can be created without colliding with
    whatever else the runner is doing.
    """
    base = _admin_url()
    name = f"compose_{uuid.uuid4().hex[:12]}"
    root = create_engine(base, isolation_level="AUTOCOMMIT")
    with root.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
        for role in ("app_user", "platform_api", "app_admin"):
            conn.execute(
                text(
                    "DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE "
                    f"rolname='{role}') THEN CREATE ROLE {role} LOGIN; END IF; END$$"
                )
            )

    # `render_as_string(hide_password=False)`, NOT `str(url)`. SQLAlchemy masks
    # the password to `***` when a URL is stringified, so `str()` hands Alembic a
    # DSN that cannot authenticate — and the failure surfaces as
    # "password authentication failed", which reads like a broken CI service
    # rather than like a masked credential.
    scratch = make_url(base).set(database=name).render_as_string(hide_password=False)

    # `heads`, PLURAL. This deployment composes two independent lineages with
    # distinct branch labels, and `head` upgrades one branch — silently leaving
    # the other unapplied and reporting success. That is exactly what happened
    # on the first green-connection run: alembic exited 0 and `mod_intg` was
    # empty. The whole fleet uses `heads` for the same reason.
    completed = subprocess.run(
        [
            "poetry",
            "run",
            "python",
            "-m",
            "dotmac_integrator.migrate",
            "upgrade",
            "heads",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "MIGRATION_DATABASE_URL": scratch},
        check=False,
    )
    if completed.returncode != 0:
        # Surfaced, not swallowed. `check=True` raises a CalledProcessError whose
        # message is the command line and nothing else, so the actual reason —
        # here, an authentication failure — is only recoverable by digging
        # through the raw CI log. A migration failure must say why.
        pytest.fail(
            "alembic upgrade heads failed\n"
            f"--- stdout ---\n{completed.stdout}\n"
            f"--- stderr ---\n{completed.stderr}"
        )
    try:
        yield scratch
    finally:
        with root.connect() as conn:
            conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    f"WHERE datname = '{name}'"
                )
            )
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
        root.dispose()
