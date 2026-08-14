"""The composed lineages apply to a real PostgreSQL, and the plane contract holds.

Every table this deployment owns is created by a migration it does not author.
Without this file the first run of `ig_0001` and `ig_0002` in this composition
would be in production — the Starter proves them in its own scratch database,
but the Starter composes a different set of lineages, and "the same migration
ran somewhere else" is not evidence about this deployment.

Requires a real database; skipped without one, so a contributor without
PostgreSQL still gets the rest of the suite. CI does not skip.
"""

from __future__ import annotations

import os
import subprocess
import uuid
from collections.abc import Iterator

import dotmac_integration
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


def test_the_module_schema_exists_with_exactly_its_declared_tables(
    migrated: str,
) -> None:
    """Read from the manifest, never a second list that can drift.

    NOT vacuous: two empty sets satisfy the equality, so both sides are required
    non-empty — an unapplied lineage against an empty manifest would otherwise
    pass.
    """
    engine = create_engine(migrated)
    with engine.connect() as conn:
        live = {
            row[0]
            for row in conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = :s"),
                {"s": dotmac_integration.SCHEMA},
            )
        }
    engine.dispose()

    declared = set(dotmac_integration.module.platform_tables)
    assert declared, "the manifest declares no platform table"
    assert live, f"{dotmac_integration.SCHEMA} is empty — the ig lineage did not apply"
    assert live == declared
    assert (
        dotmac_integration.module.tables == ()
    ), "this deployment owns no tenant plane"


def test_the_live_catalog_contract_holds(migrated: str) -> None:
    """The kernel's own audit, over the composed schema.

    This is what turns "the migration ran" into "the migration produced a
    correct schema" — no tenant column, no RLS, app_user holding nothing.
    """
    from dotmac_kernel.migrations.catalog import audit_live_schemas
    from dotmac_kernel.namespaces import NamespaceRegistry

    registry = NamespaceRegistry.from_manifests([dotmac_integration.module])
    engine = create_engine(migrated)
    with engine.connect() as conn:
        violations = audit_live_schemas(conn, registry)
    engine.dispose()
    assert not violations, "plane violations:\n" + "\n".join(violations)


@pytest.mark.parametrize(
    ("role", "expected"),
    [("platform_api", True), ("app_user", False)],
)
def test_schema_usage_follows_reachability(
    migrated: str, role: str, expected: bool
) -> None:
    """USAGE belongs to the role that must reach the plane, and only to it.

    Kernel 0.1.0a57 stopped REQUIRING tenant-role USAGE on a platform-only
    schema; nothing forbids it, so this assertion is the deployment's to make.
    """
    engine = create_engine(migrated)
    with engine.connect() as conn:
        held = conn.execute(
            text("SELECT has_schema_privilege(CAST(:r AS text), :s, 'USAGE')"),
            {"r": role, "s": dotmac_integration.SCHEMA},
        ).scalar_one()
    engine.dispose()
    assert held is expected, f"{role} USAGE on {dotmac_integration.SCHEMA}"


def test_the_audit_bites_on_this_schema(migrated: str) -> None:
    """Sensitivity proof (ADR-0018): a clean audit is evidence only if the audit
    CAN report a violation here. Rolled back in its own transaction."""
    from dotmac_kernel.migrations.catalog import audit_live_schemas
    from dotmac_kernel.namespaces import NamespaceRegistry

    registry = NamespaceRegistry.from_manifests([dotmac_integration.module])
    victim = sorted(dotmac_integration.module.platform_tables)[0]
    grant = f'GRANT SELECT ON {dotmac_integration.SCHEMA}."{victim}" TO app_user'
    engine = create_engine(migrated)
    with engine.connect() as conn:
        transaction = conn.begin()
        try:
            conn.execute(text(grant))
            violations = audit_live_schemas(conn, registry)
        finally:
            transaction.rollback()
        assert violations, "the audit reported nothing on a deliberate violation"
        assert not audit_live_schemas(conn, registry), "rollback left the schema dirty"
    engine.dispose()
