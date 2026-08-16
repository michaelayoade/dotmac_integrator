"""The composed lineages apply to a real PostgreSQL, and the plane contract holds.

Every table this deployment owns is created by a migration it does not author.
Without this file the first run of `ig_0001` and `ig_0002` in this composition
would be in production — the Starter proves them in its own scratch database,
but the Starter composes a different set of lineages, and "the same migration
ran somewhere else" is not evidence about this deployment.

Requires a real database; skipped without one, so a contributor without
PostgreSQL still gets the rest of the suite. CI does not skip. The scratch
database itself is `tests/composition/conftest.py`\'s `migrated` fixture.
"""

from __future__ import annotations

import dotmac_integration
import pytest
from sqlalchemy import create_engine, text


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
