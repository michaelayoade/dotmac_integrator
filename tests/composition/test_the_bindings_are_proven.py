"""Every bound effect is proven against the migrated database, not believed.

`tests/architecture/test_bindings_are_declared.py` proves the bindings are
*well-formed*: registered names, no duplicates, no revision this deployment does
not compose. None of that can tell a supplied effect from a stamped one — only
the catalog can, and this is where it is asked.

The question each assertion answers is the one a requiring migration asks at
deploy time, through the same function: `require_prerequisites`. Running it here
means a binding that has quietly stopped being true fails in CI rather than
during `make migrate` on a deploy night.

## What `dotmac-integration 0.1.0a4` changed

Under a3 the module declared nothing, so `alembic upgrade heads` never consulted
a binding and this file was the ONLY thing checking the effects the module writes
at runtime. a4 declares them, and `ig_0007_idempotency_ledger` calls
`require_prerequisites` before any DDL — so the `migrated` fixture's own
`upgrade heads` now exercises the real deploy-time path, and
`test_the_upgrade_itself_verified_the_prerequisites` asserts that it did.

That makes this file's job the narrower and better one it should always have had:
not standing in for a check the module was missing, but proving that the check
the module now performs is passing against THIS composition, and that it is
capable of failing here.

Requires a real database; skipped without one. CI does not skip. The scratch
database is `tests/composition/conftest.py`'s `migrated` fixture.
"""

from __future__ import annotations

import dotmac_integration
import pytest
from dotmac_kernel.migrations.verify import (
    PrerequisiteNotSatisfiedError,
    registered_verifiers,
    require_prerequisites,
)
from dotmac_kernel.prerequisites import (
    IDEMPOTENCY_LEDGER_V1,
    PLATFORM_AUDIT_LOG_V1,
    install_prerequisite_bindings,
)
from sqlalchemy import create_engine, text

from dotmac_integrator.migration_bindings import ASSEMBLY_PREREQUISITE_BINDINGS

BOUND_EFFECTS = tuple(
    binding.prerequisite for binding in ASSEMBLY_PREREQUISITE_BINDINGS
)


@pytest.fixture(autouse=True)
def _bindings_installed() -> None:
    """`require_prerequisites` refuses through `binding_for`, which reads the
    INSTALLED set — an uninstalled binding turns a real refusal into an
    `UnboundPrerequisiteError` about the test rather than about the database."""
    install_prerequisite_bindings(ASSEMBLY_PREREQUISITE_BINDINGS)


def test_every_bound_effect_is_present_in_this_database(migrated: str) -> None:
    """The whole set at once, exactly as a requiring migration would ask.

    Not `verify_*` called directly: `require_prerequisites` is what a module's
    `upgrade()` calls, and it additionally refuses a prerequisite that has no
    registered verifier — an effect nothing can prove must not pass by being
    unprovable.
    """
    engine = create_engine(migrated)
    with engine.connect() as conn:
        require_prerequisites(conn, BOUND_EFFECTS)
    engine.dispose()


@pytest.mark.parametrize("effect", BOUND_EFFECTS)
def test_each_bound_effect_has_a_verifier(effect: str) -> None:
    """A binding for an effect with no verifier is a claim nothing checks.

    Cheap, and it fails with the effect's name rather than as a
    `PrerequisiteVerifierMissingError` in the middle of the run above.
    """
    assert effect in registered_verifiers()


def test_the_upgrade_itself_verified_the_prerequisites(migrated: str) -> None:
    """The fixture's `alembic upgrade heads` advanced past `ig_0008`, so the DEPLOY path
    was exercised — not merely this file's re-check afterwards.

    `ig_0008_platform_audit_log` creates nothing. Its entire body is
    `require_prerequisites(op.get_bind(), REQUIRES)`, and it resolves its
    `depends_on` from this assembly's bindings at import. So its presence in
    `alembic_version` is evidence of three separate things at once: the bindings
    were installed before the revision map was built, the ordering edge they
    produced was real, and the effects verified against this database at migrate
    time.

    Asserted on the head of the `ig` branch rather than by scanning history,
    because `alembic_version` holds current heads and nothing else — the same
    fact that makes an order canary the wrong instrument. `ig_0010` is the head
    at a8, so that row is the right question to ask; its ancestry includes the
    prerequisite-verification revision.
    """
    engine = create_engine(migrated)
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT version_num FROM alembic_version"))
        applied = {row[0] for row in rows}
    engine.dispose()
    assert "ig_0010_shadow_evidence" in applied, (
        f"alembic_version holds {sorted(applied)}. The `ig` head at "
        "dotmac-integration 0.1.0a8 is ig_0010_shadow_evidence, whose ancestry "
        "includes ig_0008_platform_audit_log. If the head did not run, the "
        "deploy-time verification did not complete and `upgrade heads` applied "
        "one branch."
    )


def test_the_ledger_this_deployment_writes_at_runtime_is_present(
    migrated: str,
) -> None:
    """`platform_idempotency_records`, named on its own.

    `dotmac_integration.idempotency.run_effect_once` writes this table on every
    guarded delivery. a4 declares that as `idempotency_ledger.v1` and `ig_0007`
    verifies it at migrate time — so this is no longer the only thing standing
    between a clean migration and an `UndefinedTable`. It stays because it is the
    one effect whose absence would be silent until a real delivery, and a named
    failure beats one name inside a set.
    """
    engine = create_engine(migrated)
    with engine.connect() as conn:
        require_prerequisites(conn, (IDEMPOTENCY_LEDGER_V1.name,))
        present = conn.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE "
                "table_schema = 'public' AND table_name = "
                "'platform_idempotency_records')"
            )
        ).scalar_one()
    engine.dispose()
    assert present is True


# ── Sensitivity proof (ADR-0018) ────────────────────────────────────────────


def test_the_verification_bites_on_this_database(migrated: str) -> None:
    """A passing verification is evidence only if it CAN fail here.

    The ledger table is renamed inside a transaction that is rolled back, so the
    refusal is observed against this exact composition rather than argued from
    the kernel's own test suite — which runs against a different one.

    Renamed rather than dropped: a drop would cascade to anything referencing
    it, and the point is to break the *name the verifier looks for*, not to find
    out what else falls over.
    """
    engine = create_engine(migrated)
    with engine.connect() as conn:
        transaction = conn.begin()
        try:
            conn.execute(
                text(
                    "ALTER TABLE public.platform_idempotency_records "
                    "RENAME TO platform_idempotency_records_hidden"
                )
            )
            with pytest.raises(PrerequisiteNotSatisfiedError) as refusal:
                require_prerequisites(conn, (IDEMPOTENCY_LEDGER_V1.name,))
        finally:
            transaction.rollback()

        # The refusal names the binding at fault, not merely the table — that is
        # what sends a reader to `migration_bindings.py` instead of to a
        # migration they cannot change.
        assert "0018_idempotency_one_owner" in str(refusal.value)

        # And the rollback really restored it, so the break cannot leak into the
        # assertions of whatever runs next against this database.
        require_prerequisites(conn, BOUND_EFFECTS)
    engine.dispose()


def test_the_platform_audit_verification_bites_on_this_database(
    migrated: str,
) -> None:
    """The new a6 prerequisite is live, not only present in a tuple."""
    engine = create_engine(migrated)
    with engine.connect() as conn:
        transaction = conn.begin()
        try:
            conn.execute(
                text(
                    "ALTER TABLE public.platform_audit_events "
                    "RENAME TO platform_audit_events_hidden"
                )
            )
            with pytest.raises(PrerequisiteNotSatisfiedError) as refusal:
                require_prerequisites(conn, (PLATFORM_AUDIT_LOG_V1.name,))
        finally:
            transaction.rollback()

        assert "0026_platform_audit_log" in str(refusal.value)
        require_prerequisites(conn, BOUND_EFFECTS)
    engine.dispose()


def test_the_bound_effect_list_matches_what_the_module_requires() -> None:
    """Several checks above iterate `BOUND_EFFECTS`; an emptied binding tuple
    would collect nothing and report success.

    Compared against the installed manifest rather than a literal, so this stays
    true through a pin bump that legitimately changes the set — while the count
    keeps an emptied tuple from passing. The static suite owns the reasoning
    about WHICH effects; this only refuses to run blind.
    """
    required = frozenset(
        (
            *dotmac_integration.module.requires,
            *dotmac_integration.module.platform_requires,
        )
    )
    assert len(BOUND_EFFECTS) == 3
    assert frozenset(BOUND_EFFECTS) == required
