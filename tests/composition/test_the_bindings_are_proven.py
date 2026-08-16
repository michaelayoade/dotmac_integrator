"""Every bound effect is proven against the migrated database, not believed.

`tests/architecture/test_bindings_are_declared.py` proves the bindings are
*well-formed*: registered names, no duplicates, no revision this deployment does
not compose. None of that can tell a supplied effect from a stamped one — only
the catalog can, and this is where it is asked.

The question each assertion answers is the one a requiring migration asks at
deploy time, through the same function: `require_prerequisites`. Running it here
means a binding that has quietly stopped being true fails in CI rather than
during `make migrate` on a deploy night, and — for the effects
`dotmac-integration 0.1.0a3` depends on at RUNTIME without declaring
(`platform_idempotency_records`) — rather than on the first guarded delivery.

Requires a real database; skipped without one. CI does not skip. The scratch
database is `tests/composition/conftest.py`'s `migrated` fixture.
"""

from __future__ import annotations

import pytest
from dotmac_kernel.migrations.verify import (
    PrerequisiteNotSatisfiedError,
    registered_verifiers,
    require_prerequisites,
)
from dotmac_kernel.prerequisites import (
    IDEMPOTENCY_LEDGER_V1,
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


def test_the_ledger_this_deployment_writes_at_runtime_is_present(
    migrated: str,
) -> None:
    """`platform_idempotency_records`, named on its own.

    `dotmac-integration 0.1.0a3` declares no prerequisites, and its
    `idempotency.run_effect_once` writes this table on every guarded delivery.
    So until the a4 pin lands, THIS assertion is the only thing standing between
    a clean migration and an `UndefinedTable` on the first delivery — worth its
    own failure message rather than being one name inside a set.
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


def test_the_bound_effect_list_is_not_empty() -> None:
    """Two of the checks above iterate `BOUND_EFFECTS`; an emptied binding
    tuple would collect nothing and report success."""
    assert len(BOUND_EFFECTS) == 4
