"""Every effect a composed lineage needs has exactly one truthful answer here.

`migration_bindings.py` is a declaration, and a declaration is precisely the
thing that can lie. These checks are the half that needs no database: a binding
naming a revision this deployment does not compose, or a composed module
requiring an effect nobody answered, is caught before PostgreSQL is involved.

The other half — whether the bound provider actually SUPPLIED the effect — can
only be answered by the catalog, and lives in
`tests/composition/test_the_bindings_are_proven.py`.

Every check here carries a sensitivity proof (ADR-0018), because all of them are
currently satisfied by a composition where `dotmac-integration 0.1.0a3` requires
nothing at all. A guard that cannot demonstrate it bites against an empty
requirement set is not enforcement; it is a comment that runs.
"""

from __future__ import annotations

import os

import dotmac_integration
import dotmac_integration.idempotency
import pytest
from dotmac_kernel.prerequisites import (
    BINDINGS_ENV_VAR,
    IDEMPOTENCY_LEDGER_V1,
    OUTBOX_RELAY_V1,
    PrerequisiteBinding,
    autoload_bindings,
    install_prerequisite_bindings,
    installed_bindings,
)

from dotmac_integrator.migration_bindings import (
    ASSEMBLY_PREREQUISITE_BINDINGS,
    BINDINGS_REFERENCE,
    bindings_naming_uncomposed_revisions,
    composed_revision_ids,
    unbound_prerequisites,
)


def _required_by_composed_manifests() -> frozenset[str]:
    """Every prerequisite the composed module manifests declare.

    Read from the installed manifest rather than restated, so a pin bump that
    adds a requirement is caught by this repository instead of by an adopter.
    `dotmac-integration 0.1.0a4` adds `idempotency_ledger.v1`; today the module
    declares nothing, which is exactly why the detector below exists.
    """
    manifest = dotmac_integration.module
    return frozenset(
        (
            *getattr(manifest, "requires", ()),
            *getattr(manifest, "platform_requires", ()),
        )
    )


# ── The declarations hold ───────────────────────────────────────────────────


def test_the_bindings_install() -> None:
    """Names are registered, and no effect is bound twice.

    `install_prerequisite_bindings` is the kernel's own validation — an
    unregistered prerequisite name or a duplicated effect raises here rather
    than at `alembic upgrade` on a deploy night.
    """
    install_prerequisite_bindings(ASSEMBLY_PREREQUISITE_BINDINGS)
    assert len(installed_bindings()) == len(ASSEMBLY_PREREQUISITE_BINDINGS)


def test_every_binding_names_a_revision_this_deployment_composes() -> None:
    """A binding pointing at a revision nobody runs is unfalsifiable at runtime.

    Alembic never orders against it, `require_prerequisites` never mentions it,
    and the effect is either present by luck or absent by surprise.
    """
    stranded = bindings_naming_uncomposed_revisions()
    assert not stranded, (
        "bindings name revisions absent from every composed lineage: "
        f"{stranded}. Either the pin moved and the revision was renamed, or "
        "the binding names a lineage this assembly does not compose."
    )


def test_every_prerequisite_a_composed_manifest_requires_is_bound() -> None:
    """Fail-closed: composing a module whose requirements are unanswered.

    Vacuous today by construction — see the sensitivity proof below, which is
    what makes this assertion worth reading.
    """
    unanswered = unbound_prerequisites(_required_by_composed_manifests())
    assert not unanswered, (
        f"composed manifests require {sorted(unanswered)} and this assembly "
        "binds no provider. Add a PrerequisiteBinding naming the revision that "
        "supplies each effect."
    )


def test_the_reference_string_resolves_to_these_bindings() -> None:
    """`DOTMAC_MIGRATION_BINDINGS` is a string, and a typo in it is silent.

    `alembic heads` builds a revision map without running `env.py`, so this
    string is the ONLY way a module lineage resolves its edge on that path. A
    misspelt module or attribute would surface as a crash in the one command an
    operator reaches for while diagnosing a bad migration.
    """
    previous = os.environ.get(BINDINGS_ENV_VAR)
    os.environ[BINDINGS_ENV_VAR] = BINDINGS_REFERENCE
    try:
        assert autoload_bindings() is True
        assert installed_bindings() == tuple(
            sorted(ASSEMBLY_PREREQUISITE_BINDINGS, key=lambda b: b.prerequisite)
        )
    finally:
        if previous is None:
            os.environ.pop(BINDINGS_ENV_VAR, None)
        else:
            os.environ[BINDINGS_ENV_VAR] = previous
        install_prerequisite_bindings(ASSEMBLY_PREREQUISITE_BINDINGS)


def test_the_runtime_ledger_dependency_is_bound_ahead_of_being_declared() -> None:
    """`dotmac_integration.idempotency` calls `execute_once_platform`.

    That makes `public.platform_idempotency_records` a dependency of every
    guarded delivery at REQUEST time, in a release whose manifest declares
    nothing. The binding is therefore present before the declaration is, and
    this test is what keeps it from being tidied away as unused.
    """
    bound = {binding.prerequisite for binding in ASSEMBLY_PREREQUISITE_BINDINGS}
    assert IDEMPOTENCY_LEDGER_V1.name in bound
    assert hasattr(
        dotmac_integration.idempotency, "run_effect_once"
    ), "the module no longer adapts the kernel ledger — re-derive this binding"


# ── Sensitivity proofs (ADR-0018) ───────────────────────────────────────────


def test_the_revision_scan_actually_reads_the_composed_lineages() -> None:
    """Both checks above compare against `composed_revision_ids()`. An empty
    set would make the first vacuous and the second unfalsifiable."""
    composed = composed_revision_ids()
    assert len(composed) > 10, composed
    # One from each composed lineage, so a scan that found only the kernel's
    # (or only the module's) fails here rather than passing half-blind.
    assert "0001_initial_tenant_schema" in composed
    assert "ig_0001_connector_cp" in composed


def test_the_uncomposed_revision_detector_bites() -> None:
    """A fabricated binding must be reported, so the empty result above is
    evidence rather than an accident of an over-permissive scan."""
    planted = (
        PrerequisiteBinding(
            prerequisite=OUTBOX_RELAY_V1.name,
            provider_revision="zz_9999_not_a_real_revision",
            provider_owner="nobody",
        ),
    )
    assert bindings_naming_uncomposed_revisions(planted) == {
        OUTBOX_RELAY_V1.name: "zz_9999_not_a_real_revision"
    }


def test_the_unbound_prerequisite_detector_bites() -> None:
    """The requirement set is empty in this release, so the fail-closed
    direction is exercised against a requirement that does not exist."""
    assert unbound_prerequisites(frozenset({"imaginary_effect.v1"})) == frozenset(
        {"imaginary_effect.v1"}
    )
    assert unbound_prerequisites(frozenset({IDEMPOTENCY_LEDGER_V1.name})) == frozenset()


def test_the_manifest_reader_is_reading_the_manifest() -> None:
    """`_required_by_composed_manifests` returns the empty set today. That is a
    fact about `0.1.0a3`, not a broken reader, and the two are indistinguishable
    unless the attributes it reads are asserted to exist."""
    manifest = dotmac_integration.module
    assert hasattr(manifest, "requires"), "the manifest lost `requires`"
    assert hasattr(
        manifest, "platform_requires"
    ), "the manifest lost `platform_requires`"
    assert _required_by_composed_manifests() == frozenset(
        (*manifest.requires, *manifest.platform_requires)
    )


@pytest.mark.parametrize(
    "binding", ASSEMBLY_PREREQUISITE_BINDINGS, ids=lambda b: b.prerequisite
)
def test_each_binding_names_an_owner(binding: PrerequisiteBinding) -> None:
    """Parametrised over the real tuple, so an emptied `ASSEMBLY_PREREQUISITE_
    BINDINGS` collects zero cases — which the count assertion below catches."""
    assert binding.provider_owner == "kernel", (
        "this deployment composes the kernel lineage and the `ig` lineage; the "
        "`ig` lineage supplies no shared effect, so every provider is the kernel"
    )


def test_the_binding_set_is_not_empty() -> None:
    assert len(ASSEMBLY_PREREQUISITE_BINDINGS) == 4
