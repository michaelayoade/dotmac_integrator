"""Every effect a composed lineage needs has exactly one truthful answer here.

`migration_bindings.py` is a declaration, and a declaration is precisely the
thing that can lie. These checks are the half that needs no database: a binding
naming a revision this deployment does not compose, or a composed module
requiring an effect nobody answered, is caught before PostgreSQL is involved.

The other half — whether the bound provider actually SUPPLIED the effect — can
only be answered by the catalog, and lives in
`tests/composition/test_the_bindings_are_proven.py`.

## What changes with the `dotmac-integration 0.1.0a6` candidate

Under `0.1.0a3` the module declared `requires = ()`. Every fail-closed check in
this file was therefore satisfied by having nothing to check, which is why each
one was written with a planted-input sensitivity proof rather than left to assert
the passing case.

a6 adds `platform_audit_log.v1` to a4's database-role and idempotency-ledger
requirements. The exact package pins remain on published a4 until a6 and its
kernel a68 floor are released; this source-composed acceptance is what prevents
that future pin move from discovering an unanswered prerequisite in deployment.
"""

from __future__ import annotations

import os

import dotmac_integration
import dotmac_integration.idempotency
import pytest
from dotmac_kernel.prerequisites import (
    BINDINGS_ENV_VAR,
    IDEMPOTENCY_LEDGER_V1,
    MODULE_DATABASE_ROLES_V1,
    OUTBOX_RELAY_V1,
    PLATFORM_AUDIT_LOG_V1,
    TENANT_SCOPE_CATALOG_V1,
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

#: What the `dotmac-integration 0.1.0a6` candidate declares. Restated ON PURPOSE,
#: unlike everything else in this file, which reads the installed manifest: a pin
#: bump that silently changes the requirement set must fail with a diff a reviewer
#: can see, not adapt to it. `test_the_pinned_release_declares_what_we_think_it
#: _does` is the comparison.
EXPECTED_REQUIREMENTS = frozenset(
    {
        MODULE_DATABASE_ROLES_V1.name,
        IDEMPOTENCY_LEDGER_V1.name,
        PLATFORM_AUDIT_LOG_V1.name,
    }
)

#: Effects this assembly composes a provider for and deliberately does NOT bind,
#: because no composed manifest requires them. Retired at the a4 bump; see
#: `migration_bindings.py`'s module docstring for why each one went.
DELIBERATELY_UNBOUND = frozenset({TENANT_SCOPE_CATALOG_V1.name, OUTBOX_RELAY_V1.name})


def _required_by_composed_manifests() -> frozenset[str]:
    """Every prerequisite the composed module manifests declare.

    Read from the installed manifest rather than restated, so a pin bump that
    adds a requirement is caught by this repository instead of by an adopter.
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

    No longer vacuous. `ig_0007_idempotency_ledger` resolves its `depends_on`
    from these bindings at import and verifies them at upgrade, so an unanswered
    requirement is a failed `alembic upgrade` — this test is where it should be
    found instead.
    """
    unanswered = unbound_prerequisites(_required_by_composed_manifests())
    assert not unanswered, (
        f"composed manifests require {sorted(unanswered)} and this assembly "
        "binds no provider. Add a PrerequisiteBinding naming the revision that "
        "supplies each effect."
    )


def test_every_binding_answers_a_question_something_actually_asks() -> None:
    """The other direction, and it is only assertable since a4.

    A binding for an effect no composed manifest requires can never fail at
    `alembic upgrade`, because nothing resolves it — its only enforcement would
    be this repository's own live proof, which then spends CI time verifying a
    contract this deployment does not depend on. Under a3 the requirement set was
    empty and this assertion was unstatable; a4 makes it the ratchet that keeps
    decorative bindings out.

    Re-binding a retired effect is legitimate — but it comes WITH the module that
    requires it, in the same diff.
    """
    bound = {binding.prerequisite for binding in ASSEMBLY_PREREQUISITE_BINDINGS}
    required = _required_by_composed_manifests()
    assert bound <= required, (
        f"{sorted(bound - required)} is bound and required by nothing composed. "
        "Retire it, or land it beside the module that requires it."
    )


def test_the_pinned_release_declares_what_we_think_it_does() -> None:
    """A pin bump must not silently change the requirement set.

    Every other check here reads the manifest, so a release that dropped
    `idempotency_ledger.v1` would leave them all green while this deployment
    quietly stopped verifying the ledger it writes on every delivery. This is the
    one place the expectation is written down, so that change is a failing test
    with a diff rather than an absence.
    """
    assert _required_by_composed_manifests() == EXPECTED_REQUIREMENTS
    assert DELIBERATELY_UNBOUND.isdisjoint(EXPECTED_REQUIREMENTS), (
        "an effect listed as deliberately unbound is now required — bind it and "
        "move it out of DELIBERATELY_UNBOUND"
    )


def test_the_reference_string_resolves_to_these_bindings() -> None:
    """`DOTMAC_MIGRATION_BINDINGS` is a string, and a typo in it is silent.

    Load-bearing since a4: `ig_0007` calls `resolve_depends_on` AT IMPORT, and
    `alembic heads` / `history` / `show` build the revision map without running
    `env.py`. On those paths this string is the only channel, so a misspelt
    module or attribute crashes the exact commands an operator reaches for while
    diagnosing a bad migration.
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


def test_the_ledger_binding_matches_what_the_module_actually_calls() -> None:
    """The declaration and the call site must stay the same fact.

    a4 declares `idempotency_ledger.v1`; `dotmac_integration.idempotency` is what
    makes that declaration true, by adapting
    `dotmac_kernel.idempotency.execute_once_platform` on every guarded delivery.
    A release that kept the declaration and dropped the call — or the reverse —
    is a drift this repository should notice, because it is the one composing
    both.
    """
    bound = {binding.prerequisite for binding in ASSEMBLY_PREREQUISITE_BINDINGS}
    assert IDEMPOTENCY_LEDGER_V1.name in bound
    assert IDEMPOTENCY_LEDGER_V1.name in _required_by_composed_manifests()
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
    # a4's new head, and the reason the scan PARSES rather than imports: this
    # revision resolves `depends_on` at import time and would need the bindings
    # installed first, making a static check depend on runtime state.
    assert "ig_0007_idempotency_ledger" in composed
    assert "ig_0008_platform_audit_log" in composed


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


@pytest.mark.parametrize("dropped", sorted(EXPECTED_REQUIREMENTS))
def test_dropping_a_real_binding_is_detected(dropped: str) -> None:
    """THE proof that matters at a4, and it was unwritable at a3.

    Drives the REAL requirement set — read from the installed manifest, not a
    fixture — against this assembly's real bindings with one removed, and
    requires exactly the removed effect to be reported. Parametrised over both,
    so a check that happened to notice only the ledger fails on the roles.

    A guard that has finally got something to check must be shown reacting to the
    realistic mistake, which is a binding deleted during a tidy-up, not a
    prerequisite name nobody has ever typed.
    """
    survivors = tuple(
        binding
        for binding in ASSEMBLY_PREREQUISITE_BINDINGS
        if binding.prerequisite != dropped
    )
    assert (
        len(survivors) == len(ASSEMBLY_PREREQUISITE_BINDINGS) - 1
    ), f"{dropped} is not actually bound, so removing it proves nothing"
    assert unbound_prerequisites(
        _required_by_composed_manifests(), survivors
    ) == frozenset({dropped})


def test_the_unbound_prerequisite_detector_bites_on_an_unknown_name() -> None:
    """The parser-level direction, kept from the a3 era. It guards the set
    arithmetic itself, which the realistic proof above would still pass if
    `unbound_prerequisites` had been reduced to `frozenset()`."""
    assert unbound_prerequisites(frozenset({"imaginary_effect.v1"})) == frozenset(
        {"imaginary_effect.v1"}
    )
    assert unbound_prerequisites(EXPECTED_REQUIREMENTS) == frozenset()


def test_the_manifest_reader_is_reading_the_manifest() -> None:
    """The reader now returns a NON-empty set, which is itself the evidence it
    works — at a3 it returned `frozenset()` and a broken reader was
    indistinguishable from an honest one."""
    manifest = dotmac_integration.module
    assert hasattr(manifest, "requires"), "the manifest lost `requires`"
    assert hasattr(
        manifest, "platform_requires"
    ), "the manifest lost `platform_requires`"
    assert _required_by_composed_manifests(), "the reader found no requirements"
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
    """Three, matching a6's three requirements exactly. A count rather than a
    non-empty check, so retiring or adding a binding is a deliberate edit."""
    assert len(ASSEMBLY_PREREQUISITE_BINDINGS) == 3
