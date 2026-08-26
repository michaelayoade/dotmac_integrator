"""This assembly's answers to "which revision supplies that effect?".

A module lineage declares the database *effects* it needs
(`ModuleManifest.requires`, `dotmac_kernel.prerequisites`). It never names a
foreign revision, because the answer differs per assembly. This file is where
THIS assembly answers, and it is the same class of decision as `lineage.py`'s
`version_locations` — which lineages are composed, and which of their revisions
supply the shared effects.

The Starter's `app/migration_bindings.py` is the reference for the shape. The
answers happen to be identical here because this deployment also runs the kernel
lineage in full; that is a fact about this composition, not a default. ERP, which
hosts `public.tenants` in its own lineage and structurally cannot run kernel
`0001`, writes different answers and installs the same modules.

## A binding is proven, never believed

Three independent controls sit under these two declarations, and none of them is
this file:

1. **Static** — `tests/architecture/test_bindings_are_declared.py` requires every
   `provider_revision` below to be a revision id that actually exists in a
   lineage this assembly composes, and every effect a composed manifest requires
   to be bound. Caught without a database.
2. **Live** — `tests/composition/test_the_bindings_are_proven.py` runs the
   kernel's own verifier for each bound effect against the migrated scratch
   database, and proves each verifier *bites* on this composition. Reading the
   catalog is the only thing that can tell a supplied effect from a stamped one.
3. **At migration time** — `ig_0007_idempotency_ledger` and
   `ig_0008_platform_audit_log` call `require_prerequisites` before any DDL, so
   a wrong answer here fails `alembic upgrade` rather than on the first request.

Control 3 became real at `dotmac-integration 0.1.0a4`. Under a3 nothing declared
a requirement, so nothing consulted a binding and the first two controls were the
only ones; a4's `ig_0007` resolves its `depends_on` from these bindings AT IMPORT
and verifies them at upgrade, which is why `env.py` installs them before the
revision map is walked and `migrate.py` exports `DOTMAC_MIGRATION_BINDINGS` for
the commands that never run `env.py`.

Deliberately absent: an "is the provider revision in `alembic_version`?" canary.
That table records the current head of each branch, not the history of applied
revisions, so the check fails against every database whose kernel lineage has
advanced past `0001`. Kernel 0.1.0a67's `require_prerequisites` docstring records
the same lesson; do not reintroduce it here.

## Three effects, because three are required — and two were RETIRED

`dotmac-integration 0.1.0a16` declares the database roles, idempotency ledger and
append-only platform audit log requirements. All three are bound below, and
nothing else is.

Re-derived at the a13 → a16 bump, which is required rather than a formality: a
release that changes `requires` changes what this assembly must assert about it.
The answer this time is that the bindings did not move, while the module lineage
did: a16 adds `ig_0012_delivery_evidence`, `ig_0013_delivery_result` and
`ig_0014_polling_evidence`, and its `manifest.requires` tuple remains the same
three effects as a13. Those revisions change module-owned platform tables and
columns; none introduces a new cross-lineage prerequisite. A no-op binding
re-derivation is recorded because the alternative is a reader at the next bump
not knowing whether this one was checked or skipped.

Under a3 this file also bound `tenant_scope_catalog.v1` and `outbox_relay.v1`.
Both were truthful — this deployment composes the whole kernel lineage, so kernel
`0001` really does create `public.tenants` and `0012` really does complete the
relay — and both are now **retired**, because a truthful answer to a question
nobody asks is not a binding, it is decoration that CI must maintain:

* `tenant_scope_catalog.v1` — a4 does not require it, and the reason is
  structural rather than an oversight: every foreign key in the `ig` lineage
  targets `mod_intg.*`, and this deployment owns no tenant plane at all
  (`module.tables == ()`). There is no FK for a tenant catalogue to be the target
  of.
* `outbox_relay.v1` — nothing composed here touches `dotmac_kernel.messaging`.
  The module's own "outbox" is `mod_intg.delivery_attempts` with its own claim
  loop; the name collides with the kernel relay and the machinery does not.
  Verifying the relay contract — dispatcher roles, the `SECURITY DEFINER`
  claim/settle pairs, the grant posture — would turn any kernel-side relay change
  into a red build here for a facility this deployment never calls.

Retired is not unavailable. Both effects are still SUPPLIED by the composed
kernel lineage, so if a future connector module requires one, re-binding it is
the three lines below and `binding_for` fails closed with an explicit message in
the meantime. That is the designed behaviour, not a gap.

At a6 the former platform-audit gap is closed: kernel a68 names and verifies the
append-only log as `platform_audit_log.v1`, and `ig_0008` requires it. The
provider is kernel `0026`, the revision that completes the effect by removing
UPDATE/DELETE and column-level escape grants from the online platform role.

## The `ig_0001` literal edge — unrepaired through a16

`ig_0001_connector_cp` still ships `depends_on = ("0001_initial_tenant_schema",)`
at `0.1.0a16` — a physical edge naming a foreign revision, which is exactly what
the prerequisite vocabulary exists to replace. It cannot be repaired at any
version: the file shipped in a1, a2, a3 and a4, its bytes have run in databases
the Starter does not own, and `alembic_version` records that a revision ran,
never which version of it. a4 added `ig_0007` rather than editing the root for
that reason; a8 correctly leaves released migrations unchanged.

So the constraint is permanent for this lineage: **an adopter that cannot run
kernel `0001_initial_tenant_schema` cannot install `dotmac-integration` at all**,
however correct its bindings are. This assembly is unaffected only because it
composes that exact revision. That is coping, not agreement, and nothing below
papers over it — a binding cannot rewrite an edge a released migration hard-codes.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from dotmac_kernel.prerequisites import (
    IDEMPOTENCY_LEDGER_V1,
    MODULE_DATABASE_ROLES_V1,
    PLATFORM_AUDIT_LOG_V1,
    PrerequisiteBinding,
)

from dotmac_integrator.lineage import version_locations

#: Dotted `module:ATTRIBUTE` for `DOTMAC_MIGRATION_BINDINGS`. Alembic entry
#: points that build a revision map WITHOUT running `env.py` (`heads`,
#: `history`, `show`) can only be reached through that environment variable, so
#: the string lives beside the bindings rather than being retyped in
#: `migrate.py`.
BINDINGS_REFERENCE: Final[str] = (
    "dotmac_integrator.migration_bindings:ASSEMBLY_PREREQUISITE_BINDINGS"
)

ASSEMBLY_PREREQUISITE_BINDINGS: Final[tuple[PrerequisiteBinding, ...]] = (
    # `_ensure_roles` in kernel `0001` creates `app_admin`, `app_user` and
    # `platform_api`. Every `ig` migration GRANTs to roles it must never create
    # itself — creating a role needs privileges a module migration cannot assume,
    # and a module that invented its own would be a second authority over cluster
    # access. This is the effect `ig_0001`'s literal edge was standing in for.
    PrerequisiteBinding(
        prerequisite=MODULE_DATABASE_ROLES_V1.name,
        provider_revision="0001_initial_tenant_schema",
        provider_owner="kernel",
    ),
    # `0018`, not the lineage root. A binding names the revision that SUPPLIES
    # the effect: `0018_idempotency_one_owner` created
    # `idempotency_records`/`platform_idempotency_records` (ADR-0014). Bound to
    # `0001`, a database stopped at `0017` would order correctly, satisfy the
    # binding, and have no ledger for the first guarded delivery to write.
    PrerequisiteBinding(
        prerequisite=IDEMPOTENCY_LEDGER_V1.name,
        provider_revision="0018_idempotency_one_owner",
        provider_owner="kernel",
    ),
    PrerequisiteBinding(
        prerequisite=PLATFORM_AUDIT_LOG_V1.name,
        provider_revision="0026_platform_audit_log",
        provider_owner="kernel",
    ),
)

#: `revision = "..."` as a released Alembic migration writes it. Parsed rather
#: than imported: importing a revision module executes it, and a module lineage
#: is entitled to resolve `depends_on` at import time through machinery a static
#: check must not depend on being installed and configured.
_REVISION_ASSIGNMENT: Final[re.Pattern[str]] = re.compile(
    r"^revision\s*(?::\s*str\s*)?=\s*[\"']([^\"']+)[\"']", re.MULTILINE
)


def composed_revision_ids() -> frozenset[str]:
    """Every revision id in every lineage this assembly composes.

    Read from the INSTALLED wheels through `version_locations()`, so this
    answers "what does this deployment actually run", not "what did the
    repository expect to be installed".
    """
    found: set[str] = set()
    for directory in version_locations():
        for path in sorted(Path(directory).glob("*.py")):
            if path.name.startswith("__"):
                continue
            match = _REVISION_ASSIGNMENT.search(path.read_text(encoding="utf-8"))
            if match is not None:
                found.add(match.group(1))
    return frozenset(found)


def bindings_naming_uncomposed_revisions(
    bindings: tuple[PrerequisiteBinding, ...] = ASSEMBLY_PREREQUISITE_BINDINGS,
) -> dict[str, str]:
    """`{prerequisite: provider_revision}` for every binding this deployment
    cannot possibly honour, because no composed lineage contains the revision.

    Returned rather than raised so the caller shows an operator the whole list;
    a function that raised on the first would turn one review into four.
    """
    composed = composed_revision_ids()
    return {
        binding.prerequisite: binding.provider_revision
        for binding in bindings
        if binding.provider_revision not in composed
    }


def unbound_prerequisites(
    required: frozenset[str],
    bindings: tuple[PrerequisiteBinding, ...] = ASSEMBLY_PREREQUISITE_BINDINGS,
) -> frozenset[str]:
    """Everything `required` that `bindings` names no provider for.

    Pure, and takes BOTH sides rather than reading the manifest and the module
    global. That is what lets the fail-closed direction be exercised: with
    `dotmac-integration 0.1.0a4` the real requirement set is finally non-empty,
    so the proof that this check bites is to drive the REAL requirements against
    a binding set with one removed — which is the mistake it exists to catch, and
    which no amount of asserting the passing case would demonstrate.
    """
    bound = {binding.prerequisite for binding in bindings}
    return frozenset(required - bound)


__all__ = [
    "ASSEMBLY_PREREQUISITE_BINDINGS",
    "BINDINGS_REFERENCE",
    "bindings_naming_uncomposed_revisions",
    "composed_revision_ids",
    "unbound_prerequisites",
]
