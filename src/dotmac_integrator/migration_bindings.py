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

Three independent controls sit under these four lines of declaration, and none
of them is this file:

1. **Static** — `tests/architecture/test_bindings_are_declared.py` requires every
   `provider_revision` below to be a revision id that actually exists in a
   lineage this assembly composes. A binding naming a revision nobody runs is
   caught without a database.
2. **Live** — `tests/composition/test_the_bindings_are_proven.py` runs the
   kernel's own verifier for each bound effect against the migrated scratch
   database, and proves each verifier *bites* on this composition. Reading the
   catalog is the only thing that can tell a supplied effect from a stamped one.
3. **At migration time** — `require_prerequisites` re-checks the same effects
   before a requiring migration's DDL, so a wrong answer here fails
   `alembic upgrade` rather than at runtime.

Deliberately absent: an "is the provider revision in `alembic_version`?" canary.
That table records the current head of each branch, not the history of applied
revisions, so the check fails against every database whose kernel lineage has
advanced past `0001`. Kernel 0.1.0a67's `require_prerequisites` docstring records
the same lesson; do not reintroduce it here.

## Nothing composed *requires* these yet — and they are still declared

`dotmac-integration 0.1.0a3` declares `requires=()`, so no composed lineage
consults a binding today. Two reasons the file exists anyway rather than being
an empty tuple waiting for a4:

* The module already **writes** the at-most-once ledger at request time —
  `dotmac_integration.idempotency` calls
  `dotmac_kernel.idempotency.execute_once_platform`, so
  `public.platform_idempotency_records` is a runtime dependency of every guarded
  delivery. `dotmac-integration 0.1.0a4` declares it as
  `idempotency_ledger.v1`; until then the dependency is real, undeclared, and
  satisfied here only because this assembly composes the whole kernel lineage.
  Binding it now means the a4 pin bump is a version change with a test already
  standing behind it.
* The live proof above is worth having against effects this deployment genuinely
  depends on, whether or not a manifest has got around to naming them.

`platform_audit_events` is the same shape and has no binding, because the kernel
registers no prerequisite name for it — `dotmac_integration.operations` adapts
`dotmac_kernel.audit.write_platform_audit_event` and nothing can declare that
dependency yet. An effect with no name cannot be bound; it is recorded here so
the gap is visible rather than mistaken for completeness.

## The `ig_0001` literal edge

`ig_0001_connector_cp` ships `depends_on = ("0001_initial_tenant_schema",)` — a
physical edge naming a foreign revision, which is exactly what the prerequisite
vocabulary exists to replace. It is a known defect in the module, resolved in the
Starter rather than here.

This assembly copes today by *composing the lineage that contains that revision
id*: kernel `0001_initial_tenant_schema` is in `version_locations()`, so Alembic
resolves the edge and orders correctly. That is coping, not agreement — an
adopter that does not run kernel `0001` cannot install the module at all, which
is the defect. Nothing below papers over it: a binding cannot rewrite an edge a
released migration hard-codes.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from dotmac_kernel.prerequisites import (
    IDEMPOTENCY_LEDGER_V1,
    MODULE_DATABASE_ROLES_V1,
    OUTBOX_RELAY_V1,
    TENANT_SCOPE_CATALOG_V1,
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
    # Kernel `0001` creates `tenants`/`tenant_domains` and
    # `app_current_tenant_id()`, and the three grantable roles. This deployment
    # owns no tenant plane at all, and still supplies both: `mod_intg` is
    # created by a lineage that is ordered after `0001`, and every module
    # migration GRANTs to roles it must never create itself.
    PrerequisiteBinding(
        prerequisite=TENANT_SCOPE_CATALOG_V1.name,
        provider_revision="0001_initial_tenant_schema",
        provider_owner="kernel",
    ),
    PrerequisiteBinding(
        prerequisite=MODULE_DATABASE_ROLES_V1.name,
        provider_revision="0001_initial_tenant_schema",
        provider_owner="kernel",
    ),
    # `0018`, not the lineage root. A binding names the revision that SUPPLIES
    # the effect: `0018_idempotency_one_owner` created
    # `idempotency_records`/`platform_idempotency_records` (ADR-0014). Bound to
    # `0001`, a database stopped at `0017` would satisfy the binding and fail on
    # the first guarded delivery.
    PrerequisiteBinding(
        prerequisite=IDEMPOTENCY_LEDGER_V1.name,
        provider_revision="0018_idempotency_one_owner",
        provider_owner="kernel",
    ),
    # The relay is assembled across three kernel revisions and the binding names
    # the LAST: `0008` created `outbox_events`, `0011` added leasing, the
    # reclaim index and the dispatcher role, and `0012` added the whole platform
    # peer. Only after `0012` is the effect whole, and the platform half is the
    # only half a platform-plane deployment could ever use.
    PrerequisiteBinding(
        prerequisite=OUTBOX_RELAY_V1.name,
        provider_revision="0012_platform_outbox",
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


def unbound_prerequisites(required: frozenset[str]) -> frozenset[str]:
    """Everything `required` that this assembly binds no provider for.

    Pure, and takes its input rather than reading the manifests, so the
    fail-closed direction can be exercised against a requirement set that does
    not exist yet — `dotmac-integration 0.1.0a3` requires nothing, and a check
    that could only ever look at today's manifests would report success without
    being able to fail.
    """
    bound = {binding.prerequisite for binding in ASSEMBLY_PREREQUISITE_BINDINGS}
    return frozenset(required - bound)


__all__ = [
    "ASSEMBLY_PREREQUISITE_BINDINGS",
    "BINDINGS_REFERENCE",
    "bindings_naming_uncomposed_revisions",
    "composed_revision_ids",
    "unbound_prerequisites",
]
