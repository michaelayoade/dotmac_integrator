"""The deployment's projection of what its installed connectors declared.

`dotmac-integration 0.1.0a10` raises the SPI to 1.3 and makes two runtime
boundaries part of the connector manifest contract: the NAMED secret bindings a
connector needs, and the EXACT provider hosts it may reach. The module derives
one immutable projection from the installed manifest set
(`derive_runtime_policy`) and deliberately stops there — it knows nothing about
Docker, a network policy or OpenBao, and it has no provider list.

This file is the other half: the independently deployed runtime rendering that
projection into what it enforces and reports. It is the same shape as
`migration_bindings.py` — the module declares, the assembly answers — and it is
held to the same rule. **Nothing here restates a connector's declarations.**
There is no host list, no secret name and no provider identity below; every
value is read from the installed manifests through the module's own projection,
because a second list in the assembly is a list that drifts and the drift is
invisible until the connector nobody re-checked is the one that mattered
(AGENTS.md rule 2).

## Why omission refuses the boot here

`derive_runtime_policy` refuses a pre-1.3 manifest rather than reading its
missing declarations as deny-all, and this deployment escalates that refusal to
a failed construction — beside `require_a_correct_surface`, for the same reason.
An empty egress declaration is this deployment's ENFORCEABLE evidence that a
connector needs no provider egress; an omitted one is the absence of evidence
wearing the same shape. A process that started anyway would publish a policy
digest covering a connector whose boundary nobody declared, and the operator
reading `/operations/runtime-policy` could not tell the two apart.

The cost is stated rather than hidden: an adopter installing a pre-1.3 connector
cannot run this deployment until that connector is re-released. Every
distribution this assembly pins already declares SPI `>=1.3,<2.0`, so the
refusal is currently unreachable through the pins — which is exactly why
`tests/unit/test_runtime_policy.py` drives it with a planted legacy manifest.
A guard whose only evidence is that it never fired is not enforcement
(ADR-0018).

## Capability coverage is REPORTED, never decided

The module owns three capability refusals. Two are already load-bearing
elsewhere: `require_declared_for_binding` refuses a destination binding naming
an undeclared capability, inside `dotmac_integration.destination_binding`, and
`ConnectorManifest.require_declares` refuses a binding naming a capability the
connector never implements. The third pair — `require_implements_only_declared`
and `require_no_orphans` — is for the COMPOSING RUNTIME, which is this one, and
nothing called it.

They are called here and their verdicts are reported, not raised. The reason is
a boundary, not a preference: an installed connector implementing a capability
no product has declared is a **product** decision to make or decline — which
application owns that observation, and under what contract — and this assembly
may never mint a capability declaration (AGENTS.md rule 27). Refusing the boot
would be this deployment deciding it; answering nothing would leave an operator
reading a green screen for an integration that can never deliver. So the report
names the gap, with the ids on both sides, and the per-receipt path stays
fail-closed exactly as it was: an unreconciled destination is a pre-network
`UNAVAILABLE`, never a receipt marked done.

No connector pinned today is in that state, which is why the coverage report is
built now rather than when one is: the connectors waiting on a product-declared
capability are the reason this reporting exists, and adding it in the same
change that pins one would leave nothing that ever showed the gap. See
`docs/UPGRADE-READINESS.md`, slice 3.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import dotmac_integration as integration

__all__ = [
    "capability_coverage",
    "policy_report",
    "projected_policy",
    "require_declared_runtime_boundaries",
]


def projected_policy() -> integration.RuntimePolicy:
    """The module's own projection of the INSTALLED manifest set.

    Entry-point discovery every time rather than a cached value: a distribution
    can be installed after construction ran, and the projection's whole purpose
    is to describe what is loaded now.
    """
    return integration.derive_runtime_policy(integration.discover())


def require_declared_runtime_boundaries() -> integration.RuntimePolicy:
    """Refuse construction when an installed connector cannot be projected.

    Returns the policy so the caller can hold it; raises the module's own
    `RuntimeBoundaryMissing` otherwise. Deliberately NOT translated into a local
    exception type — the message names the offending connector key and tells the
    operator to install a release that declares its boundaries, which is the
    whole remedy.
    """
    return projected_policy()


def capability_coverage() -> dict[str, Any]:
    """Which implemented capabilities have a declaration, and which do not.

    Both directions, because they fail differently. A capability implemented
    with no declaration is an integration that can never be bound to a
    destination — the module refuses that binding. A capability declared with no
    implementation reads on an operations screen exactly like a working
    integration: the contract resolves and nothing ever arrives.

    `registry` is `"absent"` — not an empty declaration set — when no product
    port is installed. A deployment with `PRODUCT_PORT_ENABLED=false` has
    declared nothing rather than declared nothing to be true, and reporting the
    two as the same value would make an unconfigured deployment look like one
    whose product deliberately declares no capability.
    """
    manifests = [plugin.manifest for plugin in integration.discover().plugins]
    implemented = _implemented(manifests)
    try:
        registry = integration.capability_registry()
    except integration.CapabilityRegistryNotInstalled:
        return {
            "registry": "absent",
            "implemented": sorted(implemented),
            "declared": None,
            "implemented_without_declaration": None,
            "declared_without_implementation": None,
        }

    declared = set(registry.declared_ids)
    return {
        "registry": "installed",
        "implemented": sorted(implemented),
        "declared": sorted(declared),
        # The module's own refusals, run for their verdict rather than their
        # exception. Recomputing the set difference here would be a second
        # implementation of a rule that already has an owner.
        "implemented_without_declaration": sorted(
            {
                capability_id
                for manifest in manifests
                for capability_id in _undeclared(registry, manifest)
            }
        ),
        "declared_without_implementation": sorted(
            _orphans(registry, manifests),
        ),
    }


def _undeclared(
    registry: integration.CapabilityRegistry, manifest: integration.ConnectorManifest
) -> frozenset[str]:
    """The module's refusal, run for its verdict. The set difference is
    recomputed only on the branch the refusal already took, so this file never
    becomes a second implementation of the rule."""
    try:
        integration.require_implements_only_declared(registry, manifest)
    except integration.UnknownCapabilityError:
        return frozenset(manifest.capability_ids - registry.declared_ids)
    return frozenset()


def _orphans(
    registry: integration.CapabilityRegistry,
    manifests: Sequence[integration.ConnectorManifest],
) -> frozenset[str]:
    try:
        integration.require_no_orphans(registry, manifests)
    except integration.OrphanCapabilityError:
        implemented = _implemented(manifests)
        return frozenset(registry.declared_ids) - implemented
    return frozenset()


def _implemented(manifests: Sequence[integration.ConnectorManifest]) -> frozenset[str]:
    return frozenset(
        capability_id
        for manifest in manifests
        for capability_id in manifest.capability_ids
    )


def policy_report(policy: integration.RuntimePolicy) -> dict[str, Any]:
    """Serialise the projection for an operator. NAMES ONLY.

    A secret binding NAME identifies a purpose; it is not a reference and it is
    certainly not a value, and this deployment's rule that no value is logged,
    serialised or persisted (AGENTS.md rule 13) is unaffected by publishing one.
    Nothing here reads held material, and there is no code path from this
    function to `secret_resolver`'s store.

    `egress_denies_all` is stated rather than left for the reader to infer from
    an empty list, because that empty list is the load-bearing half of the SPI
    1.3 contract: under 1.3 it is an explicit deny-all that every projected
    connector affirmatively declared, and it is indistinguishable at a glance
    from a field somebody forgot to fill in.
    """
    hosts = list(policy.egress_hosts)
    return {
        "spi_version": str(integration.CURRENT_SPI_VERSION),
        "policy_digest": policy.digest,
        "egress_hosts": hosts,
        "egress_denies_all": not hosts,
        "secret_bindings": [
            {"connector_key": connector_key, "name": name, "required": required}
            for connector_key, name, required in policy.secret_bindings
        ],
        "connectors": [
            {
                "connector_key": connector.connector_key,
                "manifest_digest": connector.manifest_digest,
                "egress_hosts": list(connector.egress_hosts),
                "secret_bindings": [
                    {"name": binding.name, "required": binding.required}
                    for binding in connector.secret_bindings
                ],
            }
            for connector in policy.connectors
        ],
        "capabilities": capability_coverage(),
    }
