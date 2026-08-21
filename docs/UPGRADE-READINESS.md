# Upgrade readiness — the connector programme, in three slices

**Date:** 2026-08-21 · **Scope:** composition only. No connector is activated,
no external traffic is taken, no product cutover happens, and nothing here
changes a product domain decision.

This file is evidence, not intent. Each claim states what was checked and what
the check read, so the next reader can tell "verified" from "assumed" — the
distinction the Starter's own publication ledger exists to preserve.

## Why three slices and not one change

The obvious change is one PR that bumps the module and pins every published
connector. It is wrong, and it is wrong for a structural reason rather than a
review-size one: **a module bump, a second connector on one capability, and a
connector for an undeclared capability are three different problems with three
different owners.**

| | Slice | Owner of the blocker | Gate |
|---|---|---|---|
| **1** | Integration a10 + WhatsApp a2 + the SPI 1.3 runtime-policy surface | this repository | released tags, re-derived bindings, a refreshed lock |
| **2** | Reconcile every local binding for the capability, then pin Meta Social | this repository | the fix lands and is proved BEFORE the second connector is pinned |
| **3** | Settlement connectors (Paystack, Flutterwave) | the destination product, and the Starter's release lane | a compatible product port exists, and Flutterwave has a verified tag |

Collapsing them means a red CI run cannot tell you which of the three broke, and
— worse — slice 2's fix would land on the same commit as the connector that
needs it, so nothing would ever demonstrate the broken state it repairs.

---

# Slice 1 — Integration a10, WhatsApp a2, and the runtime-policy surface

**Status: implemented. This is the PR in front of you.** `version:minor`: the
operator surface gains a route and `create_app` gains a refusal, both additive,
with no migration and no removed contract.

## 1.1 What moved

| Distribution | From | To | Release evidence |
|---|---|---|---|
| `dotmac-integration` | `0.1.0a9` | `0.1.0a10` | tag `dotmac-integration-v0.1.0a10`, published from `7a59864` by run `32230755284` |
| `dotmac-connector-whatsapp` | `0.1.0a1` | `0.1.0a2` | tag `dotmac-connector-whatsapp-v0.1.0a2` |
| `dotmac-kernel` | `0.1.0a68` | `0.1.0a68` | unchanged — a10's floor is `>=0.1.0a68` and it did not move |

**The oracle is a git tag, not the index.** The Starter's release workflows write
a tag only after `verify-registry` has installed the exact published version back
from the private index and registered its manifest, so a tag is that repository's
own assertion that a version is installable — stronger than "an upload
succeeded". Both versions above were confirmed with `git ls-remote --tags`.

## 1.2 What a10 actually is, and what it asks of this repository

a10 raises the SPI to **1.3** and moves two declarations into the connector
manifest: the NAMED secret bindings a connector needs, and the EXACT provider
DNS hosts it may reach. It projects the installed manifest set through
`derive_runtime_policy` and then deliberately stops — it carries no provider
list and performs no I/O. Its own changelog says the independently deployed
Integrator projects the declarations into its runtime policy. That projection is
this slice.

`src/dotmac_integrator/runtime_policy.py` renders it, and **restates nothing**:
no host, no secret name, no provider identity. `GET /operations/runtime-policy`
publishes the exact egress union, the named bindings, a policy digest and
capability coverage on both sides.

Three properties are worth naming because each is a decision:

* **An empty egress is an explicit deny-all; an omitted one refuses the boot.**
  `derive_runtime_policy` refuses to project a pre-1.3 manifest, and
  `create_app` escalates that to a failed construction, beside
  `require_a_correct_surface`. Reading omission as deny-all would give a legacy
  connector the appearance of declared evidence, and the published policy digest
  would then cover a connector whose boundary nobody declared. There is
  deliberately no degraded-start knob.
* **The refusal is unreachable through the pins, so it is planted.** The one
  pinned connector declares `>=1.3,<2.0`. A guard whose only evidence is that it
  never fired is not enforcement, so `tests/unit/test_runtime_policy.py` drives
  it with a planted legacy manifest (ADR-0018).
* **The surface is guarded like every other `/operations` read.** It is a map of
  what this fleet's connectors may reach and which of their capabilities no
  product has declared — an operations answer, not a status page. It carries
  NAMES only: a secret binding name identifies a purpose, is not a reference and
  cannot be dereferenced, so rule 13 is untouched and nothing on the path
  reaches held material.

Deliberately NOT a metric: a policy digest or a connector key as a label would
break the closed label vocabulary (rule 18) for a value that changes only when a
release is installed, which a scrape is the wrong instrument for.

## 1.3 Migration bindings — re-derived, and unchanged

Rule 10 requires re-derivation at every pin bump, because a release that changes
`requires` changes what this assembly must assert about it. Re-derived for a10;
nothing moved, and the evidence is specific rather than a shrug:

* `manifest.requires` is byte-identical to a9 — `module_database_roles.v1`,
  `idempotency_ledger.v1`, `platform_audit_log.v1`, all three already bound.
* a10 ships **no new revision**. `ig_0011_replay_retention` is still the `ig`
  head; the release is confined to `spi.py`, the new `runtime_policy.py` and the
  version bump.
* The `ig_0001` literal edge on `0001_initial_tenant_schema` is unrepaired at
  a10 and permanently unrepairable — its bytes have run in databases the Starter
  does not own. This deployment composes that exact revision, so it is coping,
  not agreement.

A no-op re-derivation is RECORDED rather than skipped, because a reader at the
next bump otherwise cannot tell a checked no-op from an unexamined one.

## 1.4 Product ports — the a10 diff touches none of it

`ProductPortDescriptorV1`, `reconcile_product_port_descriptor`, the shadow port
and the mirror verdict are identical between a9 and a10. `product_port.py` needs
no change, and the wire contract it transcribes from the destination's own
merged port (rule 25) is unmoved.

## 1.5 The lock: generated in one lane, validated in another

The lock cannot be refreshed on the workstation — it needs the pinned Poetry
`2.4.1` and the forgejo read credential, and rule 30 forbids a validation lane
from running `poetry lock`, because that proves repaired state rather than the
commit.

So it is two lanes on Observer, and the separation is the point:

1. **Generation lane** — pinned Poetry 2.4.1, credential exported, `poetry lock`
   (never `--regenerate`: this is an ordinary dependency edit). The refreshed
   lock is committed.
2. **Validation lane** — a FRESH clone of the final commit, non-mutating:
   `poetry check --lock`, `poetry install --sync`, `make check`. It regenerates
   nothing. A lane that could repair what it validates cannot tell you whether
   the commit was already correct.

---

# Slice 2 — one reconciled binding becomes every binding, THEN Meta Social

**Status: not started. It is a separate change and must land before any second
connector is pinned.**

## 2.1 The limit, found by doing slice 1's validation

`PRODUCT_PORT_LOCAL_BINDING_ID` is one UUID.
`ProductPortDescriptorReconciler.reconcile` calls the module's
`reconcile_product_port_descriptor` once, for that binding, and that function is
per capability binding: it looks the binding up, checks the descriptor's
capability against the binding's, and writes the destination revision onto that
binding alone.

A capability binding is per installation × capability, and an installation is
per connector key. So a SECOND connector implementing the SAME capability gets
its own capability binding that no reconcile call reaches.

Concretely for `dotmac-connector-meta-social`, which implements
`messaging.receive.v1` alongside WhatsApp: its ingress would record receipts
durably, then delivery would fail to resolve a destination. A typed refusal,
counted and retried; nothing mis-delivered, no receipt marked done for an
observation nobody received. Fail-closed, and useless.

**This is why Meta Social is not in slice 1.** Pinning it there would ship a
connector that cannot deliver, and would do so in the same commit as the fix's
absence — leaving nothing that ever demonstrates the broken state.

## 2.2 The fix is the module's binding registry, not a longer environment variable

The tempting repair is `PRODUCT_PORT_LOCAL_BINDING_IDS`, a comma-separated set.
Reject it. It is a second list of bindings maintained by hand, in an environment
variable, beside the registry that already knows every binding and its
capability — exactly the parallel-authority shape the egress rule refuses one
file away, and it drifts silently the moment an operator adds a binding through
`/operations` and forgets the `.env`.

The correct source is the module. `CapabilityBinding` carries `capability_id`
and `installation_id`, `ConnectorInstallation` carries the state, and
`selection.resolve_binding` already encodes what "usable" means. Reconciliation
should ask the module which local bindings carry the descriptor's capability and
project onto each of them, inside one session and one commit, so partial
reconciliation is unreachable.

The module today exposes selection (exactly one binding, per dispatch) but no
enumerator (every binding for a capability). Slice 2 therefore starts in
`dotmac-integration`: add the enumerator beside `resolve_binding`, where the
usability predicate already lives, rather than hand-rolling a
`select(CapabilityBinding)` in the assembly — an assembly that wrote that query
would own a second opinion about which bindings are eligible.

Sequence:

1. `dotmac-integration` a11: a module-owned enumerator for "the bindings serving
   this capability", sharing `_usable` with `resolve_binding`.
2. Integrator: reconcile across the enumerated set; retire
   `PRODUCT_PORT_LOCAL_BINDING_ID` as the routing input. Prove a second binding
   on one capability reconciles, and that a binding whose capability differs
   from the descriptor's is still refused (the module already compares them).
3. Only then pin `dotmac-connector-meta-social 0.1.0a1` — tag
   `dotmac-connector-meta-social-v0.1.0a1` exists and is verified.

Interim, if Meta Social traffic is needed before slice 2 lands: run it in
`mirror` mode, which settles nothing, or do not enable it. The symptom to watch
is a rising undelivered count for one binding on `/operations/health-report`
while another binding on the same capability is healthy.

---

# Slice 3 — settlement connectors wait on a product port and a tag

**Status: blocked on two other repositories. Nothing to do here.**

## 3.1 No application declares the capability

`dotmac-connector-paystack` and `dotmac-connector-flutterwave` implement
`payments.settlement.observation.v1`. The destination this deployment is
configured against declares one capability and it is not that one — Sub's
`app/schemas/integrator_observation.py` types it as
`capability_id: Literal["messaging.receive.v1"]`.

Installing is not binding: `dotmac_integration.destination_binding` calls
`require_declared_for_binding`, which refuses a binding naming an undeclared
capability, so a settlement receipt could never be mis-delivered. But a
connector that can never be bound is not readiness, so it is not pinned.

**Which application owns a settlement observation is a product decision** — Sub
billing or ERP — and this assembly may never mint a capability declaration
(rule 27). The unblocking work is in the owning product's repository: declare
the capability and publish it in that application's port descriptor. When a
compatible port exists, `/operations/runtime-policy`'s
`capabilities.implemented_without_declaration` closes on its own.

## 3.2 Flutterwave is not released

`dotmac-connector-flutterwave 0.1.0a1` is **merged and release-allowlisted in
the Starter, and not released.** It is a live row in
`docs/inventories/declared-publication-baseline.json`:

> ALLOWLISTED FOR RELEASE, NOT YET RELEASED, AND NOT ADOPTED. […] Remove this
> row only after the protected-main release installs the exact artifact back
> from the registry, verifies conformance and writes
> `dotmac-connector-flutterwave-v0.1.0a1`.

There is no such tag. Pinning it would make `poetry lock` the step that
discovers the version does not exist, on whichever machine ran it next. Paystack
`0.1.0a1` IS tagged; it waits on § 3.1 alone.

---

# What no slice does

Stated so the next reader does not mistake absence for oversight:

* **No connector activation.** No installation is drafted, no binding is
  configured or enabled, no ingress endpoint is minted.
* **No external traffic.** No provider is repointed, no callback URL moves, no
  incumbent receiver is retired and no ratchet is lowered.
* **No product cutover.** Shadow comparison against Sub remains the gate, and
  the final cutover is a product decision the module refuses to make for
  anybody.
* **No product domain decision.** No capability is declared, no port descriptor
  is authored, no destination is chosen.
* **No egress enforcement mechanism.** The declared union is published and is
  deny-all today. Rendering it into a NetworkPolicy or firewall rule is a
  deployment step; this repository publishes the exact set precisely so that
  step has one source rather than a second list.

# Slice 1 verification

CI is the acceptance owner. What must go green, and what each gate asserts:

- [ ] `poetry check --lock` clean against the committed lock (§ 1.5).
- [ ] `test_pins_are_exact.py` — every `dotmac-*` dependency is an exact version
      and the lock agrees. Parametrisation is derived from `pyproject.toml`, so
      a future pin is covered without a second list.
- [ ] `test_installed_wheels.py` — the connector pin contributes exactly one
      entry point, and discovery finds exactly the pinned set.
- [ ] `test_runtime_policy.py` — the projection, deny-all reporting, the pre-1.3
      refusal driven with a planted legacy manifest, and capability coverage in
      both directions.
- [ ] `test_the_assembly_stays_thin.py` — no host-shaped literal in the
      projection, and the module's three calls are actually made.
- [ ] `test_bindings_are_declared.py` / `test_the_bindings_are_proven.py` — the
      restated a10 requirement set, and the live-catalog proof against a
      migrated scratch database.
- [ ] `test_operator_surface.py` — `/operations/runtime-policy` is classified
      OPERATOR and carries `require_operator`. `create_app` refuses an
      incorrectly classified surface, so this failing is a boot failure.
