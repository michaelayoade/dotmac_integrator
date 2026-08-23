# Upgrade readiness — the connector programme, in three slices

**Date:** 2026-08-23 · **Scope:** composition only. No connector is activated,
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
| **2** | Reconcile every local binding for the capability, then pin the published cohort | module + this repository | a12 is registry-verified before the exact assembly pins resolve |
| **3** | Compose the settlement product wire; activate Paystack, then Flutterwave | product + module + this repository | Sub's v2 descriptor and ProductObservation v1 agree before shadow begins |

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

## 1.3 WhatsApp a2 is not configuration-compatible, and that is the point

Found by CI's composition job on the first push of this branch, which is the
argument for driving the operator flow over HTTP against a real database rather
than asserting that a pin moved.

a2 does not merely re-declare boundaries. Because SPI 1.3 makes the logical
secret names part of the installed package's contract, the connector's current
`config_schema` is `additionalProperties: false` with NO properties — the
operator-chosen slot aliases of the 1.2 shape are gone, and `secret_refs` is
keyed by the DECLARED binding names instead.

| | SPI 1.2 (a1) | SPI 1.3 (a2) |
|---|---|---|
| `config` | `{"signing_slots": [...], "handshake_slot": "..."}` | `{}` |
| `secret_refs` keys | operator-invented aliases | the manifest's declared names |

**Running installations are unaffected.** The connector keeps its a1 manifest in
`historical_manifests`, so a persisted revision pinned to the a1 digest still
validates and its installation keeps working — which is exactly what that field
is for. Only a NEW config revision is written against the current manifest, and
the old shape is refused with a 409 naming the capability rather than accepted
and failing later at verification.

Two tests carry this: the end-to-end authoring flow was rewritten to the 1.3
shape, and `test_the_pre_1_3_configuration_shape_is_refused` drives the retired
shape deliberately. The second is not decoration — a rewrite that only asserted
the new shape would pass just as happily if the module had quietly kept
accepting the old one, and nobody would learn that an operator following the
previous runbook writes a revision the connector cannot use. `docs/RUNBOOK.md`
carries the operator-facing note.

## 1.4 Migration bindings — re-derived, and unchanged

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

## 1.5 Product ports — the a10 diff touches none of it

`ProductPortDescriptorV1`, `reconcile_product_port_descriptor`, the shadow port
and the mirror verdict are identical between a9 and a10. `product_port.py` needs
no change, and the wire contract it transcribes from the destination's own
merged port (rule 25) is unmoved.

## 1.6 The lock: generated in one lane, validated in another

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

# Slice 2 — one reconciled binding becomes every binding, then the cohort

**Status: implemented.** Integration a12 owns capability-wide binding
enumeration and atomic descriptor reconciliation; this assembly consumes that
operation and pins the complete published connector cohort.

## 2.1 The limit, found by doing slice 1's validation

Before a12, `PRODUCT_PORT_LOCAL_BINDING_ID` was one UUID and
`ProductPortDescriptorReconciler.reconcile` called the module's single-binding
`reconcile_product_port_descriptor` once. That function looked the binding up,
checked the descriptor's capability against it, and wrote the destination
revision onto that binding alone.

A capability binding is per installation × capability, and an installation is
per connector key. A second connector implementing the same capability therefore
received its own capability binding that no reconcile call reached.

Concretely for `dotmac-connector-meta-social`, which implements
`messaging.receive.v1` alongside WhatsApp: its ingress would record receipts
durably, then delivery would fail to resolve a destination. A typed refusal,
counted and retried; nothing mis-delivered, no receipt marked done for an
observation nobody received. Fail-closed, and useless.

**This is why Meta Social was not in slice 1.** Pinning it there would have shipped a
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

Integration a12 now exposes `capability_bindings_for` and
`reconcile_product_port_descriptor_for_capability`. The latter reads the
complete durable set and projects one authenticated product descriptor across
it in the caller-owned transaction. It includes configured and disabled
bindings intentionally: destination projection precedes activation, so an
enabled-only query would recreate the circular activation failure this slice
exists to remove.

Sequence:

1. `dotmac-integration` a12 added the module-owned enumeration and atomic
   capability-wide reconciler, with a two-binding canary and an unrelated-
   capability negative control.
2. Integrator retired `PRODUCT_PORT_LOCAL_BINDING_ID` and delegates once to the
   capability-wide operation after the authenticated descriptor read.
3. The assembly pins WhatsApp, Meta Social, LinkedIn, Mono, Remita, Paystack and
   Flutterwave exactly. Discovery remains the only registration mechanism;
   installing them does not activate or bind them.

Capability coverage remains reported rather than decided. A connector whose
capability no product declares is visible on `/operations/runtime-policy` and
cannot be bound; product adoption supplies the missing descriptor in its own
cutover slice.

---

# Slice 3 — settlement product wire composed; operational adoption follows

**Status: the Sub-owned port and generic Integrator wire are implemented. This
slice changes no installation, binding, callback or external traffic.**

## 3.1 Both connectors are released and verified

An earlier revision of this file said Flutterwave was unreleased. That was true
when it was written and is now wrong — corrected here rather than left to be
discovered by whoever tried to pin it.

| Distribution | Version | Tag → commit | Evidence |
|---|---|---|---|
| `dotmac-connector-paystack` | `0.1.0a2` | `dotmac-connector-paystack-v0.1.0a2` | released through the protected lane |
| `dotmac-connector-flutterwave` | `0.1.0a2` | `dotmac-connector-flutterwave-v0.1.0a2` | v4-only release, verified through the protected lane |

Flutterwave's publication-baseline row is **gone** from Starter `origin/main`,
which is the other half of the release contract: a ledger that only grows stops
describing anything, so the row is removed in the same change as the release.
Both halves check out — the tag exists and the row does not.

At the tag, `dotmac-connector-flutterwave 0.1.0a2` declares connector key
`flutterwave`, capability `payments.settlement.observation.v1`, SPI
`>=1.3,<2.0`, an empty (deny-all) egress and `dotmac-integration >=0.1.0a10`.

**Nothing about publication blocks this repository any more.** What blocks it is
below, and it is not ours.

## 3.2 The ownership question is CLOSED: Sub, via the billing acceptance port

Ruled 2026-08-21. The first declaring application is **Sub**, targeting the
**`dotmac-billing` acceptance port** — **not ERP**. The layering, which is the
part worth carrying forward:

| Layer | Owns |
|---|---|
| **Integrator** | PSP transport and the observations it records. Nothing else. |
| **Billing** | Allocation and financial consequences — the money decisions. |
| **ERP** | Downstream accounting facts, and the GL. |

This is consistent with the checked-in extraction dossier, which already
specifies Paystack ingress against Sub first, with Flutterwave following in a
later adoption slice — so the two connectors are not adopted as a pair, and
Paystack going first is a sequencing decision that has already been made
elsewhere.

It also settles a question this file previously left open ("Sub billing or
ERP"). ADR-0020 § A3 already split payments in two — billing owns the money
decisions, the transport is transport — and this ruling applies that split to
the settlement observation rather than inventing a new boundary.

## 3.3 The product contract now exists, and the assembly does not restate it

Sub now declares `payments.settlement.observation.v1` through a billing-owned
descriptor v2 and accepts the generic `dotmac.io/product-observation/v1`
envelope. Integration a13 derives `source` from its durable installation and
binding, carries that provenance in the request fingerprint and owns the generic
document builder. The assembly selects v1 or v2 only from the authenticated
descriptor schema version; it contains no settlement, product or provider
branch.

Read-only shadow uses the same module-owned source resolver as the leased write
path. This matters because otherwise the thin assembly would need its own join
from binding to installation and would become a second persistence interpreter
just to avoid claiming a receipt.

## 3.4 The remaining gate is operational, not architectural

The published connectors are already pinned. What remains is to create the
Paystack installation and binding, authenticate and reconcile Sub's descriptor,
mint ingress as required, and run the mirror path until every sampled event has
zero unexplained drift. Only then may the product callback/client/credential and
retry path be retired and its ratchet lowered. Flutterwave v4 repeats the same
sequence after Paystack; the two are not activated as a pair.

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

- [ ] `poetry check --lock` clean against the committed lock (§ 1.6).
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
- [ ] `test_the_operator_surface_end_to_end.py` (composition, PostgreSQL) — the
      authoring flow in a2's SPI 1.3 shape, and the retired 1.2 shape refused.
      This is the gate that caught § 1.3, and it runs only in the database job.
