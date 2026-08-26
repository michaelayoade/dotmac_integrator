# dotmac_integrator

The independently deployed **connector control plane**. It composes
`dotmac-integration` — the module that owns every connector decision — and adds
only what a deployment can own.

```
dotmac-kernel 0.1.0a67  ──┐
                          ├──►  dotmac_integrator  ──►  connector distributions
dotmac-integration 0.1.0a4┘         (this repo)          (installed, discovered)
```

## What this repository is allowed to contain

| Owned here | Owned by `dotmac-integration` |
|---|---|
| Configuration | Retry, backoff, lease duration, attempt limits |
| Health and readiness probes | Connector health assessment |
| Operational controls (adapters) | Lifecycle transitions, activation, binding selection |
| Worker startup and scheduling | The work itself |
| Lineage composition, and which revision supplies each effect | The migrations, and which effects they need |
| Materialising secret REFERENCES into values | Storing the references, and refusing values |
| Operator identity, and the actor on every audit row | The audit vocabulary and what each event means |

**No provider logic. No business decisions.** That is not a convention — it is
`tests/architecture/test_the_assembly_stays_thin.py`, which fails the build if
this assembly names a provider, assigns an `ExecutionPolicy` field, redefines a
module-owned function, queries from a route handler, or issues DDL.

Read `assembly.py`'s route table and you have read the whole deployment.

## Why it is a separate deployment and not a Starter feature

"Independently deployed" is a **runtime** boundary. It does not make the
Integrator a separate place to write code — the reusable behaviour is a Starter
module, published as a wheel, and this repository is the thin assembly that pins
and composes it (ADR-0024 §§ 6-7).

The Starter deliberately does **not** compose this module: `app/assembly.py`
omits it and its `alembic.ini` carries no `ig` lineage, because every Starter
deployment would otherwise grow a `mod_intg` schema it never uses.

## Persistence

Platform-plane only (ADR-0023). Every table the module declares lands in
`mod_intg` with no `tenant_id`, no RLS, and `app_user` REVOKEd from all of them —
on this plane the REVOKE **is** the isolation. A connector installation and its
delivery evidence are control-plane facts; none belongs to a tenant. The count is
deliberately not restated here: `test_the_module_schema_exists_with_exactly_its_
declared_tables` compares the live schema against the manifest, so the manifest
is the list and a number in this file could only ever go stale.

Two roles, and they are not interchangeable:

- `DATABASE_URL` → `platform_api`, the **online** role. Row DML and schema
  USAGE. It cannot create a table, by design.
- `MIGRATION_DATABASE_URL` → `app_admin`, the **owner**. Used only by
  `make migrate`, at deploy time, never on boot.

## Connectors

A connector is a **separately released distribution**, discovered through the
`dotmac_integration.connectors` entry-point group. It appears in
`/operations/connectors` by being installed. There is no registration call, and
no connector is named anywhere in this repository.

The first one will be Meta/WhatsApp, **ingress-only**, shadowed against the
current owner before anything is retired or the external-connector ratchet is
lowered.

## Running it

```bash
cp .env.example .env          # then edit
make install                  # needs registry credentials, see below
make migrate                  # as the OWNER role — a deploy step, not a boot step
make run
```

**Never run the bare `alembic` CLI here.** It resolves `version_locations`
before `env.py` runs, and this deployment installs wheels — so the lineages
cannot be named in `alembic.ini`. The CLI would find no revisions and exit 0
against an empty database. `make migrate` goes through
`python -m dotmac_integrator.migrate`, which sets the locations first; `env.py`
refuses loudly if it is reached without them.

Registry credentials come from the environment and are never written to
`pyproject.toml` or the lockfile:

```bash
export POETRY_HTTP_BASIC_FORGEJO_USERNAME=ci-reader
export POETRY_HTTP_BASIC_FORGEJO_PASSWORD=...   # OpenBao: secret/dotmac/forgejo/read-token
```

## Surface

Every route belongs to one of three CLASSES, and `create_app` refuses to return
an app that breaks a class rule — it is a boot failure, not a test failure.

| Class | Prefix | Rule |
|---|---|---|
| probe | `/health/**` | Unauthenticated, read-only. An orchestrator holds no credential, and a probe that fails closed on an auth outage restarts healthy replicas. |
| operator | `/operations/**` | `require_operator` on **every** route, reads included. Every mutation additionally carries a required `reason`. |
| ingress | `/ingress/**` | Provider-authenticated, and must never carry the operator guard. **Nothing is mounted here yet** — the classification exists before the adapter so the adapter cannot inherit the wrong auth. |

| Route | Purpose |
|---|---|
| `GET /health/live` | Process alive. Touches nothing external — a liveness probe that queries the database turns a blip into a crash loop. |
| `GET /health/ready` | Database reachable and schema present. 503 until migrated. |
| `GET /health/composition` | Loaded versions, read from the installed distributions rather than the pins. |
| `GET /operations/connectors` | Installed connector distributions. |
| `GET /operations/health-report` | The module's report, unmodified. |
| `GET /operations/secrets` | Which references resolved and why the others did not. **Names only.** |
| `POST /operations/secrets/refresh` | Rotation. Explicit, never a TTL. |
| `POST /operations/installations/{id}/enable` | Materialises the revision's references, then the module's live connection check. |
| `POST /operations/leases/release-expired` | Reclaim leases whose holder died. |
| `POST /operations/deliveries/{id}/replay` | |
| `POST /operations/receipts/{id}/replay` | |
| `POST /commands/provisioning/plan` | Ed25519-authenticated typed plan validation; signed receipt response. |
| `POST /commands/provisioning/apply` | Accept and drive one exact approval-bound apply step through the module ledger. |
| `POST /commands/provisioning/observe` | Observe one indeterminate/remote operation after every signed pin matches durable state. |
| `POST /commands/provisioning/cancel` | Bounded typed cancellation after every signed pin matches durable state. |
| `GET /ingress/{endpoint_key}` | Provider activation handshake. Answers for a CONFIGURED but still DISABLED binding. |
| `POST /ingress/{endpoint_key}` | Provider delivery. Requires binding AND installation enabled. |
| `GET /metrics` | Prometheus text exposition, bearer-authenticated. 404 when unauthorized. `METRICS_ENABLED=false` removes it. |

`reason` is required rather than defaulted: an assembly that invented one would
put a fabricated justification into the audit record of a manual intervention,
which is worse than no record.

Reads are guarded too. The connector inventory and the health report together
describe which integrations this fleet runs and which of them are unattended,
which is reconnaissance rather than a status page.

### Machine provisioning commands

`/commands/**` is a third authentication population: neither a person on
`/operations/**` nor a provider on `/ingress/**`. Every body is a strict
`integrator.provisioning-command.v1` envelope signed with Ed25519 and binding
`key_id`, exact audience, timezone-aware `issued_at`/`expires_at`,
`command_id`, `nonce`, and the canonical body hash. `nonce` must equal
`command_id`; the module's durable command record is the one replay/collision
owner, so this assembly has no nonce cache or second ledger.

`COMMAND_ISSUER_ASSIGNMENTS_REF` names a held JSON document with contract
`integrator.command-issuer-assignments.v2`. Its exact shape is an
`assignments` array of `{key_id, account_ref, deployment_instances}` records;
each deployment entry is
`{deployment_ref, capability_instance_refs}`. All three lists are non-empty,
unique and canonically sorted. The assignment key set must exactly equal the
held public-key set. V1 is not accepted as a wildcard migration. PLAN, APPLY,
OBSERVE and CANCEL all carry `deployment_ref` and `capability_instance_ref`,
and the guard refuses any unassigned exact pair before delegation. The derived
`account_ref` and signed pair are projected into the signed receipt.

Canonical JSON is UTF-8 with recursively sorted keys, `,`/`:` separators,
ASCII escaping, explicit nulls, and no non-finite numbers (`NaN` and infinities
are refused before hashing). The body hash is `sha256:` plus the SHA-256
hex digest of that canonical body. The Ed25519 signature covers the canonical
header without `signature` or `body`; `body_sha256` binds the body. The checked
cross-repository vector is
[`docs/fixtures/provisioning_plan_command_v1.json`](docs/fixtures/provisioning_plan_command_v1.json)
for PLAN and
[`docs/fixtures/provisioning_apply_command_v1.json`](docs/fixtures/provisioning_apply_command_v1.json)
for APPLY.
PLAN stays deliberately minimal: `deployment_ref`, `capability_id`,
`capability_instance_ref`, `capability_binding_id`, `plan_hash`,
`config_digest`, and exact `steps`. The
module resolves and verifies the local binding, connector configuration and
owner contract, then persists an immutable settlement receipt keyed by the
envelope's command id and request-body digest.

An APPLY body carries the static, pre-approval fields
`approved_command_template_digest` and
`prerequisite_capability_binding_ids`, the static
`prerequisite_evidence_bindings`, plus the dispatch-time
`prerequisite_receipt_pins` (all three arrays are present and empty when there
are no cross-binding edges). Binding ids are unique and sorted
lexicographically by their canonical lowercase UUID strings. The approved
template is exactly
`deployment_ref`, positive `desired_state_revision`,
`desired_state_version_id`, `desired_state_hash`, `saved_plan_id`,
`profile_version_id`, `profile_code`, positive
`profile_version` and `profile_schema_version`, `profile_content_hash`,
`command_schema_version`, `capability_id`, `capability_instance_ref`,
`capability_owner_code`,
`capability_code`, positive `capability_schema_version`,
`capability_contract_attestation_id`, `capability_contract_digest`, and the
canonically sorted exact request/result schema identities for the a69 engine
verbs (`apply`, `cancel`, `observe`, `plan`) in `capability_operations`,
`capability_binding_id`, equal `binding_ref`, `installation_id`,
`installation_ref`, `connector_key`, `connector_version`,
`connector_manifest_digest`, `connector_configuration_revision_id`,
`configuration_snapshot_ref`, positive `configuration_schema_version`,
`configuration_hash`, `artifact_digest` (the connector artifact), the explicit
nullable `component_artifact_digest`, `config_digest`,
`execution_policy_digest` (the module-owned policy fingerprint, never
assembly-authored policy values), exact provider-neutral `steps`, and
`prerequisite_capability_binding_ids` plus
`prerequisite_evidence_bindings`. For this first SPI, every step
`endpoint_code` equals the versioned `capability_id`; it is not an a69 engine
operation code. The template excludes
`plan_hash`, `approval_request_id`, approval/grant material, the later PLAN
validation evidence, and dynamic prerequisite receipt pins. Its digest uses the
same canonical JSON and `sha256:` encoding as the body. Both the top-level
field and `approval.approved_command_template_digest` must equal that computed
digest.

APPLY and its verified grant carry the same `approval_request_id`,
`approval_request_binding_hash`, `saved_plan_id`, `plan_command_id`,
`plan_validation_receipt_id` (the Vendor's verified-ingress row),
`plan_validation_receipt_digest` (the signed transport receipt digest),
`plan_validation_request_body_digest`, and `module_plan_receipt_hash`. The
Integrator compares body and grant; the module corroborates the PLAN command,
request digest and module receipt against its locked durable command record. No
assembly receipt or replay ledger is introduced.

Each dynamic pin has exactly these fields:

| field | wire type | constraint |
|---|---|---|
| `operation_id` | UUID string | immutable upstream operation |
| `capability_binding_id` | UUID string | maps one-for-one to the approved static prerequisite set |
| `terminal_receipt_sequence` | integer | at least 1; must be the upstream operation's latest terminal receipt |
| `terminal_receipt_digest` | string | `sha256:` plus 64 lowercase hex characters |
| `required_terminal_status` | string | exactly `succeeded` in v1 |

The pin array is unique by `operation_id` and sorted lexicographically by its
canonical lowercase UUID string. Same-binding `steps[].depends_on` contains
only step keys from that APPLY body; cross-binding edges are the approved
symbolic binding set plus the exact later receipt evidence. Dynamic receipt
pins are deliberately excluded from the global plan hash and template digest
because they do not exist at approval time. They remain covered by the command
body hash/signature and the module's command replay fingerprint.

Each static evidence mapping has exactly these fields:

| field | wire type | constraint |
|---|---|---|
| `source_capability_binding_id` | UUID string | member of the approved prerequisite binding set |
| `source_step_key` | stable code | exact upstream step |
| `source_schema_ref` / `source_schema_digest` | canonical schema ref / `sha256:` digest | upstream operation's persisted a69 APPLY-output schema |
| `source_pointer` | string | non-root RFC 6901 pointer classified `public_non_secret` by the held output schema |
| `target_step_key` | stable code | member of this command's exact step set |
| `target_schema_ref` / `target_schema_digest` | canonical schema ref / `sha256:` digest | this command's a69 APPLY-input schema |
| `target_pointer` | string | non-root RFC 6901 input location, unique with its target step |
| `required` | boolean | whether absent upstream public evidence refuses execution |

Mappings are unique and sorted by
`(source_capability_binding_id, source_step_key, source_pointer,
target_step_key, target_pointer)`, using the canonical lowercase UUID string.
Operation identity is implicitly APPLY. No evidence value appears in the
approved template or command. The module schema-validates connector output and
persists only its classified public projection in the upstream immutable
receipt. For a downstream step it validates the exact upstream receipt pin,
source and target held schemas and public classification, injects into a copy
of the step input immediately before connector I/O, and records only the
resolved-input digest for that injection rather than copying resolved values
into audit material. The assembly owns no evidence store or resolver.

The assembly opens and closes each module transaction around prepare and
settle, and invokes the connector with no session held. Apply identity,
plan/observe/cancel replay, prerequisite-receipt validation, expected-pin
comparison, operation state and the structured receipt chain all belong to
`dotmac-integration`. It recomputes the static template digest, requires the
verified grant to approve it, and locks upstream operations in UUID order. It
then requires the same deployment and plan, exact binding, succeeded state,
and exact latest terminal receipt sequence/hash/status before plugin I/O. The
module resolves approved cross-binding evidence only from that locked
receipt's public projection; secret and unclassified evidence fail closed. The
APPLY route claims and invokes at most one durable step per authenticated
dispatch. While the receipt remains actionable, the caller re-dispatches the
same command id and body (in a fresh valid envelope when necessary); a replay
may therefore advance the next unclaimed step but can never duplicate a
settled one. An `indeterminate` outcome is observed or cancelled and is never
blindly applied again.

The HTTP response signs the module's verified projection with a separate Integrator
receipt key; it never attests an unverified caller-supplied observe/cancel pin.
The module owns and verifies the immutable hash chain; it accepts no private-key
signer. This assembly owns only the canonical transport projection and its
separate Ed25519 signature.
For PLAN the signed transport projection lifts the module settlement receipt
hash and complete receipt material (command fingerprint, request-body digest,
result digest, capability instance reference and receipt hash).
For APPLY/OBSERVE/CANCEL the signed transport projection also lifts the latest
module receipt sequence and hash beside the full verified `module_receipts`
chain. Every projected operation receipt includes the module-owned nullable
`step_key` and `provider_operation_ref`; operation-level receipts carry nulls,
while step-result receipts carry both, so a receiver never infers a multi-step
correlation from free-form evidence. Every transport and module receipt also
projects the immutable `capability_instance_ref`. A receiver verifies both the transport
signature and module-chain continuity through that terminal pin.

The command setting is off by default. When enabled with the real gateway,
construction requires the complete published module façade and refuses boot
before mounting routes if any symbol is absent. The currently declared a4 pin
does not provide that façade. Integration a5 and kernel a68 were subsequently
published for independent verification-evidence/contract changes, so the first
admissible command-surface releases are Integration a6 built on kernel a69.
Both must be published and registry-verified before the exact pins move; a
working-tree or path dependency is not release evidence.

## Secret material

**A secret is HELD, never dereferenced** (ADR-0009). References are loaded into
memory at startup and on an explicit `POST /operations/secrets/refresh`;
nothing fetches a secret while handling a request. Which material is needed is
not configured anywhere — it is the `secret_refs` the module already stores in
its configuration revisions.

Two schemes are implemented, neither touching a network: `env://NAME` confined
to `SECRET_ENV_PREFIX`, and `file:///path` confined to `SECRET_FILE_ROOT`. The
confinement matters because a reference is operator-written data: without it,
`env://DATABASE_URL` in a configuration row would hand this process's own
credentials to a connector.

`bao://`, `aws-sm://` and `gcp-sm://` are recognised by the module and
deliberately **not** implemented here. Each needs a store client, an address and
an auth method — a reviewed change with a named deployment target, not a
configuration toggle. Enabling one is refused at boot.

This is what makes enablement possible at all: `lifecycle.enable` gates on a
LIVE `validate_connection`, which takes values. See `docs/RUNBOOK.md`.

## Operators

`require_operator` is an ADAPTER over `dotmac_kernel.platform_auth` — the
kernel's own predicate, called with this assembly's session. No second identity
model, no second token population, and an auth fix in the kernel arrives by
moving the pin.

The first operator is created out of band, with the OWNER credentials, because
the surface that could create one is itself guarded and there is no HTTP
self-registration path for a platform actor:

```bash
OPERATOR_PASSWORD='…' make bootstrap-operator EMAIL=you@dotmac.io
```

## Observability

`GET /metrics` publishes facts; `deploy/alerts/ingress.rules.yml` decides what
they mean; `docs/RUNBOOK-restore-and-reconciliation.md` says what to do about
them. The split is deliberate — a threshold in the process would fork from the
rule that fires on it, and one of the two would then be wrong forever.

Three properties are worth knowing before reading `telemetry.py`:

**Every backlog that can age reports a depth AND an age.** `receipts_unprocessed
1` reads as a quiet night and is also what one receipt stuck since March looks
like. The alerts fire on the ages.

**An age with nothing to measure is absent, not zero.** Zero would mean "the
oldest due delivery is due right now" — the healthiest reading of the
unhealthiest cause.

**No metric label can carry an identifier, structurally.** Every metric family
declares the complete set of label values it will ever accept — from a database
CHECK constraint, a dataclass's fields, or a closed tuple — and the renderer
*raises* on anything else. An endpoint key, a `provider_event_id`, a phone
number, message content or anything derived from a secret has no code path to a
label. `tests/architecture/test_no_identifier_reaches_a_label.py` drives that
with real-looking values, and applies the same rule to log lines. Correlate an
alert to a customer through the audit ledger, never through a label: a scrape
outlives the row and is readable by everyone with a dashboard.

**`/metrics` authenticates.** `Authorization: Bearer $METRICS_TOKEN`, compared
in constant time, and unauthorized is answered **404 rather than 403** — a 403
is an oracle telling a prober the endpoint exists. An unset token falls back to
**loopback only, never to open**, and is prod-fatal in `validate_settings`,
because a production replica binds a routable interface and "loopback only"
there is an endpoint nobody can scrape on a port anybody can reach. This is the
fleet's observability auth standard; the labels carrying no identifier is a
second line of defence, not a reason to skip the first.

**The payload-retention period is deliberately unset.** The module refuses to
purge until it is configured, and the alert file ships the breach rule beside a
commented-out recording rule with no value in it — so the breach alert cannot
fire and `IntegratorPayloadRetentionNotConfigured` does instead. See the runbook.

## Pins

`dotmac-kernel` and `dotmac-integration` are pinned **exactly**, and a test
enforces it. A library declares the earliest version it works with; a deployment
declares the exact one it was tested against. `>=` here would let an install
months from now compose a combination nobody has ever run.

| Distribution | Pin | Why this one |
|---|---|---|
| `dotmac-integration` | `0.1.0a4` | This assembly's latest registry-verified pin. Published a5 adds SPI verification evidence but not the provisioning façade; jumping through it cannot enable commands. The next candidate is a6 after publication/index verification. |
| `dotmac-kernel` | `0.1.0a67` | This assembly's latest verified kernel pin. `0.1.0a4` floors at `>=0.1.0a66`; published a68 is already allocated, so the managed contract grammar must release as a69 before the assembly pin moves with Integration a6. |

### What a pin bump actually costs

An earlier draft of this file claimed the a3 → a4 bump was "one line here and one
line in `pyproject.toml`". That was wrong, and it was wrong in an instructive
way: a4's whole content is that it declares `requires`, and this repository's
tests were written to assert the SHAPE of a release that declared nothing. A bump
that changes what the module says about itself changes what the assembly must
assert about the module.

The real cost, as a checklist:

1. `pyproject.toml`, and `poetry lock` regenerated with a Poetry matching CI's.
2. **The bindings** — re-derived from the new `requires`, not assumed unchanged.
   a4 both added two requirements and made two previously bound effects
   unrequired; see below.
3. **The tests that assert the old shape** — the empty-`requires` case became a
   populated one, which flipped which sensitivity proof is the meaningful one.
4. This section, and the "Lineage bindings" section.

What genuinely did *not* move: the kernel pin, because it was chosen at the a3
bump to already satisfy a4's floor. That much of the earlier claim holds.

Moving a pin is a reviewed diff with its own CI run — `make outdated` shows
what is available. The lockfile must be regenerated with it (`poetry lock`),
which needs the registry credentials below.

## Lineage bindings

A module lineage declares the database *effects* it needs and never names a
foreign revision, because the answer differs per assembly.
`src/dotmac_integrator/migration_bindings.py` is where this deployment answers,
and the answers are **proven, not believed**:

- statically, that every bound revision exists in a lineage this assembly
  actually composes, and that every effect a composed manifest requires is bound
  (`tests/architecture/test_bindings_are_declared.py`);
- against a live PostgreSQL, by running the kernel's own verifier for each bound
  effect — and by proving that verification *bites* on this composition
  (`tests/composition/test_the_bindings_are_proven.py`);
- at deploy time, by `require_prerequisites` inside `ig_0007_idempotency_ledger`,
  whose entire body is that call.

`dotmac-integration 0.1.0a4` requires two effects, and both are bound:

| Effect | Provider revision | Why the module needs it |
|---|---|---|
| `module_database_roles.v1` | kernel `0001_initial_tenant_schema` | every `ig` migration GRANTs to `app_admin`/`platform_api`/`app_user` and must never create a role itself |
| `idempotency_ledger.v1` | kernel `0018_idempotency_one_owner` | `idempotency.run_effect_once` writes `public.platform_idempotency_records` on every guarded delivery |

Neither names the lineage root by default: `0018` is bound rather than `0001`
because a database stopped at `0017` would order correctly, satisfy a
root-binding, and have no ledger.

### Two bindings were RETIRED at the a4 bump

Under a3 this assembly also bound `tenant_scope_catalog.v1` and
`outbox_relay.v1`. Both were truthful — the composed kernel lineage really does
supply them — and both are gone, because a truthful answer to a question nobody
asks is decoration that CI has to maintain:

- **`tenant_scope_catalog.v1`** — not required by a4, and structurally so: every
  foreign key in the `ig` lineage targets `mod_intg.*`, and this deployment owns
  no tenant plane at all (`module.tables == ()`). There is no FK for a tenant
  catalogue to be the target of.
- **`outbox_relay.v1`** — nothing composed here touches
  `dotmac_kernel.messaging`. The module's own "outbox" is
  `mod_intg.delivery_attempts` with its own claim loop; the name collides with
  the kernel relay and the machinery does not.

Retired is not unavailable: both effects are still *supplied* by the composed
kernel lineage, so re-binding one is three lines — landed beside the module that
requires it — and `binding_for` fails closed with an explicit message meanwhile.

### `platform_audit_events` is a kernel gap, not worked around here

`dotmac_integration.operations` adapts
`dotmac_kernel.audit.write_platform_audit_event`, so this deployment depends on
that table at request time. It has no binding because the kernel registers no
prerequisite name for it — the same class of gap `idempotency_ledger.v1` and
`outbox_relay.v1` closed in kernel a66 and a67. It is deliberately **not**
worked around in the assembly: an effect with no name cannot be bound, and
inventing a local one would make this assembly a second authority over the
kernel's vocabulary.

### `ig_0001`'s literal edge is permanent — and it is the adoption constraint

`ig_0001_connector_cp` ships `depends_on = ("0001_initial_tenant_schema",)`: a
physical edge naming a foreign revision, the exact thing the prerequisite
vocabulary exists to replace. **It is still there at `0.1.0a4`, and it cannot be
repaired at any version.** The file shipped in a1, a2, a3 and a4; its bytes have
run in databases the Starter does not own, and `alembic_version` records that a
revision ran, never which version of it. a4 added `ig_0007` rather than editing
the root for precisely that reason.

So, plainly, and it is the single biggest constraint on who can adopt this
assembly:

> **An adopter that cannot run kernel `0001_initial_tenant_schema` cannot install
> `dotmac-integration` at all** — regardless of how correct its prerequisite
> bindings are. ERP is the standing example: it hosts `public.tenants` in its own
> lineage, so kernel `0001` would collide, permanently.

This is demonstrated rather than argued. Compose only the `ig` lineage and
building the revision map raises:

```
KeyError: '0001_initial_tenant_schema'
```

Note *when* that happens: Alembic builds the revision map **before any command
runs**, so such an adopter cannot even `alembic history` the lineage to find out
what is wrong, let alone `upgrade` it. There is no partial mode, no
"install-without-that-edge", and no binding that helps — a binding answers which
revision supplies an *effect*, and this is a hard-coded revision *id*.

This deployment is unaffected only because it composes that exact revision. That
is coping, not agreement, and no binding can rewrite an edge a released migration
hard-codes.

## Deployment

`docker-compose.yml` is the shape: one image, two services, and the ORDER is
enforced rather than asked for. `migrate` runs the composed lineages as the
OWNER role and exits; `api` starts only on
`service_completed_successfully`, on the online platform role, and never
touches DDL. `MIGRATION_DATABASE_URL` is absent from the runtime service's
environment on purpose.

The image is non-root, carries no registry credential (the token arrives
through a BuildKit secret mount, not an `ARG`), and its default command binds a
port rather than migrating. `scripts/audit_image.sh` asserts all of that
against the built artefact, in CI.

`docs/RUNBOOK.md` covers deploy, rollback, operator bootstrap, rotation, and
backup/restore.

## Validation

`make check` runs lint, formatting, types and the no-database tests. CI runs the
same list plus two more jobs: **composition**, which applies every lineage to a
real PostgreSQL as the owner role and audits the result — without it, these
migrations would first run in production — and **image**, which audits the
artefact that actually ships.

## Public ingress

Two routes into `dotmac_integration`'s three-phase engine, and three things
this assembly owns that the engine correctly refuses to.

**The body is bounded as it is read.** `read_capped_body` consumes
`request.stream()` and refuses on byte `limit + 1`. Reading an unbounded body
in order to reject it is the denial of service the cap exists to prevent, and
doing it before an HMAC is worse: a signature covers the whole body, so
verifying first means buffering first. `INGRESS_MAX_BODY_BYTES` is the knob;
the 413 and the code come from the module's own `PayloadTooLarge`, because an
ingress status is a retry instruction to the provider and inventing one
silently destroys events.

**The endpoint key never reaches a log.** It is a bearer credential carried in
the URL path — whoever holds it can drive that connector's `verify`. The module
takes structural care to keep it out of its own error text and cannot help with
the URL, because it never sees one. `redaction.py` closes that: a filter on the
loggers, a `del` in the route so no frame local survives for a locals-capturing
error reporter, an unvalidated path parameter so no 422 echoes it, and a closed
label vocabulary. Each surface has a sensitivity proof showing the value DOES
appear when the redaction is removed.

**Handshake and delivery do not share an eligibility rule, and must not.** GET
answers for a binding that is configured but still disabled; POST requires the
binding and its installation both enabled. A single predicate makes activation
circular with any provider that requires a completed handshake before a
subscription can be enabled: the operator cannot enable the binding until the
provider is subscribed, and the provider cannot subscribe until the endpoint
answers. Nothing about verification is relaxed — only which binding may be
addressed.

## Receipt delivery

Recording that a provider event arrived is not delivering it. The worker's
second pump lands recorded observations in the product that owns them, through
`dotmac_integration.receipt_delivery` — `ReceiptClaims` for the claim
(a conditional UPDATE where `rowcount == 1` IS the claim) and `deliver_receipt`
for the ordering (claim → call with no session held → settle). Neither is
reimplemented here, and a test bans the SQL that would mean they had been.

`due_receipt_ids` is a plain unlocked SELECT. Two workers being handed the same
id is expected and costs one losing UPDATE — much cheaper than a row lock held
while the product is contacted, which is what `FOR UPDATE SKIP LOCKED` quietly
becomes.

`ProductPortClient` is a port the deployment installs at startup, held in memory
(ADR-0009), and with none installed the pump does not run and says so. It does
not fall back to marking receipts delivered — that would be the inbox lying at a
different layer.

### The client (`product_port.py`)

The client is **implemented** here and **not authored** here. Authoring a wire
contract inside the transport is what ADR-0024 forbids: this assembly would
become the sole author of a shape two systems must agree on. The contract is the
destination's — `dotmac_sub`'s `app/api/integrator_observations.py` and
`app/schemas/integrator_observation.py`, reviewed and merged there — and every
field, length, status and refusal code in this file is transcribed from it. A
disagreement is a defect here, or a change that happens there first.

Four decisions worth reading before touching it:

- **`provider_event_id` crosses the wire raw.** The destination namespaces it
  with its own observation-kind prefix. Pre-prefixing here would produce a
  second identity for one upstream event — a duplicate, not a dedupe — and it
  would double-record every message in flight during the producer overlap.
- **The fingerprint covers the destination's own canonical body.** It recomputes
  a canonical-JSON SHA-256 over its model dump, which carries every declared
  field including the null ones and an empty attachment list. A fingerprint over
  the sparse dict a connector supplied would fail *every* delivery, complaining
  about a mangled body rather than about a missing key.
- **The destination's binding id is configured, never derived.** Its port is
  keyed on ITS capability-binding UUID, in ITS database. This deployment's is a
  different UUID; posting the wrong one 404s at best and writes to somebody
  else's binding at worst. `PRODUCT_PORT_BINDINGS` carries the pairing, and an
  unmapped binding is refused before the network with its own code.
- **Acceptance is mapped honestly.** `ACCEPTED` and `ALREADY_APPLIED` both mean
  the destination holds the consequence — `replayed` is the evidence the
  deduplication worked, and collapsing it would hide a double-send.
  `UNAVAILABLE` means nothing landed and the same envelope may be sent again.
  A 409 identity collision is `INDETERMINATE`: the observation owner is
  reporting that two producers disagree about what the provider said, and that
  needs a human, not a retry and not a dead letter.

### Shadow, and why it cannot settle

The destination exposes a second, strictly narrower port that records nothing
and answers with a parity verdict, under its own scope so a shadow credential
cannot become a writer by accident. That narrowness is honoured on this side:
the client declares a direction, `install_product_port` requires it, a `MIRROR`
client's `deliver` raises, and the delivery pump refuses to run against one. A
shadow deployment runs `mirror_due_receipts` instead — it claims nothing,
settles nothing, and returns verdict counts.

The failure this prevents is the expensive one. A shadow run that settled
receipts as `processed` would look exactly like a completed cutover, while every
observation it "delivered" was seen by nobody.
