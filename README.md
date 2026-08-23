# dotmac_integrator

The independently deployed **connector control plane**. It composes
`dotmac-integration` — the module that owns every connector decision — and adds
only what a deployment can own.

```
dotmac-kernel  0.1.0a68  ──┐
                           ├──►  dotmac_integrator  ──►  connector distributions
dotmac-integration 0.1.0a13┘        (this repo)          (pinned, discovered)
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
`/operations/connectors` by being installed. There is no registration call.
The deployment manifest names and exactly pins connector DISTRIBUTIONS; generic
assembly source imports no connector and carries no provider branch or registry.

The complete published cohort is pinned today: WhatsApp, Meta Social, LinkedIn,
Mono, Remita, Paystack and Flutterwave. Installation makes each distribution
discoverable; it does not activate it or declare a product capability. Those
decisions remain in the durable installation/binding registry and in
product-owned descriptors.

It is installed and discoverable here; shadow comparison against Sub remains the
cutover gate before any incumbent receiver is retired or its ratchet is lowered.

**Composed is not the same as delivering.** `docs/UPGRADE-READINESS.md` carries
the release and adoption evidence:

* **Overlapping connectors share a product declaration without a parallel
  binding list.** Integration a12 enumerates every durable binding for the
  descriptor's capability and reconciles the set atomically. The assembly no
  longer accepts a local binding UUID, so adding an installation cannot create
  an omitted, undeliverable sibling behind stale environment configuration.
* **Settlement now has a product-owned port and a generic wire.** Paystack and
  Flutterwave are both released and verified. Sub declares
  `payments.settlement.observation.v1` through its billing acceptance port;
  integration a13 projects engine-owned source provenance into ProductObservation
  v1, and this assembly selects that protocol only from descriptor v2. The
  remaining work is operational adoption: reconcile the authenticated descriptor,
  run Paystack shadow first, cut it over on zero unexplained drift, then repeat
  for Flutterwave v4. ERP remains the GL owner and receives only product-owned
  accounting consequences, never provider transport.

### Runtime boundaries (SPI 1.3)

`dotmac-integration 0.1.0a10` moved two declarations into the connector
manifest: the NAMED secret bindings a connector needs, and the EXACT provider
hosts it may reach. The module projects the installed manifest set into one
immutable policy (`derive_runtime_policy`) and stops there — it knows nothing
about a network policy or a secret store.

`src/dotmac_integrator/runtime_policy.py` is this deployment's half. It restates
nothing: there is no host, no secret name and no provider identity in it, and
`test_the_assembly_stays_thin.py` fails the build on a host-shaped literal.
`create_app` refuses to start when an installed connector's manifest predates
1.3, beside the surface audit and for the same reason — an omitted boundary is
the absence of evidence wearing the same shape as deny-all, and the published
policy digest would cover a connector nobody declared a boundary for.

Deliberately NOT a metric. A policy digest or a connector key as a label would
break the closed label vocabulary (hard rule 18) for a value that changes only
when a release is installed, which a scrape is the wrong instrument for.

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

Every route belongs to one of four CLASSES, and `create_app` refuses to return
an app that breaks a class rule — it is a boot failure, not a test failure.

| Class | Prefix | Rule |
|---|---|---|
| probe | `/health/**` | Unauthenticated, read-only. An orchestrator holds no credential, and a probe that fails closed on an auth outage restarts healthy replicas. |
| operator | `/operations/**` | `require_operator` on **every** route, reads included. Every mutation additionally carries a required `reason`. |
| ingress | `/ingress/**` | Provider-authenticated inside the discovered connector, and must never carry the operator guard. |
| scrape | configured `METRICS_PATH` | Monitoring credential, read-only; neither an operator token nor a provider signature. |

| Route | Purpose |
|---|---|
| `GET /health/live` | Process alive. Touches nothing external — a liveness probe that queries the database turns a blip into a crash loop. |
| `GET /health/ready` | Database reachable and schema present. 503 until migrated. |
| `GET /health/composition` | Loaded versions, read from the installed distributions rather than the pins. |
| `GET /operations/connectors` | Installed connector distributions. |
| `GET /operations/health-report` | The module's report, unmodified. |
| `GET /operations/secrets` | Which references resolved and why the others did not. **Names only.** |
| `POST /operations/secrets/refresh` | Rotation. Explicit, never a TTL. |
| `POST /operations/installations` | Draft and pin one discovered connector. Provider-neutral. |
| `POST /operations/installations/{id}/bindings` | Create/update one connector-declared capability binding. |
| `POST /operations/installations/{id}/config-revisions` | Write or select one immutable, digest-idempotent config revision. Secret references only. |
| `POST /operations/installations/{id}/enable` | Materialises the revision's references, then the module's live connection check. |
| `POST /operations/bindings/{id}/ingress-endpoint/mint` | Mint a bearer endpoint and return the key once; the key is never audited. |
| `POST /operations/bindings/{id}/enable` | Ask the module to prove and enable the binding. |
| `POST /operations/leases/release-expired` | Reclaim leases whose holder died. |
| `POST /operations/deliveries/{id}/replay` | |
| `POST /operations/receipts/{id}/replay` | |
| `GET /ingress/{endpoint_key}` | Provider activation handshake. Answers for a CONFIGURED but still DISABLED binding. |
| `POST /ingress/{endpoint_key}` | Provider delivery. Requires binding AND installation enabled. |
| `GET /metrics` | Prometheus text exposition, bearer-authenticated. 404 when unauthorized. `METRICS_ENABLED=false` removes it. |

`reason` is required rather than defaulted: an assembly that invented one would
put a fabricated justification into the audit record of a manual intervention,
which is worse than no record.

Reads are guarded too. The connector inventory and the health report together
describe which integrations this fleet runs and which of them are unattended,
which is reconnaissance rather than a status page.

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

Every Dotmac runtime distribution is pinned **exactly**, and the gate discovers
that set from `pyproject.toml` so a newly added connector cannot evade it by
being absent from a second list. A library declares the earliest version it
works with; a deployment declares the exact one it was tested against. `>=`
here would let an install months from now compose a combination nobody ran.

| Distribution | Pin | Why this one |
|---|---|---|
| `dotmac-connector-whatsapp` | `0.1.0a2` | The first published ingress connector, re-released at SPI `>=1.3,<2.0` with its runtime boundaries declared. It keeps its a1 manifest in `historical_manifests`, so an installation pinned to the a1 digest is not invalidated by this bump. |
| `dotmac-integration` | `0.1.0a13` | Published SPI **1.3** module. Adds ProductObservation v1 projection, engine-owned source resolution and descriptor v2 compatibility; the lineage head remains `ig_0011` and `requires` is unchanged, which is why the bindings below are a re-derived no-op rather than an unexamined one. |
| `dotmac-kernel` | `0.1.0a68` | Current pinned kernel. It satisfies the module's `>=0.1.0a68` floor — a10 did not move it — and is the exact release this composition is tested against. |

### What a pin bump actually costs

An earlier draft of this file claimed the a3 → a4 bump was "one line here and one
line in `pyproject.toml`". That was wrong, and it was wrong in an instructive
way: a4's whole content is that it declares `requires`, and this repository's
tests were written to assert the SHAPE of a release that declared nothing. A bump
that changes what the module says about itself changes what the assembly must
assert about the module.

The real cost, as a checklist:

1. `pyproject.toml`, and the committed lock updated with the exact Poetry
   declared by `requires-poetry`.
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

### Poetry is pinned too

`[tool.poetry].requires-poetry` is the one toolchain source. CI and the runtime
image install that exact release from the committed hash-locked bootstrap, and
`make poetry-lock-check` refuses an ambient Poetry, stale bootstrap, or lock
generated by another version before dependency work begins.

For an ordinary dependency change, run `poetry lock` with the declared tool and
review the lock diff. Validation runs `poetry check --lock` against the
committed file; it never repairs it first. `poetry lock --regenerate` belongs
only in an explicit dependency/toolchain upgrade, because it may re-resolve
otherwise unrelated packages. A Poetry upgrade also regenerates the bootstrap
with `.github/bootstrap/regenerate.sh`.

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
- at deploy time, by `require_prerequisites` inside `ig_0007_idempotency_ledger`
  and `ig_0008_platform_audit_log`, whose bodies are those checks.

`dotmac-integration 0.1.0a13` requires three effects, and all three are bound:

| Effect | Provider revision | Why the module needs it |
|---|---|---|
| `module_database_roles.v1` | kernel `0001_initial_tenant_schema` | every `ig` migration GRANTs to `app_admin`/`platform_api`/`app_user` and must never create a role itself |
| `idempotency_ledger.v1` | kernel `0018_idempotency_one_owner` | `idempotency.run_effect_once` writes `public.platform_idempotency_records` on every guarded delivery |
| `platform_audit_log.v1` | kernel `0026_platform_audit_log` | module and assembly operator actions append audit facts through the online platform role, which must hold SELECT+INSERT and no mutation grant |

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

### The platform audit dependency is now explicit

Kernel a68 registers and verifies `platform_audit_log.v1`; integration a9's
`ig_0008` requires it. This assembly binds the effect to kernel `0026`, where
the platform audit role becomes append-only. The former unnameable dependency
is therefore a deploy-time verified contract rather than request-time luck.

### `ig_0001`'s literal edge is permanent — and it is the adoption constraint

`ig_0001_connector_cp` ships `depends_on = ("0001_initial_tenant_schema",)`: a
physical edge naming a foreign revision, the exact thing the prerequisite
vocabulary exists to replace. **It is still there at `0.1.0a13`, and it cannot be
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

The client is **implemented** here and **not authored** here. Descriptor v1
keeps the legacy messaging contract transcribed from Sub. Descriptor v2 uses
`dotmac_integration.product_observation_document`: the engine owns the generic
envelope and durable source provenance, while the destination product owns and
validates the typed `observation`. Selection is by descriptor protocol version
only; no product, provider, connector or capability branch exists here. A
disagreement is a defect here, or a contract change that happens in the owning
product first.

Five decisions worth reading before touching it:

- **`provider_event_id` comes from the durable receipt and crosses raw.** The
  destination namespaces it with its own observation-kind prefix. A connector's
  transitional payload copy is accepted only when it agrees; it never selects
  the identity sent to the product.
- **The fingerprint covers exactly what the destination validates.** The client
  builds one explicit typed body (including nested location attachments), hashes
  it, and sends that same body. Sub recomputes over its `exclude_unset` model
  dump, preserving those explicitly supplied fields. The connector's sparse
  dict is never fingerprinted by accident.
- **Transport evidence stops at the transport boundary.** The module retains
  `transport_evidence` on its receipt for repair; the client deliberately omits
  it from Sub's domain envelope. Unknown fields are still refused, so this does
  not become a general suppression mechanism.
- **The product publishes one authenticated descriptor.** It owns the remote
  binding id, capability declaration, port paths, contract version and opaque
  stream scope. `ProductPortDescriptorReconciler` checks an operator-approved
  digest and idempotently appends the module's immutable projection. There is
  no parallel binding map or capability declaration in this assembly.
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
settles nothing, and returns verdict counts. Each comparison is appended through
the module's `record_shadow_observation` service to
`mod_intg.shadow_comparison_evidence`, keyed by the immutable
`PRODUCT_PORT_SHADOW_REVISION`. Terminal results run once per receipt and
revision; `no_counterpart`, `unreadable`, and `unrecognized` results are sampled
again only after `PRODUCT_PORT_SHADOW_RETRY_SECONDS`. Changing the revision
deliberately re-drives the full population after an image or contract change.

`GET /operations/shadow-report` asks the module to reduce the latest observation
per receipt into counts, field names and an observation window. It emits no
receipt or provider identifiers. `sample_has_no_blockers` describes that
non-empty sample only; it cannot approve a cutover without traffic-cycle,
replay/collision, credential-scope, migration and rollback evidence.

The failure this prevents is the expensive one. A shadow run that settled
receipts as `processed` would look exactly like a completed cutover, while every
observation it "delivered" was seen by nobody.
