# dotmac_integrator

The independently deployed **connector control plane**. It composes
`dotmac-integration` — the module that owns every connector decision — and adds
only what a deployment can own.

```
dotmac-kernel 0.1.0a67  ──┐
                          ├──►  dotmac_integrator  ──►  connector distributions
dotmac-integration 0.1.0a3┘         (this repo)          (installed, discovered)
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

`dotmac-kernel` and `dotmac-integration` are pinned **exactly**, and a test
enforces it. A library declares the earliest version it works with; a deployment
declares the exact one it was tested against. `>=` here would let an install
months from now compose a combination nobody has ever run.

| Distribution | Pin | Why this one |
|---|---|---|
| `dotmac-integration` | `0.1.0a3` | The newest **published** release — `dotmac-integration-v0.1.0a3`, tagged from the Starter and verified on the registry. `0.1.0a4` exists only as an open pull request and cannot be installed. |
| `dotmac-kernel` | `0.1.0a67` | The newest published kernel. `0.1.0a3` floors at `>=0.1.0a58`, so a58…a67 all satisfy it; a67 is chosen because it is the first release registering `outbox_relay.v1`, the last of the four effects bound in `migration_bindings.py`, and because `0.1.0a4` will floor at `>=0.1.0a66` — pinning below that would make the next pin bump two changes instead of one. |

**When `dotmac-integration 0.1.0a4` is published**, the bump is one line here and
one line in `pyproject.toml`. Its manifest declares `idempotency_ledger.v1`,
which this assembly already binds and already proves against a real database, so
nothing else has to move — that is the whole reason the binding landed first.

Moving a pin is a reviewed diff with its own CI run — `make outdated` shows
what is available. The lockfile must be regenerated with it (`poetry lock`),
which needs the registry credentials below.

## Lineage bindings

A module lineage declares the database *effects* it needs and never names a
foreign revision, because the answer differs per assembly.
`src/dotmac_integrator/migration_bindings.py` is where this deployment answers,
and the answers are **proven, not believed**:

- statically, that every bound revision exists in a lineage this assembly
  actually composes (`tests/architecture/test_bindings_are_declared.py`);
- against a live PostgreSQL, by running the kernel's own verifier for each bound
  effect — and by proving that verification *bites* on this composition
  (`tests/composition/test_the_bindings_are_proven.py`);
- at deploy time, by `require_prerequisites` inside any requiring migration.

Two things about the current release are worth knowing rather than discovering:

1. **`dotmac-integration 0.1.0a3` declares no prerequisites at all**, yet
   `idempotency.run_effect_once` writes `public.platform_idempotency_records` on
   every guarded delivery. The dependency is real, undeclared until `0.1.0a4`,
   and satisfied here only because this deployment composes the whole kernel
   lineage. It is bound and proven now so that is a fact rather than luck.
   `platform_audit_events` is the same shape and cannot be bound: the kernel
   registers no prerequisite name for it yet.
2. **`ig_0001_connector_cp` ships a literal `depends_on =
   ("0001_initial_tenant_schema",)`** — a physical edge naming a foreign
   revision, which is the thing the prerequisite vocabulary exists to replace.
   It is a known module defect, resolved in the Starter rather than here. This
   assembly copes by composing the lineage that contains that exact revision id,
   so Alembic resolves the edge; an adopter that does not run kernel `0001`
   cannot install the module at all. No binding can rewrite an edge a released
   migration hard-codes.

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
