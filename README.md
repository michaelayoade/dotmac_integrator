# dotmac_integrator

The independently deployed **connector control plane**. It composes
`dotmac-integration` — the module that owns every connector decision — and adds
only what a deployment can own.

```
dotmac-kernel 0.1.0a58  ──┐
                          ├──►  dotmac_integrator  ──►  connector distributions
dotmac-integration 0.1.0a1┘         (this repo)          (installed, discovered)
```

## What this repository is allowed to contain

| Owned here | Owned by `dotmac-integration` |
|---|---|
| Configuration | Retry, backoff, lease duration, attempt limits |
| Health and readiness probes | Connector health assessment |
| Operational controls (adapters) | Lifecycle transitions, activation, binding selection |
| Worker startup and scheduling | The work itself |
| Lineage composition | The migrations |
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

Platform-plane only (ADR-0023). Seven tables in `mod_intg`, no `tenant_id`, no
RLS, and `app_user` REVOKEd from all of them — on this plane the REVOKE **is**
the isolation. A connector installation and its delivery evidence are
control-plane facts; none belongs to a tenant.

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

## Pins

`dotmac-kernel` and `dotmac-integration` are pinned **exactly**, and a test
enforces it. A library declares the earliest version it works with; a deployment
declares the exact one it was tested against. `>=` here would let an install
months from now compose a combination nobody has ever run.

Moving a pin is a reviewed diff with its own CI run — `make outdated` shows
what is available.

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
