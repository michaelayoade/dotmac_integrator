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

| Route | Purpose |
|---|---|
| `GET /health/live` | Process alive. Touches nothing external — a liveness probe that queries the database turns a blip into a crash loop. |
| `GET /health/ready` | Database reachable and schema present. 503 until migrated. |
| `GET /health/composition` | Loaded versions, read from the installed distributions rather than the pins. |
| `GET /operations/connectors` | Installed connector distributions. |
| `GET /operations/health-report` | The module's report, unmodified. |
| `POST /operations/leases/release-expired` | Reclaim leases whose holder died. |
| `POST /operations/deliveries/{id}/replay` | Requires a `reason`. |
| `POST /operations/receipts/{id}/replay` | Requires a `reason`. |

`reason` is required rather than defaulted: an assembly that invented one would
put a fabricated justification into the audit record of a manual intervention,
which is worse than no record.

## Pins

`dotmac-kernel` and `dotmac-integration` are pinned **exactly**, and a test
enforces it. A library declares the earliest version it works with; a deployment
declares the exact one it was tested against. `>=` here would let an install
months from now compose a combination nobody has ever run.

Moving a pin is a reviewed diff with its own CI run — `make outdated` shows
what is available.

## Validation

`make check` runs lint, formatting, types and the no-database tests. CI runs the
same list plus a **composition** job that applies every lineage to a real
PostgreSQL as the owner role and audits the result — without it, these
migrations would first run in production.
