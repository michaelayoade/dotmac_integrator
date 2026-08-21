# Integrator runbook

Operating the connector control plane: deploy, roll back, rotate material, and
restore. Everything here is about the DEPLOYMENT. Anything about what a
connector does belongs to `dotmac-integration` or to the connector's own
distribution.

Two roles, and they are not interchangeable:

| | role | may |
|---|---|---|
| `DATABASE_URL` | `platform_api` | row DML, schema USAGE. **Cannot create a table.** |
| `MIGRATION_DATABASE_URL` | `app_admin` | owns the schema. Used by the migration job **only**. |

`MIGRATION_DATABASE_URL` is absent from the `api` service's environment on
purpose. A compromised web process must not be able to read the credential that
can drop the ledger it is meant to be writing to.

---

## Deploy

```bash
export INTEGRATOR_TAG=<the tag under review>
docker compose pull
docker compose up -d --wait
```

The order is enforced, not asked for: `api` declares
`depends_on: migrate: {condition: service_completed_successfully}`, so the
runtime does not start until the migration job has exited 0.

**Never** run the bare `alembic` CLI here. It resolves `version_locations`
before `env.py` runs, and this deployment installs wheels — so the lineages
cannot be named in `alembic.ini`. The CLI finds no revisions, has nothing to do,
and **exits 0** against an empty database. `migrations/env.py` refuses loudly
if it is reached with no locations resolved.

`heads`, plural. Two lineages with distinct branch labels are composed; `head`
upgrades one branch and reports success, silently leaving the other unapplied.

### Is it up

| probe | means |
|---|---|
| `GET /health/live` | the process is running. Touches nothing external — a liveness probe that queries the database turns a blip into a crash loop. |
| `GET /health/ready` | database reachable **and** schema present. 503 until the migration job has run. This is what decides whether a replica takes traffic. |
| `GET /health/composition` | the kernel and module versions actually loaded, read from the installed distributions rather than from the pins. |

A replica that is `live` and not `ready` for more than a minute after the
migration job succeeded means the online role cannot reach the database — check
the DSN and the grant, not the image.

### Shutdown

`stop_grace_period` is 30s. On SIGTERM the lifespan stops claiming new work,
lets the in-flight sweep finish, then disposes the pool — in that order,
because disposing first strands leases held by an operation still settling.
`uvicorn` is PID 1 (the `CMD` uses `exec`), so the signal reaches it directly.

A lease stranded by a hard kill is not lost: it expires, and the next sweep —
timed, or `POST /operations/leases/release-expired` — returns it to the queue
with its attempt count intact.

---

## Roll back

A rollback is an image change, **not** a schema change.

```bash
export INTEGRATOR_TAG=<the previous tag>
docker compose up -d --wait
```

The migration job runs again and is a no-op: every lineage is already at its
head, and Alembic applies nothing.

**Do not `downgrade` to roll back.** A downgrade drops columns and tables that
the previous image also read, so the failure mode of a bad downgrade is data
loss rather than a failed deploy. If a migration is genuinely wrong, roll the
image back first — the old code against the new schema is the case
expand/contract migrations are designed for — and then fix forward.

`downgrade` exists for exactly one situation: a migration that failed partway
in a maintenance window, with a restore already taken.

---

## Operators

The `/operations` surface is guarded, so the first operator cannot be created
through it. There is no HTTP self-registration path for a platform actor, ever.

```bash
OPERATOR_PASSWORD='…' \
MIGRATION_DATABASE_URL='…' \
  poetry run python -m dotmac_integrator.bootstrap_operator --email you@dotmac.io
```

Owner credentials, deliberately: creating an operator is the same trust
boundary as changing the schema. The password comes from the environment or a
prompt and never from `argv`, which is readable by every process on the host.

Re-running for an existing email resets the password and reactivates the
account — the second reason anyone runs this is a lockout.

### Getting a token

```bash
curl -sX POST https://$PLATFORM_ROOT_DOMAIN/platform/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@dotmac.io","password":"…"}'
```

Requests are **host-exact**: a request whose `Host` is not
`PLATFORM_ROOT_DOMAIN` is refused before any database lookup.

### Revoking one

Set `revoked_at` on the `platform_sessions` row, or `is_active = false` on the
`platform_admins` row. Both take effect on the next request — that is the
operational point of a session table, and it is why revocation does not wait
for a token to expire.

---

## Connector releases and runtime boundaries

A connector enters this deployment ONE way: it is exactly pinned in
`pyproject.toml`, resolved into the image, and found through the
`dotmac_integration.connectors` entry-point group. There is no registration
call, no admin screen that installs one, and no way to add one to a running
process.

After a deployment that moves a connector pin, check the projection before
enabling anything:

```bash
curl -sH "Authorization: Bearer $OPERATOR_TOKEN" \
     https://$HOST/operations/runtime-policy | jq
```

What to read, in the order it matters:

1. **`policy_digest`** — the identity of the manifest set now running. It
   changes when, and only when, an installed connector's reviewable contract
   changes: its key, version, SPI range, capability set, secret-binding names
   and requiredness, or its egress hosts. A digest that did NOT change across a
   deploy you expected to change one means the image did not pick up the pin.
2. **`egress_hosts` / `egress_denies_all`** — the exact set this deployment's
   connectors declared they may reach. Every connector pinned today declares
   an EMPTY egress, which under SPI 1.3 is an explicit deny-all rather than an
   unset field, so `egress_denies_all` is `true` and the union is `[]`. If a
   future connector release declares a host, this is where it appears — and it
   appears here BEFORE anything needs to reach it, which is the point.
3. **`secret_bindings`** — the logical names each connector needs, and which
   are required. Names, never references and never values. Cross-check against
   `GET /operations/secrets`, which says which references actually resolved.
4. **`capabilities.implemented_without_declaration`** — installed connectors
   whose capability no product has declared. These cannot be bound: the module
   refuses a destination binding naming an undeclared capability, so the
   connector sits installed and inert. That is a **product** decision to make
   or decline, not a configuration one; do not try to route around it.
   `capabilities.declared_without_implementation` is the mirror image — a
   contract that resolves while nothing ever arrives.

**A boot that refuses with `RuntimeBoundaryMissing` naming a connector key** is
telling you an installed connector's manifest predates SPI 1.3 and declares
neither its secret bindings nor its egress. The remedy is a connector release
that declares them; there is deliberately no knob that starts anyway, because a
policy digest covering an undeclared boundary is worse than a failed boot.

Wiring the declared egress union into an actual network policy or firewall is a
deployment step this repository does not take for you — it publishes the exact
set and refuses to be the second list.

**Breaking for AUTHORING, not for running installations: SPI 1.3 retires
operator-chosen secret slot aliases.** Under 1.2 an operator invented the slot
names and keyed `secret_refs` by them:

```jsonc
// RETIRED — a config revision written this way is now refused 409
"config":      { "signing_slots": ["signing"], "handshake_slot": "handshake" },
"secret_refs": { "signing": "env://...", "handshake": "env://..." }
```

Under 1.3 the logical names are part of the installed package's contract, so
`config` is EMPTY and `secret_refs` is keyed by the names the connector's own
manifest declares — read them off
`GET /operations/runtime-policy` under `secret_bindings`, never from memory:

```jsonc
"config":      {},
"secret_refs": { "<declared name>": "env://...", "<declared name>": "env://..." }
```

Existing revisions are NOT invalidated: a connector keeps its old manifest in
`historical_manifests`, so a persisted revision pinned to the old digest still
validates and the installation keeps running. Only a NEW revision is written
against the current manifest. The refusal is explicit — a 409 naming the
capability and `config_additionalProperties` — rather than a silent acceptance
that fails later at verification.

**Known limit: one reconciled local binding per boot.**
`PRODUCT_PORT_LOCAL_BINDING_ID` is one UUID, and the product-port descriptor is
reconciled onto that one local capability binding at startup. A SECOND connector
implementing the SAME capability gets its own capability binding, which no
reconcile call reaches — its receipts are recorded by ingress and then fail to
resolve a destination. Nothing is lost and nothing is mis-delivered; the
receipts simply accumulate. The symptom is a rising undelivered count for one
binding on `/operations/health-report` while another binding on the same
capability is healthy. Until the setting takes a set, run the second connector
in `mirror` mode or do not enable it. See `docs/UPGRADE-READINESS.md`, slice 2.

---

## Secret material

**A secret is held, never dereferenced** (ADR-0009). Material is loaded into
memory at startup and on an explicit refresh; nothing fetches a secret while
handling a request, and there is no TTL.

The set of material this deployment needs is not configured anywhere — it is
the `secret_refs` already stored in the module's configuration revisions. Two
schemes are implemented, neither of which touches a network:

| scheme | source | confined to |
|---|---|---|
| `env://NAME` | this process's environment | `SECRET_ENV_PREFIX` |
| `file:///path` | a read-only mount | `SECRET_FILE_ROOT` |

The confinement is not decoration. A reference is data an operator wrote into a
configuration revision; without it, `env://DATABASE_URL` in that row would hand
this process's own credentials to a connector.

`bao://`, `aws-sm://` and `gcp-sm://` are recognised by the module and **not
implemented here**. Each needs a store client, an address and an auth method —
a reviewed change with a named deployment target, not a configuration toggle.
Until one exists, material from the fleet's store is injected out of band by the
orchestrator and referenced as `env://` or `file://`.

### Provisioning or rotating

1. Make the material available (write the file, set the variable, redeploy).
2. `POST /operations/secrets/refresh` with a reason.
3. `GET /operations/secrets` — every reference should now be under `held`.

A **failed** refresh keeps the working set: a mount that vanished during a
rotation attempt leaves a working process working, and the response says the
rotation did not land.

### When an enablement is refused

`409` naming a reference means the material is not held. `GET
/operations/secrets` says why — wrong prefix, outside the root, file absent,
scheme not enabled. Nothing in that report is a value; there is no accessor
anywhere in this deployment that returns one.

`502` naming a leaking diagnostic means the connector echoed the credential it
failed to authenticate with into its own error text. The failure was **not**
recorded, because a configuration row is immutable and reaches every backup.
That is a bug in the connector: a diagnostic may name a credential, never quote
one.

---

## Backup and restore

This deployment owns no volume. Its entire durable state is one PostgreSQL
database — seven `mod_intg` tables plus the kernel's `public` schema, all
platform-plane, no tenant data, no RLS.

### Backup

```bash
pg_dump --format=custom --no-owner --no-privileges \
        --file "integrator-$(date -u +%Y%m%dT%H%M%SZ).dump" "$MIGRATION_DATABASE_URL"
```

`--no-owner --no-privileges` because roles and grants are created by the
deployment's own provisioning, not by the dump — restoring them from a dump
means restoring whatever the roles happened to be on the day it was taken.

**The dump contains no secret material.** Configuration revisions hold
references only, which is enforced at the write by
`dotmac_integration.secret_refs`. It does contain provider payloads on
`inbox_receipts` and `delivery_attempts`, so it is treated as customer data:
encrypted at rest, retained to the same policy as any other Dotmac database
dump.

### Restore

```bash
createdb integrator_restored
pg_restore --no-owner --no-privileges -d integrator_restored <dump>
# then grant the two roles, exactly as provisioning does:
psql -d integrator_restored -c 'GRANT USAGE ON SCHEMA mod_intg TO platform_api'
# … and re-run the migration job, which is a no-op if the dump was at head
```

Verify with the same audit CI runs: `poetry run pytest tests/composition -q`
against the restored database proves the plane contract still holds — no tenant
column, no RLS, `app_user` holding nothing.

**After any restore, refresh secret material.** The process holds what it loaded
at ITS startup; a restored database can carry configuration revisions
referencing material this process has never seen.

### What a restore does not fix

An in-flight delivery is `in_flight` with a lease in the dump. After a restore
those leases are held by workers that no longer exist. Run
`POST /operations/leases/release-expired` — it only touches leases that have
already expired, so it is safe to run twice, and it does not reset the attempt
count because the attempt genuinely happened.
