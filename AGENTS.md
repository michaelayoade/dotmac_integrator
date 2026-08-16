# dotmac_integrator — hard rules

This is a **thin assembly**. The reusable behaviour lives in
`dotmac-integration`, a published wheel. See `README.md` for the shape and
`docs` in the Starter for ADR-0023 (dual-plane) and ADR-0024 (app independence).

1. **No provider logic and no business decisions.** Retry, backoff, lease
   duration, attempt limits, lifecycle transitions, binding selection and
   activation belong to `dotmac_integration`. Enforced by
   `tests/architecture/test_the_assembly_stays_thin.py`.
2. **No connector is named here.** Connectors are separately released
   distributions found through the `dotmac_integration.connectors` entry-point
   group. Installing one is the only way it enters.
3. **The Dotmac dependencies are pinned exactly**, and the lock must agree
   (`tests/architecture/test_pins_are_exact.py`). No path or git sources — this
   assembly consumes published wheels, not a second checkout of the Starter.
4. **Routes are adapters.** No session, no query, no commit in `assembly.py`;
   that lives in `operations.py`. Same split the Starter enforces between
   `router.py` and `service.py`.
5. **Migrations run as the owner at deploy time, never on boot**, and through
   `python -m dotmac_integrator.migrate` — never the bare `alembic` CLI, which
   resolves `version_locations` before `env.py` and would exit 0 having applied
   nothing. Always `heads`, plural: two lineages are composed.
   `MIGRATION_DATABASE_URL` is the owner role; `DATABASE_URL` is the online
   platform role and cannot create a table.
6. **Platform plane only.** No `tenant_id`, no RLS, no tenant context. `app_user`
   holds nothing, and schema USAGE belongs to `platform_api` alone.
7. **Everything by config**, with a documented default and prod-fatal checks in
   `validate_settings`. Never hardcode a host, port or DSN.
8. **A guard exemption states an enforceable premise** (ADR-0018), and every
   detector carries a sensitivity proof. A check that cannot demonstrate it
   bites is not enforcement.
9. **Secrets are referenced, never stored.** Registry credentials come from the
   environment; nothing secret enters `pyproject.toml`, the lockfile, a commit,
   or a log line.
10. **A lineage binding is proven, never asserted.** A module declares the
    database *effects* it needs; this assembly answers which revision supplies
    each, in `src/dotmac_integrator/migration_bindings.py`. Every answer is
    checked statically against the revisions actually composed
    (`tests/architecture/test_bindings_are_declared.py`) and against a live
    catalog through the kernel's own verifiers
    (`tests/composition/test_the_bindings_are_proven.py`), with the refusal
    demonstrated on this composition. Never add an "is the provider revision in
    `alembic_version`?" check: that table holds the current head of each branch,
    not the history, so it is wrong against every advanced database.
11. **A secret is HELD, never dereferenced on a request path** (ADR-0009).
    `secret_loading.py` may do I/O and runs at startup and on an explicit
    refresh; `secret_resolver.py` is dict lookups and imports nothing that can
    reach a network, a filesystem, a subprocess or the ORM
    (`test_secrets_are_held.py`). Rotation is `POST /operations/secrets/refresh`,
    never a TTL. A failed refresh keeps the working set. A broken MECHANISM
    refuses the boot; one bad REFERENCE refuses only that installation's
    enablement. No degraded-start knob exists and none may be added.
12. **A reference is not a capability.** `env://` is confined to
    `SECRET_ENV_PREFIX` and `file://` to `SECRET_FILE_ROOT`, resolved before
    the containment check. References come from operator-written database rows;
    without confinement one could name this process's own credentials.
13. **No value is logged, serialised or persisted.** Names and references only
    — a reference is a pointer the module already stores in an immutable
    revision. There is no accessor that dumps held values, and the assembly
    refuses to COMMIT a connector diagnostic that contains material.
14. **Every route has a CLASS and every class has a rule** (`surface.py`).
    `/health` is unauthenticated and read-only, `/operations` carries
    `require_operator` on reads AND mutations plus a required `OperationReason`
    on every mutation, `/ingress` is provider-authenticated and must NEVER
    carry the operator guard. `mint`/`rotate`/`revoke`/`refresh` may appear only
    on an operator path. `create_app` refuses to return an incorrectly
    classified surface — it is a boot failure, not a test failure.
15. **Operator identity is the kernel's, adapted, never reimplemented.**
    `require_operator` calls `dotmac_kernel.platform_auth`'s own predicate with
    this assembly's session. Actor AND reason reach the audit row; the module's
    `actor_admin_id` default of `None` is correct for the module and wrong here.
    A timed sweep records no actor, in a separately named function, because a
    schedule is not a person.
16. **`integrator.*` is this assembly's audit vocabulary and `integration.*` is
    the module's.** Declared in `INTEGRATOR_AUDIT_ACTIONS`, enforced in both
    directions (`test_audit_actions_are_declared.py`). Never write the module's.
17. **The image is non-root, migrates nothing on boot, and carries no registry
    credential.** The migration job runs as the owner and must COMPLETE before
    any runtime container starts. Asserted against the built artefact by
    `scripts/audit_image.sh`, which carries its own sensitivity proof.
18. **A metric label is a closed vocabulary, and a log line carries no
    identifier.** Every `MetricFamily` in `telemetry.py` declares the complete
    set of label values it will ever accept — sourced from a database CHECK
    constraint, a dataclass's fields, or a closed tuple in that file — and
    `render` RAISES on anything else, as do the counter methods. An endpoint
    key, a `provider_event_id`, a phone number, message content or anything
    derived from a secret therefore has no code path to a label; the same rule
    applies to log lines (ADR-0009: names are logged, values never). A new
    labelled metric means declaring its values, not widening the check.
    Enforced by `tests/architecture/test_no_identifier_reaches_a_label.py`,
    driven with real-looking identifiers rather than placeholders.
19. **Thresholds live in `deploy/alerts/`, never in the process.** `/metrics`
    publishes facts. "How late is too late" is a deployment's decision, and a
    number in `telemetry.py` would fork from the rule that fires on it. The
    payload-retention period is the one threshold that is deliberately UNSET in
    both places: `dotmac_integration.retention` refuses to purge until it is
    configured, and the alert file fails closed and visible instead of guessing.
20. **`/metrics` authenticates, and unauthorized is 404.** `Authorization:
    Bearer $METRICS_TOKEN`, `secrets.compare_digest`, 404 rather than 403 (a
    403 is an oracle telling a prober the path exists). An unset token falls
    back to **loopback only, never to open**, and `validate_settings` makes it
    prod-fatal. The fleet's observability auth standard; the closed label
    vocabulary is a second line of defence, not a substitute.
21. **Validate before pushing**: `make check`. CI is the acceptance owner —
    local runs are not evidence.
