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
10. **A metric label is a closed vocabulary, and a log line carries no
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
11. **Thresholds live in `deploy/alerts/`, never in the process.** `/metrics`
    publishes facts. "How late is too late" is a deployment's decision, and a
    number in `telemetry.py` would fork from the rule that fires on it. The
    payload-retention period is the one threshold that is deliberately UNSET in
    both places: `dotmac_integration.retention` refuses to purge until it is
    configured, and the alert file fails closed and visible instead of guessing.
12. **Validate before pushing**: `make check`. CI is the acceptance owner —
    local runs are not evidence.
