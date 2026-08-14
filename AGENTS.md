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
5. **Migrations run as the owner at deploy time, never on boot.**
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
10. **Validate before pushing**: `make check`. CI is the acceptance owner —
    local runs are not evidence.
