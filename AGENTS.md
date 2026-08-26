# dotmac_integrator — hard rules

This is a **thin assembly**. The reusable behaviour lives in
`dotmac-integration`, a published wheel. See `README.md` for the shape and
`docs` in the Starter for ADR-0023 (dual-plane) and ADR-0024 (app independence).

1. **No provider logic and no business decisions.** Retry, backoff, lease
   duration, attempt limits, lifecycle transitions, binding selection and
   activation belong to `dotmac_integration`. Enforced by
   `tests/architecture/test_the_assembly_stays_thin.py`.
2. **Generic assembly source names no connector.** The deployment manifest
   exactly pins separately released connector distributions; entry-point
   discovery is the only runtime registration. Nothing under `src/` imports a
   connector, enumerates providers or branches on one.
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
    demonstrated on this composition. Bind what a composed manifest REQUIRES and
    nothing else — a binding nothing resolves can never fail at `alembic
    upgrade`, so it is decoration CI must maintain; re-bind a retired effect
    beside the module that needs it. Never add an "is the provider revision in
    `alembic_version`?" check: that table holds the current head of each branch,
    not the history, so it is wrong against every advanced database.
    Re-derive the bindings at every pin bump; a release that changes `requires`
    changes what this assembly must assert about it, so the bump is never one
    line.
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
21. **An inbound body is bounded AS IT IS READ, before buffering and before
    any signature.** `ingress.read_capped_body` consumes `request.stream()` and
    refuses on byte `limit + 1`; `await request.body()` is forbidden on that
    path by `test_the_assembly_stays_thin.py`. Measuring after buffering makes
    the limit an amplifier for the denial of service it exists to prevent, and
    an HMAC covers the whole body — verifying first means buffering first, so a
    10 GB body from an unauthenticated sender would be held in memory to
    discover it was not signed. `Content-Length` is absent under chunked
    encoding and attacker-supplied when present: a hint, never the control.
22. **The ingress endpoint key is a BEARER credential in the URL PATH, and it
    reaches no log, body or label.** The module guards everything it can see and
    cannot see the URL, so `redaction.py` owns this: a filter on the LOGGERS
    (not the handlers — this application does not own those) collapsing `msg`
    and `args` together, the route `del`ing the raw string so no frame local
    survives for a locals-capturing error reporter, an unvalidated `str` path
    parameter so no 422 echoes it, and the closed label vocabulary. Every
    surface carries a SENSITIVITY PROOF that the same value DOES appear when
    the redaction is removed — a `not in` assertion passes trivially if the
    value never had a route there.
23. **Handshake and delivery never share an eligibility predicate.** `GET
    /ingress/{key}` answers for a CONFIGURED but still DISABLED binding; `POST`
    requires binding and installation both enabled. One predicate makes
    activation CIRCULAR for every provider that requires a completed handshake
    before a subscription can be enabled — the endpoint refuses the one request
    that would unblock it, forever. Two routes, two engine façades, no flag.
    This relaxes WHICH BINDING may be addressed, never WHAT THE REQUEST MUST
    PROVE: the connector's `challenge` still runs and still verifies.
24. **At-most-once belongs to the module, and the selector is a HINT.**
    `ReceiptClaims` (conditional UPDATE, `rowcount == 1` IS the claim) and
    `deliver_receipt` (claim → call with NO session held → settle) are
    `dotmac_integration`'s. `delivery.due_receipt_ids` is an unlocked SELECT and
    two workers seeing one id is the expected case: the database evaluates the
    real predicate inside the UPDATE and the loser gets `None`. No `FOR
    UPDATE`, no `SKIP LOCKED`, no hand-written state UPDATE — a lock taken here
    would be held across the product call. Enforced by
    `test_the_assembly_stays_thin.py`, with a sensitivity proof. The product
    port is INSTALLED at startup (ADR-0009 shape) and the pump fails closed
    without one; it never marks a receipt done that it did not deliver.
25. **The destination's wire contract is IMPLEMENTED here, never authored
    here.** `product_port.py` is transcribed from the destination
    application's own merged port (`dotmac_sub`'s
    `app/api/integrator_observations.py` and
    `app/schemas/integrator_observation.py`); a disagreement is a defect in
    this file, or a contract change that happens in THAT repository first.
    Three consequences that are easy to get wrong and expensive to discover:
    `provider_event_id` crosses the wire RAW because the destination
    namespaces it itself; the transport fingerprint covers the destination's
    OWN canonical body — every declared field present, optionals explicitly
    null — not the sparse dict a connector supplied; and a 409 identity
    collision ESCALATES (`INDETERMINATE`) rather than reporting
    `already_applied`, because the owning service is saying two producers
    disagree about what the provider said.
26. **A product port declares its DIRECTION, and shadow never settles.** The
    destination exposes a write port and a strictly narrower shadow port that
    records nothing; the narrowness is the safety property and this side
    honours it. `install_product_port` requires a boolean `writes` — required,
    never defaulted, because neither default is safe — a `MIRROR` client's
    `deliver` raises, `deliver_due_receipts` refuses a non-writing port, and
    `mirror_due_receipts` is what a shadow deployment runs: it claims nothing,
    settles nothing, returns verdict COUNTS, and appends privacy-safe evidence
    to the platform audit trail under one immutable
    `PRODUCT_PORT_SHADOW_REVISION`. Terminal evidence is not repeated in that
    revision; transient findings are sampled after the configured evidence
    interval, and a new revision re-drives the population. The aggregate report
    may say only that its non-empty sample has no blockers — it is never the
    full cutover decision. A shadow run that marked receipts `processed` would
    look exactly like a completed cutover while losing every event. One switch
    (`PRODUCT_PORT_MODE`), read once, by the client; the worker starts the
    matching loop from the client's own declaration rather than from a second
    flag.
27. **The destination-side binding id and the capability declaration are
    CONFIGURED, never derived.** The destination's port is keyed on ITS
    capability-binding UUID, in ITS database; this deployment's is a different
    UUID and no derivation exists. Both the pairing
    (`PRODUCT_PORT_BINDINGS`) and the capability vocabulary
    (`PRODUCT_PORT_CAPABILITIES`) are operator-supplied, both fail LOUD when
    absent — a refused boot, or a pre-network `UNAVAILABLE` naming the gap —
    and both are stopgaps whose provenance is an open decision recorded in the
    destination's cutover document. The Integrator may never mint a capability
    declaration.
28. **The destination credential reaches no log, no traceback and no metric
    label.** Held at startup like any other material (rule 11), resolved per
    call as a dict lookup so a rotation takes effect without a restart, and
    never interpolated into a message. Every outbound string goes through
    `secret_resolver.redact`, because the destination's refusal text is
    third-party content; the frames that hold the value `del` it in a
    `finally`, so an error reporter capturing frame locals finds nothing. All
    three carry sensitivity proofs
    (`test_the_destination_credential_never_escapes.py`).
29. **Validate before pushing**: `make check`. CI is the acceptance owner —
    local runs are not evidence.
30. **Poetry is an exact build input, not an ambient tool.**
    `[tool.poetry].requires-poetry` is the ONE version source; CI's hash-locked
    bootstrap, the lockfile generator stamp and the production Docker build
    equal it exactly. `make poetry-lock-check` fails before dependency work if
    the active Poetry differs, then validates the COMMITTED lock with
    `poetry check --lock`. A validation lane never runs `poetry lock`, because
    that proves repaired state rather than the commit. Ordinary dependency
    edits use `poetry lock` with the pinned tool; `--regenerate` is reserved for
    an explicit toolchain/dependency-resolution upgrade.
    (`scripts/check_poetry_toolchain.py`;
    `tests/architecture/test_poetry_toolchain_contract.py`)
