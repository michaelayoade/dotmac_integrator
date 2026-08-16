"""The application. Pins, composes, configures, and exposes operations.

Read the route table and you have read the whole deployment: two probes, one
composition report, and thin adapters over operations the MODULE owns. Every
handler validates its input, delegates, and serialises the result. None of them
decides anything.

## Three things happen at construction, and none of them is business logic

1. `validate_settings` — refuse to start on unsafe production configuration.
2. `require_a_correct_surface` — refuse to start on an unguarded or
   unclassified route (`surface.py`). Enforced here rather than only in a test,
   because a test proves the routes the test knows about and this proves the
   ones that are actually mounted.
3. At lifespan startup, `install_secrets` — load every referenced secret into
   memory before serving. ADR-0009: held, never fetched. A failure here is a
   failed boot, deliberately, because a process serving with no material looks
   healthy and refuses every enablement.

## What is deliberately absent

* **No connector logic.** A connector is a separately released distribution
  discovered through the `dotmac_integration.connectors` entry-point group. This
  assembly never imports one by name, and there is a test that says so.
* **No business decisions.** Retry policy, backoff, binding selection, activation
  and lifecycle transitions all live in `dotmac_integration`. An assembly that
  reimplemented any of them would become a second writer for a decision that
  already has an owner (ADR-0024).
* **No connector-specific ingress behaviour.** `/ingress/{endpoint_key}` is
  mounted (`surface.RouteClass.INGRESS`) and is two calls into the module's
  three-phase engine. This assembly supplies only what the engine correctly
  refuses to own: the unit of work, the secret resolver, and a GENERIC body cap.
  It authenticates nothing itself — the provider's signature scheme lives in the
  connector that knows it — and it must never carry the operator guard.
* **No installation authoring.** There is no route that drafts an installation
  or writes a configuration revision. A draft pins the connector installed at
  that moment, so the first of those routes belongs with the first connector,
  not before it.
* **No tenant surface.** Every table here is platform-plane. There is no tenant
  context, no RLS, and no `app_user`.
* **No migrations on boot.** `alembic upgrade` is a deploy step run as the owner
  role. `create_app` never touches DDL.
* **No alert thresholds.** `/metrics` publishes facts; "how late is too late"
  is a deployment's decision and lives in `deploy/alerts/`. A threshold encoded
  here would fork the policy between the process and the rule that fires on it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import dotmac_integration as integration
from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from dotmac_integrator import (
    delivery,
    health,
    ingress,
    operations,
    product_port,
    secret_loading,
    telemetry,
)
from dotmac_integrator.operator_auth import OperationReason, Operator
from dotmac_integrator.redaction import install_log_redaction
from dotmac_integrator.settings import Settings, get_settings, validate_settings
from dotmac_integrator.surface import require_a_correct_surface
from dotmac_integrator.worker import Worker


def build_engine(settings: Settings) -> Engine:
    """The ONLINE engine, on the platform role.

    `pool_pre_ping` because this process holds long-lived connections while
    waiting on provider I/O, and a connection killed by a proxy timeout should
    surface as a reconnect rather than as a failed dispatch.
    """
    return create_engine(
        settings.database_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_pool_max_overflow,
        pool_pre_ping=True,
        future=True,
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    # BEFORE anything can log. The ingress endpoint key is a bearer credential
    # carried in the URL PATH, and the access log is the surface the engine's
    # own careful redaction cannot reach — it never sees the URL. See
    # `redaction.py`.
    install_log_redaction()

    problems = validate_settings(settings)
    if problems:
        # Refuse rather than start degraded. A production deployment running on
        # localhost defaults is a worse outcome than a failed boot, because it
        # looks healthy.
        raise RuntimeError(
            "refusing to start with unsafe configuration:\n  - "
            + "\n  - ".join(problems)
        )

    engine = build_engine(settings)
    worker = Worker(engine=engine, settings=settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # BEFORE the worker and before the first request. Everything this
        # deployment can authenticate with is in memory from this line onward,
        # so no store outage can reach a dispatch or an enablement.
        report = secret_loading.install_secrets(engine, settings)
        if settings.product_port_enabled:
            # Installed BEFORE the worker starts, so the pump never observes a
            # half-composed deployment — and AFTER the material is held, so an
            # unresolvable destination credential refuses the boot here rather
            # than failing every delivery later with a 401 that reads as the
            # destination's problem.
            client, registry = product_port.build_from_settings(
                settings, held_references=report.held
            )
            delivery.install_product_port(client, registry=registry)
        await worker.start()
        try:
            yield
        finally:
            # Ordered: stop claiming new work, then release what is held, then
            # drop the pool. Disposing first would strand leases held by a
            # dispatch still settling.
            await worker.stop()
            engine.dispose()

    app = FastAPI(
        title="Dotmac Integrator",
        summary="Connector control plane",
        lifespan=lifespan,
    )
    app.state.engine = engine
    app.state.settings = settings
    app.state.worker = worker

    # ── Probes ──────────────────────────────────────────────────────────────
    # Unauthenticated by class (`surface.RouteClass.PROBE`). An orchestrator
    # cannot present a credential, and a probe that fails closed on an auth
    # outage restarts healthy replicas.

    @app.get("/health/live", tags=["health"])
    def live() -> dict[str, Any]:
        return health.liveness()

    @app.get("/health/ready", tags=["health"])
    def ready() -> JSONResponse:
        ok, detail = health.readiness(engine)
        return JSONResponse(detail, status_code=200 if ok else 503)

    @app.get("/health/composition", tags=["health"])
    def composed() -> dict[str, str]:
        return health.composition()

    # ── Metrics ─────────────────────────────────────────────────────────────
    # An adapter like every other handler: collect, render, return. The label
    # vocabulary and the refusal that enforces it live in `telemetry.py`, and
    # nothing here can widen them.
    if settings.metrics_enabled:
        # A DEPENDENCY, not a check in the handler body. `surface.audit_routes`
        # identifies guards by walking a route's dependency tree, so an
        # authentication check written inside `metrics()` would be invisible to
        # it — and a later `/metrics` mounted with no check at all would audit
        # clean. It answers 404 rather than 403: a 403 is an oracle telling a
        # prober the endpoint exists (fleet observability standard).
        scrape_guard = telemetry.ScrapeGuard(settings)

        @app.get(
            settings.metrics_path,
            tags=["health"],
            include_in_schema=False,
            dependencies=[Depends(scrape_guard)],
        )
        def metrics() -> PlainTextResponse:
            return PlainTextResponse(
                telemetry.scrape(engine, worker),
                # The exposition format's own content type, version included.
                # Prometheus falls back to a text parse without it, but an
                # OpenMetrics-aware scraper will not.
                media_type="text/plain; version=0.0.4; charset=utf-8",
            )

    # ── Operational controls ────────────────────────────────────────────────
    # Each of these is a thin adapter: validate, delegate, serialise. The verbs
    # belong to `dotmac_integration`.
    #
    # Every one carries `require_operator`, reads included: the connector
    # inventory and the health report together describe which integrations this
    # fleet runs and which are unattended.
    #
    # Every MUTATION additionally carries a required `reason`. It is never
    # defaulted — an assembly that invented "replayed via API" would write a
    # fabricated justification into the audit record of a manual intervention,
    # which is worse than no record because it reads as deliberate.

    @app.get("/operations/connectors", tags=["operations"])
    def connectors(
        _actor: Operator,
    ) -> dict[str, Any]:
        return operations.installed_connectors()

    @app.get("/operations/health-report", tags=["operations"])
    def health_report(
        _actor: Operator,
    ) -> dict[str, Any]:
        return operations.health_report(engine)

    @app.get("/operations/secrets", tags=["operations"])
    def secrets_held(
        _actor: Operator,
    ) -> dict[str, Any]:
        """Which references resolved, and why the others did not. NAMES ONLY.

        Deliberately the closest thing to a secret accessor in this deployment:
        an operator diagnosing a refused enablement needs to know whether a
        reference resolved and never needs to know what it resolved to.
        """
        return operations.secret_status()

    @app.post("/operations/secrets/refresh", tags=["operations"])
    def secrets_refresh(
        body: OperationReason,
        actor: Operator,
    ) -> dict[str, Any]:
        """Rotation. Explicit, never a TTL (ADR-0009)."""
        return operations.refresh_secret_material(engine, actor, body.reason)

    @app.post("/operations/installations/{installation_id}/enable", tags=["operations"])
    def enable_installation(
        installation_id: str,
        body: OperationReason,
        actor: Operator,
    ) -> dict[str, Any]:
        """Gated on held material AND on the connector's live connection check."""
        return operations.enable_installation(
            engine, installation_id, actor, body.reason
        )

    @app.post("/operations/leases/release-expired", tags=["operations"])
    def release_expired(
        body: OperationReason,
        actor: Operator,
    ) -> dict[str, Any]:
        return operations.release_expired_leases(engine, actor, body.reason)

    @app.post("/operations/deliveries/{delivery_id}/replay", tags=["operations"])
    def replay_delivery(
        delivery_id: str,
        body: OperationReason,
        actor: Operator,
    ) -> dict[str, Any]:
        return operations.replay_delivery(engine, delivery_id, actor, body.reason)

    @app.post("/operations/receipts/{receipt_id}/replay", tags=["operations"])
    def replay_receipt(
        receipt_id: str,
        body: OperationReason,
        actor: Operator,
    ) -> dict[str, Any]:
        return operations.replay_receipt(engine, receipt_id, actor, body.reason)

    # ── Public ingress ──────────────────────────────────────────────────────
    # A PROVIDER calling in (`surface.RouteClass.INGRESS`). Authenticated by
    # that provider's own signature scheme, inside the connector that knows it,
    # and NEVER by the operator guard — the two populations share no
    # credential, no token audience and no failure mode.
    #
    # Two routes, two engine façades, two eligibility rules. GET is the
    # activation handshake and answers for a CONFIGURED but still DISABLED
    # binding; POST is delivery and requires the binding and its installation
    # both enabled. They are separate calls on purpose: one function with a
    # flag is one edit away from being one predicate, and one predicate makes
    # activation circular for every provider that requires a completed
    # handshake before a subscription can be enabled. See `ingress.py`.
    if settings.ingress_enabled:

        def _answer(outcome: Any) -> Response:
            """Write the engine's decision. No status is invented here.

            `outcome.status_code` is a retry instruction to the provider, and
            only the engine knows whether the batch committed. A refusal body
            carries the engine's classification and NOTHING else — not the
            installation id, not the binding id, not the endpoint key: those are
            operator-meaningful and the reader here is a third party.
            """
            acknowledgement = outcome.acknowledgement
            if acknowledgement is None:
                return JSONResponse(
                    {"code": outcome.code.value}, status_code=outcome.status_code
                )
            return Response(
                content=acknowledgement.body,
                status_code=outcome.status_code,
                media_type=acknowledgement.media_type,
            )

        # `endpoint_key` is an UNVALIDATED `str` on purpose. A constrained path
        # parameter would let FastAPI answer 422 with the rejected value echoed
        # into `detail.input` — the credential, in a response body and in the
        # log line that response produces. The engine already treats a malformed
        # key and an unknown one as the same `EndpointUnknown`, deliberately, so
        # that the endpoint is not a probing oracle for the right SHAPE.

        @app.get("/ingress/{endpoint_key}", tags=["ingress"], include_in_schema=False)
        async def ingress_handshake(endpoint_key: str, request: Request) -> Response:
            endpoint = integration.EndpointAddress(endpoint_key)
            # The raw string stops HERE. `EndpointAddress` is `repr`-less, so
            # the credential no longer renders; but the parameter itself is a
            # frame local that every traceback through this handler pins, and an
            # error reporter configured to capture locals uploads frame locals
            # verbatim. Deleting the binding is what makes that impossible
            # rather than unlikely — the module makes the same move for the same
            # reason, and it cannot make it for the one frame it does not own.
            del endpoint_key
            try:
                body = await ingress.read_capped_body(
                    request.stream(), settings.ingress_max_body_bytes
                )
            except ingress.BodyTooLarge:
                outcome = integration.refusal_outcome(integration.PayloadTooLarge())
                telemetry.counters.record_ingress_outcome(outcome.code.value)
                telemetry.counters.record_challenge("refused")
                return _answer(outcome)
            return _answer(
                ingress.answer_handshake(
                    engine,
                    endpoint=endpoint,
                    request=ingress.build_request(
                        raw_body=body,
                        headers=dict(request.headers),
                        params=dict(request.query_params),
                    ),
                )
            )

        @app.post("/ingress/{endpoint_key}", tags=["ingress"], include_in_schema=False)
        async def ingress_delivery(endpoint_key: str, request: Request) -> Response:
            endpoint = integration.EndpointAddress(endpoint_key)
            del endpoint_key
            try:
                # BEFORE the endpoint is looked up and before any signature is
                # computed. An HMAC covers the whole body, so verifying first
                # means buffering first — a 10 GB body from an unauthenticated
                # sender would be held in memory to discover it was not signed.
                body = await ingress.read_capped_body(
                    request.stream(), settings.ingress_max_body_bytes
                )
            except ingress.BodyTooLarge:
                # The module's own refusal, handed to the module's own
                # `refusal_outcome`. This assembly never writes `413`: an
                # ingress status is a retry instruction, and inventing one is
                # the one mistake here that silently destroys events.
                outcome = integration.refusal_outcome(integration.PayloadTooLarge())
                telemetry.counters.record_ingress_outcome(outcome.code.value)
                return _answer(outcome)
            return _answer(
                ingress.receive_delivery(
                    engine,
                    endpoint=endpoint,
                    request=ingress.build_request(
                        raw_body=body,
                        headers=dict(request.headers),
                        params=dict(request.query_params),
                    ),
                )
            )

    require_a_correct_surface(app, metrics_path=settings.metrics_path)
    return app
