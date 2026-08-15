"""The application. Pins, composes, configures, and exposes operations.

Read the route table and you have read the whole deployment: two probes, one
composition report, and thin adapters over operations the MODULE owns. Every
handler validates its input, delegates, and serialises the result. None of them
decides anything.

## What is deliberately absent

* **No connector logic.** A connector is a separately released distribution
  discovered through the `dotmac_integration.connectors` entry-point group. This
  assembly never imports one by name, and there is a test that says so.
* **No business decisions.** Retry policy, backoff, binding selection, activation
  and lifecycle transitions all live in `dotmac_integration`. An assembly that
  reimplemented any of them would become a second writer for a decision that
  already has an owner (ADR-0024).
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

from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from dotmac_integrator import health, operations, telemetry
from dotmac_integrator.settings import Settings, get_settings, validate_settings
from dotmac_integrator.worker import Worker


class ReplayRequest(BaseModel):
    """Why this replay is being performed. Recorded by the module, not by us."""

    reason: str = Field(min_length=1, max_length=500)


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

    problems = validate_settings(settings)
    if problems:
        # Refuse rather than start degraded. A production deployment running on
        # localhost defaults is a worse outcome than a failed boot, because it
        # looks healthy.
        raise RuntimeError(
            "refusing to start in production with unsafe configuration:\n  - "
            + "\n  - ".join(problems)
        )

    engine = build_engine(settings)
    worker = Worker(engine=engine, settings=settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
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

        @app.get(settings.metrics_path, tags=["health"], include_in_schema=False)
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

    @app.get("/operations/connectors", tags=["operations"])
    def connectors() -> dict[str, Any]:
        return operations.installed_connectors()

    @app.get("/operations/health-report", tags=["operations"])
    def health_report() -> dict[str, Any]:
        return operations.health_report(engine)

    @app.post("/operations/leases/release-expired", tags=["operations"])
    def release_expired() -> dict[str, Any]:
        return operations.release_expired_leases(engine)

    # `reason` is REQUIRED, not defaulted. The module demands one, and an
    # assembly that invented "replayed via API" would write a fabricated
    # justification into the audit record of a manual intervention — worse than
    # no record, because it reads as deliberate.
    @app.post("/operations/deliveries/{delivery_id}/replay", tags=["operations"])
    def replay_delivery(delivery_id: str, body: ReplayRequest) -> dict[str, Any]:
        return operations.replay_delivery(engine, delivery_id, body.reason)

    @app.post("/operations/receipts/{receipt_id}/replay", tags=["operations"])
    def replay_receipt(receipt_id: str, body: ReplayRequest) -> dict[str, Any]:
        return operations.replay_receipt(engine, receipt_id, body.reason)

    return app
