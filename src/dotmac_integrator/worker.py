"""Worker startup. Scheduling only — the work itself belongs to the module.

This file decides WHEN to call `release_expired_leases`, and nothing else. It
does not decide what expired, how long a lease lasts, how many attempts a
delivery gets, or what backoff applies. Those are `ExecutionPolicy`, and reading
them from settings here would fork the policy: the module would hold one answer
and the deployment another, for a question that already has an owner.

## Why lease sweeping is the only pump today

Sweeping expired leases is idempotent, needs no connector, and is safe to run
before any connector exists — a lease whose holder died must be reclaimed
whether or not anything can dispatch.

## What this pump deliberately does NOT do

It does not refresh secret material. ADR-0009 makes rotation an explicit
operator act, never a timer: material must change when someone says so, and a
process that re-read a store every N seconds would put that store back on the
path of everything it authenticates. `POST /operations/secrets/refresh` is the
whole rotation mechanism.

The dispatch pump is deliberately NOT here. It cannot be written honestly until
a real connector exists to dispatch to, and a pump written against no connector
would be shaped by guesses. It arrives with the Meta/WhatsApp ingress-only
distribution, which is also when shadow-mode behaviour has to be decided.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from sqlalchemy.engine import Engine

from dotmac_integrator import operations
from dotmac_integrator.settings import Settings

logger = logging.getLogger(__name__)


class Worker:
    """A single background sweep, started and stopped with the app.

    In-process rather than a separate scheduler because there is exactly one
    periodic task and it is idempotent. When the dispatch pump lands this should
    be reconsidered — several replicas each running a pump is fine (the claims
    are atomic), but it is a decision to make deliberately rather than inherit.
    """

    def __init__(self, engine: Engine, settings: Settings) -> None:
        self._engine = engine
        self._settings = settings
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        if not self._settings.worker_enabled:
            logger.info("worker disabled by configuration; API-only replica")
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="lease-sweep")
        logger.info(
            "worker started; lease sweep every %ss",
            self._settings.worker_lease_sweep_seconds,
        )

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stopping.set()
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None
        logger.info("worker stopped")

    async def _run(self) -> None:
        interval = self._settings.worker_lease_sweep_seconds
        while not self._stopping.is_set():
            try:
                await asyncio.to_thread(self._sweep_once)
            except Exception:
                # Log and keep the loop alive. A sweep failing because the
                # database blipped must not kill the only periodic task in the
                # process and leave leases held until the next deploy.
                logger.exception("lease sweep failed; continuing")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stopping.wait(), timeout=interval)

    def _sweep_once(self) -> None:
        # The TIMED variant, which records no actor: a schedule is not a
        # person, and an audit row naming one would be a lie about who decided.
        released = operations.sweep_expired_leases(self._engine)
        if released:
            logger.info("released %s expired lease(s)", released)
