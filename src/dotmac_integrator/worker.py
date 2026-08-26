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
would be shaped by guesses. It arrives with the first ingress-only connector
distribution.

## Which receipt pump runs is decided by the port, not by a second flag

Shadow-mode behaviour is now decided, and it is decided ONCE: the installed
client declares whether it writes, and this file starts the matching loop. A
non-writing client gets the shadow pass, which claims nothing and settles
nothing; a writing one gets the delivery pump. There is deliberately no separate
`SHADOW_MODE` knob that could disagree with the client's own direction — two
switches for one decision is how a deployment ends up shadow by configuration
and writing by client.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from sqlalchemy.engine import Engine

from dotmac_integrator import delivery, operations, telemetry
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
        self._delivery_task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()
        #: Unix time of the last COMPLETED sweep. `None` until one finishes —
        #: seeding it at construction would make a worker that has never run
        #: look freshly swept, which is the exact failure a stall alert exists
        #: to catch.
        self.last_sweep_epoch: float | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def delivering(self) -> bool:
        return self._delivery_task is not None and not self._delivery_task.done()

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
        if not delivery.product_port_installed():
            # Loud, and NOT a fallback. A deployment receiving provider events
            # with nowhere to deliver them is accumulating a backlog behind a
            # control plane that already answered 200 to the provider.
            logger.warning(
                "no product port installed; recorded receipts will NOT be "
                "delivered. Call delivery.install_product_port(...) at startup"
            )
            return
        writes = delivery.product_port_writes()
        self._delivery_task = asyncio.create_task(
            self._deliver_forever(),
            name="receipt-delivery" if writes else "receipt-mirror",
        )
        logger.info(
            "%s started; polling every %ss in batches of %s",
            "receipt delivery"
            if writes
            else (
                "SHADOW comparison — NOTHING is delivered and no receipt is " "settled"
            ),
            self._settings.worker_poll_seconds,
            self._settings.worker_batch_size,
        )

    async def stop(self) -> None:
        self._stopping.set()
        for name in ("_delivery_task", "_task"):
            task = getattr(self, name)
            if task is None:
                continue
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            setattr(self, name, None)
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
                #
                # Counted as well as logged, because surviving is exactly what
                # makes this invisible: the loop keeps running, the process
                # stays healthy, and `last_sweep_epoch` stops advancing. The
                # counter and the stall alert are the two halves of noticing.
                telemetry.counters.record_sweep_failure()
                logger.exception("lease sweep failed; continuing")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stopping.wait(), timeout=interval)

    async def _deliver_forever(self) -> None:
        interval = self._settings.worker_poll_seconds
        while not self._stopping.is_set():
            try:
                await asyncio.to_thread(self._deliver_once)
            except Exception:
                # Survive, count, and keep polling — same reasoning as the
                # sweep. A product being unreachable is not a reason to stop
                # the only thing that will notice when it comes back.
                telemetry.counters.record_sweep_failure()
                logger.exception("receipt delivery pass failed; continuing")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stopping.wait(), timeout=interval)

    def _deliver_once(self) -> None:
        if not delivery.product_port_writes():
            # The SHADOW pass. Separate function, separate log line, and no
            # branch inside `deliver_due_receipts` — a flag threaded into the
            # delivery pump is one edit away from a shadow run that settles.
            compared = delivery.mirror_due_receipts(
                self._engine,
                self._settings.worker_batch_size,
                comparison_revision=self._settings.product_port_shadow_revision,
                retry_after_seconds=(self._settings.product_port_shadow_retry_seconds),
            )
            if compared["compared"] or compared["unreadable"]:
                # Verdict COUNTS. A per-receipt verdict names the provider's
                # event identity, which belongs on an operator's screen.
                logger.info("shadow comparison: %s", sorted(compared.items()))
            return
        counted = delivery.deliver_due_receipts(
            self._engine, self._settings.worker_batch_size
        )
        if counted["claimed"] or counted["lost"]:
            # COUNTS. Not the receipt ids, not the destination, not the
            # idempotency key — the per-receipt outcome is on the row and in
            # the audit ledger, both of which are access-controlled in a way a
            # log line is not.
            logger.info(
                "delivered %s receipt(s); %s lost claim(s)",
                counted["claimed"],
                counted["lost"],
            )

    def _sweep_once(self) -> None:
        # The TIMED variant, which records no actor: a schedule is not a
        # person, and an audit row naming one would be a lie about who decided.
        released = operations.sweep_expired_leases(self._engine)
        # Stamped AFTER the sweep returns, never before. A timestamp written on
        # entry would keep advancing while every sweep failed, and the stall
        # alert would report a healthy worker doing nothing.
        self.last_sweep_epoch = telemetry.now_epoch()
        if released:
            # A COUNT. Not the delivery ids, not the installation, not the
            # idempotency key — a log line is read by more people and kept in
            # more places than the row it describes.
            logger.info("released %s expired lease(s)", released)
