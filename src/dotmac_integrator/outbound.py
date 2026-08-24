"""Drive the module-owned outbound outbox without reimplementing it.

The selector here is only a hint.  The module's conditional claim is the
decision, and the three phase boundary stays exact:

``prepare + commit`` → ``invoke with no session`` → ``settle + commit``.

No connector, capability or provider appears in this file.  The registry is
entry-point discovery and secret resolution is an in-memory lookup supplied by
the assembly.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import Any
from uuid import UUID

import dotmac_integration as integration
import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from dotmac_integrator.secret_resolver import resolve_secrets

__all__ = [
    "DispatchResult",
    "dispatch_due_deliveries",
    "dispatch_one",
    "due_delivery_ids",
]


class DispatchResult(StrEnum):
    SETTLED = "settled"
    CONTENDED = "contended"
    MISSING = "missing"
    LOST = "lost"


SessionFactory = Callable[[], Any]
SecretResolver = Callable[[Mapping[str, str]], Mapping[str, str]]


def due_delivery_ids(engine: Engine, limit: int) -> tuple[UUID, ...]:
    """Return due candidate ids — a hint, never the claim.

    There is deliberately no row lock and no ``SKIP LOCKED``.  Every replica
    may see the same candidate; the module's one conditional UPDATE grants the
    lease to exactly one of them without holding a transaction across provider
    I/O.
    """

    delivery = integration.DeliveryAttempt
    now = sa.func.now()
    with Session(engine) as db:
        rows = db.execute(
            sa.select(delivery.id)
            .where(
                delivery.state.in_(("pending", "retryable")),
                sa.or_(
                    delivery.leased_until.is_(None),
                    delivery.leased_until < now,
                ),
                sa.or_(
                    delivery.next_attempt_at.is_(None),
                    delivery.next_attempt_at <= now,
                ),
            )
            .order_by(delivery.created_at, delivery.id)
            .limit(limit)
        ).all()
    return tuple(row[0] for row in rows)


def dispatch_one(
    delivery_id: UUID,
    *,
    session_factory: SessionFactory,
    registry: Any,
    resolve_secrets: SecretResolver = resolve_secrets,
) -> DispatchResult:
    """Drive one candidate through the module's three phases."""

    with session_factory() as db:
        delivery = db.get(integration.DeliveryAttempt, delivery_id)
        if delivery is None:
            return DispatchResult.MISSING
        prepared = integration.prepare(db, delivery, registry=registry)
        if prepared is None:
            return DispatchResult.CONTENDED
        # This closes the claim transaction BEFORE anything that can perform
        # provider I/O.  The value returned by prepare is detached data only.
        db.commit()

    outcome = integration.invoke(
        prepared,
        registry=registry,
        resolve_secrets=resolve_secrets,
    )

    with session_factory() as db:
        delivery = db.get(integration.DeliveryAttempt, delivery_id)
        if delivery is None:
            return DispatchResult.LOST
        try:
            integration.settle(
                db,
                delivery,
                outcome,
                prepared=prepared,
            )
        except integration.LostClaim:
            return DispatchResult.LOST
        db.commit()
    return DispatchResult.SETTLED


def dispatch_due_deliveries(
    engine: Engine,
    *,
    limit: int,
    registry: Any,
    resolve_secrets: SecretResolver = resolve_secrets,
) -> dict[str, int]:
    """One bounded pass; a preflight refusal cannot starve later commands."""

    identifiers = due_delivery_ids(engine, limit)
    counted = {
        "candidates": len(identifiers),
        "settled": 0,
        "contended": 0,
        "missing": 0,
        "lost": 0,
        "unavailable": 0,
    }
    for delivery_id in identifiers:
        try:
            result = dispatch_one(
                delivery_id,
                session_factory=lambda: Session(engine),
                registry=registry,
                resolve_secrets=resolve_secrets,
            )
        except integration.DispatchUnavailable:
            # A disabled/stale binding is persistent configuration failure, not
            # contention. Count it and continue so one bad command cannot starve
            # unrelated installations behind it; module health exposes the row.
            counted["unavailable"] += 1
            continue
        counted[result.value] += 1
    return counted
