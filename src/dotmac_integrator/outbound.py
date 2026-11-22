"""Outbound dispatch: product intake, the pump, crash recovery and redaction.

The module owns every decision here. `enqueue_delivery` owns de-duplication on
the idempotency key, `prepare` / `invoke` / `settle` own the claim, the call and
the claim-guarded write, `retry`/`policy` own the outcome-to-state table and
`retention` owns what may be redacted. This file supplies cadence, the unit of
work, the secret resolver and the HTTP-shaped answer.

## AMBIGUOUS is terminal, and a crash is ambiguous

A connector that cannot tell whether the effect landed returns
`RECONCILIATION_REQUIRED`; the module records `reconciliation_required`, which
`claim_delivery` never claims again. That is the whole of "no auto-retry" for a
reported ambiguity.

A process killed between the claim and the settle reports nothing, and the
module's generic `release_expired_leases` would turn that stranded `in_flight`
row into `retryable` (this assembly never calls it; see `operations`): the
next pass would send it again, and a mail that may
already have been accepted by the provider would go out twice. So the stranded
row is handled FIRST, by `mark_stranded_ambiguous`, which records the module's
own `RECONCILIATION_REQUIRED` outcome through the module's
`record_delivery_outcome`. The claim precedes the call and nothing here can tell
where in the call the process died, so any expired outbound lease is ambiguous.

Requeue of an ambiguous delivery is a deliberate act with an explicit
acknowledgement (`requeue_ambiguous.py`), never a route and never a timer.

## Lease against the connector's DATA budget

The lease duration is the module's (`DEFAULT_POLICY.lease_seconds`); it is read,
not set, here. `lease_exceeds_budget` is the boot check that it outlasts the
connector's real wall-clock deadline plus a margin (`OUTBOUND_DATA_BUDGET_SECONDS`
and `OUTBOUND_LEASE_MARGIN_SECONDS`), so a slow, healthy send cannot lose its
claim to a second worker. The SMTP connector's `SEND_DEADLINE_SECONDS` is 240 and
an uninterruptible TLS handshake makes the real worst case about 255 s; the
connector publishes no manifest field for it, so the pump carries it as a
setting.

## Payload redaction

`redact_expired_payloads` runs the module's `purge_expired_delivery_payloads`
under a `RetentionPolicy` built from settings. The module redacts only
`delivered` rows by design: a dead-lettered or ambiguous delivery is still
replayable, so its payload is unresolved content to the module.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

import dotmac_integration as integration
from dotmac_kernel.audit import write_platform_audit_event
from fastapi import HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from dotmac_integrator.product_auth import ProductPrincipal
from dotmac_integrator.secret_resolver import resolve_secrets
from dotmac_integrator.settings import Settings

logger = logging.getLogger(__name__)

__all__ = [
    "DispatchBody",
    "deliver_due_outbound",
    "drive_one",
    "enqueue_dispatch",
    "submit_dispatch_async",
    "lease_exceeds_budget",
    "mark_stranded_ambiguous",
    "redact_expired_payloads",
    "submit_dispatch",
]

_QUEUED = ("pending", "retryable")
_TERMINAL = ("delivered", "dead_letter", "reconciliation_required")

#: What the product is told. The module's names stay internal; `ambiguous` is the
#: one the product must treat as "possibly sent, do not resend".
PUBLIC_STATE: dict[str, str] = {
    "pending": "pending",
    "retryable": "pending",
    "in_flight": "in_flight",
    "delivered": "delivered",
    "dead_letter": "failed",
    "reconciliation_required": "ambiguous",
}

_Key = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)
]
_EventType = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=160)
]


class DispatchBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: The idempotency key. The product's own dispatch id, reused on every retry.
    dispatch_id: _Key
    capability_binding_id: UUID
    event_type: _EventType
    payload: dict[str, object] = Field(default_factory=dict)


def lease_exceeds_budget(
    lease_seconds: int, data_budget_seconds: int, margin_seconds: int = 0
) -> bool:
    """True when the lease outlasts the connector's deadline plus the margin."""
    return lease_seconds > data_budget_seconds + margin_seconds


# ── Intake ──────────────────────────────────────────────────────────────────


def _view(delivery: Any, *, dispatch_id: str, is_new: bool) -> dict[str, Any]:
    return {
        "dispatch_id": dispatch_id,
        "state": PUBLIC_STATE.get(delivery.state, delivery.state),
        "terminal": delivery.state in _TERMINAL,
        "attempts": delivery.attempt_count,
        "error_code": delivery.error_code,
        "accepted_now": is_new,
    }


@dataclass(frozen=True, slots=True)
class Enqueued:
    delivery_id: UUID
    dispatch_id: str
    is_new: bool
    view: dict[str, Any]


def enqueue_dispatch(
    engine: Engine,
    principal: ProductPrincipal,
    body: DispatchBody,
    *,
    capabilities: Any = None,
    cap_per_hour: int = 0,
    max_payload_bytes: int = 0,
) -> Enqueued:
    """Queue (or find) the delivery for `dispatch_id`. No waiting here.

    Idempotent through the module's `enqueue_delivery`: the same key with the
    same content returns the existing row (one send, whatever the retries); the
    same key with different content is a 409. The per-binding hourly cap is
    checked only for a key that is not already queued, so a retry of an accepted
    dispatch is never refused by it.
    """
    if body.capability_binding_id not in principal.binding_ids:
        raise HTTPException(403, "dispatch not authorized for this binding")
    if (
        max_payload_bytes
        and len(json.dumps(body.payload, separators=(",", ":"), default=str))
        > max_payload_bytes
    ):
        raise HTTPException(413, "payload too large")
    declared = capabilities if capabilities is not None else _capabilities()
    with Session(engine) as db:
        binding = db.get(integration.CapabilityBinding, body.capability_binding_id)
        if binding is None:
            raise HTTPException(404, "binding not found")
        if cap_per_hour > 0 and not _already_queued(
            db, binding.installation_id, body.dispatch_id
        ):
            since = datetime.now(UTC) - timedelta(hours=1)
            recent = db.execute(
                select(func.count())
                .select_from(integration.DeliveryAttempt)
                .where(
                    integration.DeliveryAttempt.capability_binding_id == binding.id,
                    integration.DeliveryAttempt.created_at >= since,
                )
            ).scalar_one()
            if int(recent) >= cap_per_hour:
                raise HTTPException(429, "per-binding hourly send cap reached")
        try:
            delivery, is_new = integration.enqueue_delivery(
                db,
                installation_id=binding.installation_id,
                event_type=body.event_type,
                idempotency_key=body.dispatch_id,
                payload=body.payload,
                capability_binding_id=binding.id,
                registry=declared,
            )
            db.commit()
        except integration.DeliveryIdempotencyConflict:
            db.rollback()
            raise HTTPException(
                409, "dispatch_id already names a different command"
            ) from None
        except integration.DeliveryEnqueueRaced:
            db.rollback()
            raise HTTPException(
                503, "concurrent enqueue; retry the same dispatch"
            ) from None
        except integration.CapabilityPayloadRejected:
            db.rollback()
            raise HTTPException(
                422, "payload rejected by the capability contract"
            ) from None
        return Enqueued(
            delivery.id,
            body.dispatch_id,
            is_new,
            _view(delivery, dispatch_id=body.dispatch_id, is_new=is_new),
        )


def _already_queued(db: Session, installation_id: UUID, key: str) -> bool:
    return (
        db.execute(
            select(integration.DeliveryAttempt.id).where(
                integration.DeliveryAttempt.installation_id == installation_id,
                integration.DeliveryAttempt.idempotency_key == key.strip(),
            )
        ).first()
        is not None
    )


def current_view(engine: Engine, queued: Enqueued) -> dict[str, Any]:
    with Session(engine) as db:
        row = db.get(integration.DeliveryAttempt, queued.delivery_id)
        if row is None:  # pragma: no cover - the row was just written
            return queued.view
        db.refresh(row)
        return _view(row, dispatch_id=queued.dispatch_id, is_new=queued.is_new)


def submit_dispatch(
    engine: Engine,
    principal: ProductPrincipal,
    body: DispatchBody,
    *,
    wait_seconds: float,
    capabilities: Any = None,
    cap_per_hour: int = 0,
    max_payload_bytes: int = 0,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Synchronous enqueue-and-wait, for callers that are not the event loop."""
    queued = enqueue_dispatch(
        engine,
        principal,
        body,
        capabilities=capabilities,
        cap_per_hour=cap_per_hour,
        max_payload_bytes=max_payload_bytes,
    )
    deadline = time.monotonic() + max(0.0, wait_seconds)
    current = queued.view
    while not current["terminal"] and time.monotonic() < deadline:
        sleep(0.25)
        current = current_view(engine, queued)
    return current


async def submit_dispatch_async(
    engine: Engine,
    principal: ProductPrincipal,
    body: DispatchBody,
    *,
    wait_seconds: float,
    waiters: asyncio.Semaphore,
    cap_per_hour: int = 0,
    max_payload_bytes: int = 0,
) -> dict[str, Any]:
    """The route's path. The 20 s wait is `await asyncio.sleep`, holding no
    thread, so a flood of waiting dispatches cannot exhaust the pool that serves
    `/operations/**` (the kill switch). Waiters are also capped: past the cap the
    caller gets the current state at once (202) and re-posts the same key.
    """
    queued = await run_in_threadpool(
        enqueue_dispatch,
        engine,
        principal,
        body,
        cap_per_hour=cap_per_hour,
        max_payload_bytes=max_payload_bytes,
    )
    current = queued.view
    if current["terminal"] or waiters.locked():
        return current
    async with waiters:
        deadline = time.monotonic() + max(0.0, wait_seconds)
        while not current["terminal"] and time.monotonic() < deadline:
            await asyncio.sleep(0.25)
            current = await run_in_threadpool(current_view, engine, queued)
    return current


def _capabilities() -> Any:
    try:
        return integration.capability_registry()
    except Exception:
        raise HTTPException(503, "capability registry not installed") from None


# ── Pump ────────────────────────────────────────────────────────────────────


def select_due(engine: Engine, limit: int) -> list[UUID]:
    """Queued ids, WITHOUT a lock: a hint only (hard rule 24). It never selects
    `in_flight`, so an expired lease is never re-driven from here.

    Only rows whose binding AND installation are `enabled` are selected. A
    disabled binding, or a disabled or quarantined installation, is refused by
    `prepare` and the refusal leaves the row untouched, so were it selected the
    earliest-due refused rows would fill every batch and starve every other
    binding (MED-1). Leaving them out costs nothing: the row keeps its
    `next_attempt_at`, so after re-enable it is due immediately, in its original
    order, and is delivered once. Intake is not gated, so the backlog still
    accrues while disabled (B14)."""
    now = datetime.now(UTC)
    binding = integration.CapabilityBinding
    installation = integration.ConnectorInstallation
    with Session(engine) as db:
        return list(
            db.execute(
                select(integration.DeliveryAttempt.id)
                .join(
                    binding,
                    binding.id == integration.DeliveryAttempt.capability_binding_id,
                )
                .join(installation, installation.id == binding.installation_id)
                .where(
                    binding.state == "enabled",
                    installation.state == "enabled",
                    integration.DeliveryAttempt.state.in_(_QUEUED),
                    integration.DeliveryAttempt.capability_binding_id.is_not(None),
                    integration.DeliveryAttempt.next_attempt_at <= now,
                )
                .order_by(integration.DeliveryAttempt.next_attempt_at)
                .limit(limit)
            )
            .scalars()
            .all()
        )


def drive_one(
    engine: Engine,
    delivery_id: UUID,
    *,
    registry: Any,
    capabilities: Any,
    resolver: Callable[[Mapping[str, str]], Mapping[str, str]],
    data_budget_seconds: int = 0,
) -> str:
    """Prepare, invoke, settle ONE delivery. Returns a closed outcome word.

    The id may be stale: the batch was selected earlier, and another pump may
    have claimed it or a killed pump may have left it `in_flight`. The row is
    therefore re-read FOR UPDATE SKIP LOCKED and driven only while it is still
    `pending`/`retryable`; `prepare` then claims inside the SAME transaction.
    The module's `claim_delivery` would also re-claim an expired `in_flight`
    row, which is exactly what this predicate keeps from ever reaching it.
    """
    with Session(engine) as db:
        delivery = db.execute(
            select(integration.DeliveryAttempt)
            .where(
                integration.DeliveryAttempt.id == delivery_id,
                integration.DeliveryAttempt.state.in_(_QUEUED),
            )
            .with_for_update(skip_locked=True)
        ).scalar_one_or_none()
        if delivery is None:
            return "lost"
        try:
            prepared = integration.prepare(db, delivery, registry=registry)
        except (integration.DispatchNotAdmitted, integration.DispatchUnavailable):
            db.rollback()
            return "refused"
        db.commit()
    if prepared is None:
        return "lost"
    started = time.monotonic()
    try:
        outcome = integration.invoke(
            prepared, registry=registry, resolve_secrets=resolver
        )
    except Exception as exc:
        # Nothing is known about whether anything left the process, so this is
        # ambiguous, never retryable. Type name only.
        name = type(exc).__name__
        outcome = integration.Outcome(
            status=integration.OutcomeStatus.RECONCILIATION_REQUIRED,
            error_code="invoke_failed",
            error_detail=name if name.isidentifier() else "Exception",
        )
    if data_budget_seconds and time.monotonic() - started > data_budget_seconds:
        logger.warning("an outbound send exceeded OUTBOUND_DATA_BUDGET_SECONDS")
    with Session(engine) as db:
        delivery = db.get(integration.DeliveryAttempt, delivery_id)
        if delivery is None:  # pragma: no cover
            return "failed"
        integration.settle(
            db, delivery, outcome, prepared=prepared, registry=capabilities
        )
        db.commit()
    return "settled"


def deliver_due_outbound(
    engine: Engine,
    limit: int,
    *,
    registry: Any = None,
    capabilities: Any = None,
    resolver: Callable[[Mapping[str, str]], Mapping[str, str]] = resolve_secrets,
    data_budget_seconds: int = 0,
) -> dict[str, int]:
    """One bounded pass over the module's due set. Identifier-free counts."""
    reg = registry if registry is not None else integration.discover()
    ids = select_due(engine, limit)
    counts = {"selected": len(ids), "settled": 0, "lost": 0, "refused": 0, "failed": 0}
    for delivery_id in ids:
        try:
            result = drive_one(
                engine,
                delivery_id,
                registry=reg,
                capabilities=capabilities,
                resolver=resolver,
                data_budget_seconds=data_budget_seconds,
            )
        except integration.LostClaim:
            result = "lost"
        except Exception:
            result = "failed"
            logger.error("outbound delivery pass item failed")
        counts[result] += 1
    return counts


def mark_stranded_ambiguous(engine: Engine) -> int:
    """An expired in-flight outbound lease is AMBIGUOUS, never retryable.

    UNCONDITIONAL: it does not depend on the pump flag (toggling the pump must
    not turn a stranded send into a resend), and it runs at startup, on the
    timed sweep and before the operator's lease release. Every row is taken
    `FOR UPDATE SKIP LOCKED` under the same predicate, so it cannot race a pump
    that is settling it.
    """
    now = datetime.now(UTC)
    marked = 0
    with Session(engine) as db:
        stranded = list(
            db.execute(
                select(integration.DeliveryAttempt)
                .where(
                    integration.DeliveryAttempt.state == "in_flight",
                    integration.DeliveryAttempt.leased_until.is_not(None),
                    integration.DeliveryAttempt.leased_until < now,
                )
                .with_for_update(skip_locked=True)
            )
            .scalars()
            .all()
        )
        for delivery in stranded:
            integration.record_delivery_outcome(
                delivery,
                integration.Outcome(
                    status=integration.OutcomeStatus.RECONCILIATION_REQUIRED,
                    error_code="lease_expired_in_flight",
                ),
            )
            write_platform_audit_event(
                db,
                actor_admin_id=None,
                action="integrator.delivery.ambiguous_on_lease_expiry",
                entity_type="delivery_attempt",
                entity_id=str(delivery.id),
                details={"attempt_count": delivery.attempt_count},
            )
            marked += 1
        if marked:
            db.commit()
    return marked


# ── Retention ───────────────────────────────────────────────────────────────


def retention_policy(settings: Settings) -> Any:
    return integration.RetentionPolicy(
        payload_retention_days=settings.outbound_payload_retention_days,
        replay_evidence_retention_days=(
            settings.outbound_replay_evidence_retention_days
        ),
        legal_policy_owner=settings.outbound_legal_policy_owner,
        batch_size=settings.worker_batch_size,
    )


def redact_expired_payloads(engine: Engine, settings: Settings) -> int:
    with Session(engine) as db:
        sweep = integration.purge_expired_delivery_payloads(
            db, policy=retention_policy(settings)
        )
        db.commit()
        return int(sweep.redacted)
