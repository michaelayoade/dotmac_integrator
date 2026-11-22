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
row into `retryable`: the next pass would send it again, and a mail that may
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
connector's declared DATA budget, so a slow, healthy send cannot lose its claim
to a second worker.

## Payload redaction

`redact_expired_payloads` runs the module's `purge_expired_delivery_payloads`
under a `RetentionPolicy` built from settings. The module redacts only
`delivered` rows by design: a dead-lettered or ambiguous delivery is still
replayable, so its payload is unresolved content to the module.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

import dotmac_integration as integration
from dotmac_kernel.audit import write_platform_audit_event
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from dotmac_integrator.product_auth import ProductPrincipal
from dotmac_integrator.secret_resolver import resolve_secrets
from dotmac_integrator.settings import Settings

logger = logging.getLogger(__name__)

__all__ = [
    "DispatchBody",
    "deliver_due_outbound",
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


def lease_exceeds_budget(lease_seconds: int, data_budget_seconds: int) -> bool:
    return lease_seconds > data_budget_seconds


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


def submit_dispatch(
    engine: Engine,
    principal: ProductPrincipal,
    body: DispatchBody,
    *,
    wait_seconds: float,
    capabilities: Any = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Queue (or find) the delivery for `dispatch_id`; wait for its state.

    Idempotent through the module's `enqueue_delivery`: the same key with the
    same content returns the existing row (one send, whatever the retries); the
    same key with different content is a 409.
    """
    if body.capability_binding_id not in principal.binding_ids:
        raise HTTPException(403, "dispatch not authorized for this binding")
    declared = capabilities if capabilities is not None else _capabilities()
    with Session(engine) as db:
        binding = db.get(integration.CapabilityBinding, body.capability_binding_id)
        if binding is None:
            raise HTTPException(404, "binding not found")
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
        delivery_id = delivery.id
        first = _view(delivery, dispatch_id=body.dispatch_id, is_new=is_new)

    deadline = time.monotonic() + max(0.0, wait_seconds)
    current = first
    while not current["terminal"] and time.monotonic() < deadline:
        sleep(0.25)
        with Session(engine) as db:
            row = db.get(integration.DeliveryAttempt, delivery_id)
            if row is None:  # pragma: no cover - the row was just written
                break
            db.refresh(row)
            current = _view(row, dispatch_id=body.dispatch_id, is_new=is_new)
    return current


def _capabilities() -> Any:
    try:
        return integration.capability_registry()
    except Exception:
        raise HTTPException(503, "capability registry not installed") from None


# ── Pump ────────────────────────────────────────────────────────────────────


def deliver_due_outbound(
    engine: Engine,
    limit: int,
    *,
    registry: Any = None,
    capabilities: Any = None,
    resolver: Callable[[Mapping[str, str]], Mapping[str, str]] = resolve_secrets,
) -> dict[str, int]:
    """One bounded pass: prepare (claim), invoke (no session), settle.

    The selector is a HINT (hard rule 24): it reads queued ids without a lock and
    `prepare`'s conditional claim decides the race. It never selects `in_flight`,
    so an expired lease is not re-driven here; it is recovered as ambiguous by
    `mark_stranded_ambiguous`.
    """
    reg = registry if registry is not None else integration.discover()
    now = datetime.now(UTC)
    with Session(engine) as db:
        ids = list(
            db.execute(
                select(integration.DeliveryAttempt.id)
                .where(
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
    counts = {
        "selected": len(ids),
        "settled": 0,
        "lost": 0,
        "refused": 0,
        "failed": 0,
    }
    for delivery_id in ids:
        try:
            with Session(engine) as db:
                delivery = db.get(integration.DeliveryAttempt, delivery_id)
                if delivery is None:
                    continue
                try:
                    prepared = integration.prepare(db, delivery, registry=reg)
                except (
                    integration.DispatchNotAdmitted,
                    integration.DispatchUnavailable,
                ):
                    counts["refused"] += 1
                    continue
                db.commit()
            if prepared is None:
                counts["lost"] += 1
                continue
            try:
                outcome = integration.invoke(
                    prepared, registry=reg, resolve_secrets=resolver
                )
            except Exception as exc:
                # Nothing is known about whether anything left the process, so
                # this is ambiguous, never retryable. Type name only.
                name = type(exc).__name__
                outcome = integration.Outcome(
                    status=integration.OutcomeStatus.RECONCILIATION_REQUIRED,
                    error_code="invoke_failed",
                    error_detail=name if name.isidentifier() else "Exception",
                )
            with Session(engine) as db:
                delivery = db.get(integration.DeliveryAttempt, delivery_id)
                if delivery is None:  # pragma: no cover
                    continue
                integration.settle(
                    db, delivery, outcome, prepared=prepared, registry=capabilities
                )
                db.commit()
            counts["settled"] += 1
        except integration.LostClaim:
            counts["lost"] += 1
        except Exception:
            counts["failed"] += 1
            logger.error("outbound delivery pass item failed")
    return counts


def mark_stranded_ambiguous(engine: Engine) -> int:
    """An expired in-flight outbound lease is AMBIGUOUS, never retryable.

    Runs before the module's blanket `release_expired_leases`, which would turn
    the same row into `retryable` and send it again.
    """
    now = datetime.now(UTC)
    marked = 0
    with Session(engine) as db:
        stranded = list(
            db.execute(
                select(integration.DeliveryAttempt).where(
                    integration.DeliveryAttempt.state == "in_flight",
                    integration.DeliveryAttempt.leased_until.is_not(None),
                    integration.DeliveryAttempt.leased_until < now,
                )
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
