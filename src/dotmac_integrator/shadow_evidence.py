"""Durable, privacy-safe evidence for a read-only product-port comparison.

The destination's shadow port owns the comparison.  This deployment owns only
the evidence that the comparison was run: a revision, a closed verdict, closed
blocking codes and field *names*.  Provider identities, field values, receipt
payloads and exception text never enter this module's value objects.

The comparison revision is load-bearing.  A terminal verdict is observed once
per receipt and revision; a new image/contract revision deliberately re-drives
the population.  Transient verdicts are retried after a deployment-configured
interval.  This is sampling policy for evidence, not delivery retry policy —
no receipt is claimed, settled or otherwise mutated here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa
from dotmac_kernel.audit import write_platform_audit_event
from dotmac_kernel.models_platform import PlatformAuditEvent
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.sql.selectable import Subquery

__all__ = [
    "RETRYABLE_SHADOW_VERDICTS",
    "SHADOW_EVIDENCE_ACTION",
    "SafeShadowVerdict",
    "ShadowObservation",
    "ShadowReport",
    "latest_shadow_evidence",
    "normalize_verdict",
    "record_shadow_observation",
    "shadow_report",
    "should_compare",
    "summarize",
    "unreadable_verdict",
]


class _MirrorVerdict(Protocol):
    @property
    def verdict(self) -> str: ...

    @property
    def agrees(self) -> bool: ...

    @property
    def blocking_reasons(self) -> tuple[str, ...]: ...

    @property
    def disagreeing_fields(self) -> tuple[str, ...]: ...


# Transcribed from the destination's merged mirror contract.  An unknown code
# is not persisted verbatim: that string is third-party content, and a future
# destination bug must not turn the platform audit trail into a secret sink.
_EXPECTED_BLOCKERS: dict[str, frozenset[frozenset[str]]] = {
    "agrees": frozenset({frozenset()}),
    "field_disagreement": frozenset({frozenset({"normalized_field_disagreement"})}),
    "identity_shape_mismatch": frozenset(
        {
            frozenset({"identity_shape_mismatch"}),
            frozenset({"identity_shape_mismatch", "normalized_field_disagreement"}),
        }
    ),
    "collision": frozenset({frozenset({"domain_fingerprint_collision"})}),
    "no_counterpart": frozenset({frozenset({"no_counterpart_observation"})}),
    "unreadable": frozenset({frozenset({"comparison_unreadable"})}),
    "unrecognized": frozenset({frozenset({"unrecognized_comparison_report"})}),
}
RETRYABLE_SHADOW_VERDICTS = frozenset({"no_counterpart", "unreadable", "unrecognized"})
_SAFE_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_.]{0,119}$")
_UNRECOGNIZED_REASON = "unrecognized_comparison_report"
SHADOW_EVIDENCE_ACTION = "integrator.shadow_comparison.observed"
_ENTITY_TYPE = "inbox_receipt"


def _utc(value: datetime) -> datetime:
    return (
        value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    ).astimezone(UTC)


@dataclass(frozen=True, slots=True)
class SafeShadowVerdict:
    """The only destination output permitted to reach durable evidence."""

    verdict: str
    blocking_reasons: tuple[str, ...]
    disagreeing_fields: tuple[str, ...]

    def __post_init__(self) -> None:
        expected = _EXPECTED_BLOCKERS.get(self.verdict)
        if (
            expected is None
            or frozenset(self.blocking_reasons) not in expected
            or any(
                _SAFE_FIELD_NAME.fullmatch(field) is None
                for field in self.disagreeing_fields
            )
            or (self.verdict == "agrees" and self.disagreeing_fields)
        ):
            # Never interpolate the rejected value. This constructor is the
            # final boundary before persistence and may itself be handed
            # untrusted destination text.
            raise ValueError("shadow verdict is not safe durable evidence")

    @property
    def retryable(self) -> bool:
        return self.verdict in RETRYABLE_SHADOW_VERDICTS


def normalize_verdict(value: _MirrorVerdict) -> SafeShadowVerdict:
    """Validate a destination report and discard every unsafe string.

    Field names use a deliberately narrow identifier grammar.  This permits
    names such as ``normalized_payload.text`` but not whitespace, quotes or a
    serialised value.  A malformed field invalidates the whole report rather
    than being silently dropped: a report claiming agreement after losing its
    only disagreement would be false evidence.
    """

    verdict = value.verdict
    reasons = frozenset(value.blocking_reasons)
    expected = _EXPECTED_BLOCKERS.get(verdict)
    fields = tuple(sorted(set(value.disagreeing_fields)))
    consistent_agreement = value.agrees is (verdict == "agrees")
    safe_fields = all(_SAFE_FIELD_NAME.fullmatch(field) for field in fields)
    if (
        expected is None
        or reasons not in expected
        or not consistent_agreement
        or not safe_fields
        or (verdict == "agrees" and fields)
    ):
        return SafeShadowVerdict(
            verdict="unrecognized",
            blocking_reasons=(_UNRECOGNIZED_REASON,),
            disagreeing_fields=(),
        )
    return SafeShadowVerdict(
        verdict=verdict,
        blocking_reasons=tuple(sorted(reasons)),
        disagreeing_fields=fields,
    )


def unreadable_verdict() -> SafeShadowVerdict:
    """A transport/assembly failure, with no exception text retained."""

    return SafeShadowVerdict(
        verdict="unreadable",
        blocking_reasons=("comparison_unreadable",),
        disagreeing_fields=(),
    )


@dataclass(frozen=True, slots=True)
class ShadowObservation:
    """One append-only audit event, projected into a typed safe value."""

    event_id: UUID
    receipt_id: UUID
    comparison_revision: str
    verdict: str
    blocking_reasons: tuple[str, ...]
    disagreeing_fields: tuple[str, ...]
    observed_at: datetime

    @property
    def retryable(self) -> bool:
        return self.verdict in RETRYABLE_SHADOW_VERDICTS


def should_compare(
    latest: ShadowObservation | None,
    *,
    comparison_revision: str,
    retry_after: timedelta,
    now: datetime,
) -> bool:
    """Whether a receipt needs one mirror call in this evidence revision."""

    if latest is None or latest.comparison_revision != comparison_revision:
        return True
    if not latest.retryable:
        return False
    return _utc(latest.observed_at) <= _utc(now) - retry_after


@dataclass(frozen=True, slots=True)
class ShadowReport:
    """Aggregate facts about one comparison revision, with no row identities.

    ``sample_has_no_blockers`` is deliberately NOT named ``is_cutover_safe``.
    A full cutover also needs a complete traffic cycle, replay/collision proof,
    credential scope, migration evidence and a rollback owner.  Those remain
    the destination's gate; this report supplies one input and cannot approve a
    migration by itself.
    """

    comparison_revision: str
    unique_receipts: int
    agreeing: int
    verdict_counts: dict[str, int]
    blocking_reason_counts: dict[str, int]
    disagreeing_fields: dict[str, int]
    first_observed_at: datetime | None
    last_observed_at: datetime | None

    @property
    def sample_has_no_blockers(self) -> bool:
        return self.unique_receipts > 0 and not self.blocking_reason_counts

    def as_dict(self) -> dict[str, object]:
        return {
            "comparison_revision": self.comparison_revision,
            "unique_receipts": self.unique_receipts,
            "agreeing": self.agreeing,
            "verdict_counts": dict(sorted(self.verdict_counts.items())),
            "blocking_reason_counts": dict(sorted(self.blocking_reason_counts.items())),
            "disagreeing_fields": dict(sorted(self.disagreeing_fields.items())),
            "first_observed_at": (
                self.first_observed_at.isoformat()
                if self.first_observed_at is not None
                else None
            ),
            "last_observed_at": (
                self.last_observed_at.isoformat()
                if self.last_observed_at is not None
                else None
            ),
            "sample_has_no_blockers": self.sample_has_no_blockers,
        }


def summarize(
    observations: tuple[ShadowObservation, ...], *, comparison_revision: str
) -> ShadowReport:
    """Latest verdict per receipt, plus the full revision's time span."""

    selected = tuple(
        item for item in observations if item.comparison_revision == comparison_revision
    )
    latest: dict[UUID, ShadowObservation] = {}
    for item in selected:
        incumbent = latest.get(item.receipt_id)
        item_key = (_utc(item.observed_at), item.event_id.int)
        if incumbent is None or item_key > (
            _utc(incumbent.observed_at),
            incumbent.event_id.int,
        ):
            latest[item.receipt_id] = item

    verdict_counts: dict[str, int] = {}
    reason_counts: dict[str, int] = {}
    field_counts: dict[str, int] = {}
    for item in latest.values():
        verdict_counts[item.verdict] = verdict_counts.get(item.verdict, 0) + 1
        for reason in set(item.blocking_reasons):
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        for field in set(item.disagreeing_fields):
            field_counts[field] = field_counts.get(field, 0) + 1

    times = tuple(_utc(item.observed_at) for item in selected)
    return ShadowReport(
        comparison_revision=comparison_revision,
        unique_receipts=len(latest),
        agreeing=verdict_counts.get("agrees", 0),
        verdict_counts=dict(sorted(verdict_counts.items())),
        blocking_reason_counts=dict(sorted(reason_counts.items())),
        disagreeing_fields=dict(sorted(field_counts.items())),
        first_observed_at=min(times) if times else None,
        last_observed_at=max(times) if times else None,
    )


def latest_shadow_evidence(comparison_revision: str) -> Subquery:
    """One deterministic audit row per receipt for a comparison revision.

    Returned as a subquery so the receipt selector can exclude already-proven
    rows in PostgreSQL.  Pulling every historical receipt into Python on every
    worker poll would turn a successful shadow run into an ever-growing full
    table scan.
    """

    event = PlatformAuditEvent
    ranked = (
        sa.select(
            event.entity_id.label("receipt_id"),
            event.id.label("evidence_id"),
            event.details.label("details"),
            event.created_at.label("observed_at"),
            sa.func.row_number()
            .over(
                partition_by=event.entity_id,
                order_by=(event.created_at.desc(), event.id.desc()),
            )
            .label("position"),
        )
        .where(
            event.action == SHADOW_EVIDENCE_ACTION,
            event.entity_type == _ENTITY_TYPE,
            event.details["comparison_revision"].as_string() == comparison_revision,
        )
        .subquery("ranked_shadow_evidence")
    )
    return (
        sa.select(
            ranked.c.receipt_id,
            ranked.c.evidence_id,
            ranked.c.details,
            ranked.c.observed_at,
        )
        .where(ranked.c.position == 1)
        .subquery("latest_shadow_evidence")
    )


def _from_event(event: PlatformAuditEvent) -> ShadowObservation:
    """Project an event this writer owns, refusing corrupted evidence."""

    details = event.details
    try:
        receipt_id = UUID(str(event.entity_id))
        revision = str(details["comparison_revision"])
        verdict = str(details["verdict"])
        reasons_raw = details["blocking_reasons"]
        fields_raw = details["disagreeing_fields"]
        if not isinstance(reasons_raw, list) or not isinstance(fields_raw, list):
            raise TypeError("evidence arrays are not arrays")
        safe = SafeShadowVerdict(
            verdict=verdict,
            blocking_reasons=tuple(str(item) for item in reasons_raw),
            disagreeing_fields=tuple(str(item) for item in fields_raw),
        )
        observed_at = event.created_at
        if observed_at is None:
            raise TypeError("evidence has no persistence timestamp")
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(
            "shadow evidence is malformed; refusing to produce a cutover report"
        ) from exc
    return ShadowObservation(
        event_id=event.id,
        receipt_id=receipt_id,
        comparison_revision=revision,
        verdict=verdict,
        blocking_reasons=safe.blocking_reasons,
        disagreeing_fields=safe.disagreeing_fields,
        observed_at=observed_at,
    )


def record_shadow_observation(
    engine: Engine,
    *,
    receipt_id: UUID,
    comparison_revision: str,
    verdict: SafeShadowVerdict,
) -> None:
    """Append one system-authored fact and commit no receipt mutation.

    The scheduled worker has no human actor, so ``actor_admin_id`` is null on
    purpose.  Assigning the last operator who configured the deployment would
    fabricate who performed this comparison.
    """

    with Session(engine) as db:
        write_platform_audit_event(
            db,
            actor_admin_id=None,
            action="integrator.shadow_comparison.observed",
            entity_type=_ENTITY_TYPE,
            entity_id=str(receipt_id),
            details={
                "comparison_revision": comparison_revision,
                "verdict": verdict.verdict,
                "blocking_reasons": list(verdict.blocking_reasons),
                "disagreeing_fields": list(verdict.disagreeing_fields),
            },
        )
        db.commit()


def _observations(
    engine: Engine, comparison_revision: str
) -> tuple[ShadowObservation, ...]:
    event = PlatformAuditEvent
    with Session(engine) as db:
        rows = db.scalars(
            sa.select(event)
            .where(
                event.action == SHADOW_EVIDENCE_ACTION,
                event.entity_type == _ENTITY_TYPE,
                event.details["comparison_revision"].as_string() == comparison_revision,
            )
            .order_by(event.created_at, event.id)
        ).all()
    return tuple(_from_event(row) for row in rows)


def shadow_report(engine: Engine, comparison_revision: str) -> ShadowReport:
    """Aggregate the latest evidence per receipt for an operator."""

    return summarize(
        _observations(engine, comparison_revision),
        comparison_revision=comparison_revision,
    )
