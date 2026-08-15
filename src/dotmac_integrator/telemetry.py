"""Metrics. Observations only — never a decision, and never an identifier.

A control plane that cannot say how far behind it is will be believed to be
fine right up to the moment a customer notices. This file is what makes the
queues, the leases and the refusals visible, and it does it with two rules that
are worth more than the metrics themselves.

## Rule 1 — a metric label is a closed vocabulary, structurally

Metric labels are the leak surface people forget is readable. A Prometheus
scrape is stored unencrypted, shipped to a long-lived time series database,
rendered in dashboards, pasted into tickets and read by more people than the
database row ever will be. An endpoint key, a `provider_event_id`, a phone
number, a message body or anything derived from a secret must never reach one.

The defence is not a code review convention and not a regex over strings. Every
:class:`MetricFamily` declares the ONLY label values it will ever accept, and
:func:`render` REFUSES a sample whose label is not in that set. A phone number
cannot become a label because there is no code path that would render one — the
renderer raises instead. `tests/architecture/test_no_identifier_reaches_a_label.py`
drives exactly that, with real-looking identifiers.

The corollary is that cardinality is bounded by construction. Every label set
here comes from a database CHECK constraint, a dataclass's fields, or a closed
tuple declared below; none comes from a row.

## Rule 2 — a count alone hides one stuck item

`receipts_unprocessed 1` reads as a quiet night. It is also what a single
receipt stuck since March looks like. So every backlog that can age is reported
BOTH ways: a depth and the age of its oldest member. The ages are what the
alerts fire on.

An age gauge with nothing to measure is OMITTED rather than reported as zero: a
zero would mean "the oldest due delivery is due right now", which is the
healthiest possible reading of the unhealthiest possible cause — no data.

## What is deliberately not decided here

`integration.health_report` is the MODULE's verdict about what is stuck, and it
is transported into the `integrator_health_signal` family unchanged. This file
does not recompute it. The queue-depth families beside it are distributions —
facts, not verdicts — and the two are named apart so nobody reads one as the
other. Alert THRESHOLDS live in `deploy/alerts/`, because "how late is too
late" is a deployment's decision and putting it here would fork it.
"""

from __future__ import annotations

import dataclasses
import threading
import time
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

import dotmac_integration as integration
import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

__all__ = [
    "CHALLENGE_OUTCOMES",
    "DELIVERY_STATES",
    "FAMILIES",
    "HEALTH_SIGNALS",
    "RECEIPT_STATES",
    "REDACTION_MARKER",
    "REFUSAL_REASONS",
    "SIGNATURE_OUTCOMES",
    "IngressCounters",
    "MetricFamily",
    "Sample",
    "UndeclaredLabel",
    "collect",
    "counters",
    "now_epoch",
    "render",
    "scrape",
    "snapshot",
]


class UndeclaredLabel(ValueError):
    """A sample tried to carry a label value nobody declared.

    Raised rather than sanitised. Silently dropping the label would publish a
    metric that quietly means something else; silently truncating it would
    publish a prefix of a phone number, which is still a phone number.
    """


# ── The closed vocabularies ─────────────────────────────────────────────────

#: Why an inbound request was refused. A CLOSED set, and the whole reason
#: `record_refusal` can be trusted with a label: an unrecognised reason raises,
#: so no caller can turn a provider's error string — or a subscriber's number —
#: into a new time series.
#:
#: The ingress reasons are declared alongside the operational ones on purpose:
#: the ingress handler is a separate slice, and a vocabulary that arrives with
#: its first caller cannot be reviewed as a whole.
REFUSAL_REASONS: Final[tuple[str, ...]] = (
    # Ingress: the request did not prove it was who it claimed to be.
    "signature_invalid",
    "signature_missing",
    "challenge_failed",
    "unknown_target",
    "payload_too_large",
    "replay_window_expired",
    # Operational surface: the request was authentic and still could not be
    # served.
    "malformed_identifier",
    "not_found",
    "not_repairable",
)

#: A signature was checked and it either verified or it did not. Two values, and
#: deliberately not a third: "error" would collapse "we could not check" into
#: "it failed", and those need different alerts.
SIGNATURE_OUTCOMES: Final[tuple[str, ...]] = ("accepted", "rejected")

#: A provider's verification handshake (Meta's `hub.challenge`, and every
#: provider's equivalent). `refused` is the interesting one — a challenge we
#: declined means someone is pointing a webhook at this deployment.
CHALLENGE_OUTCOMES: Final[tuple[str, ...]] = ("served", "refused")


#: Delivery and receipt lifecycle states, read from the MODULE's own CHECK
#: constraints rather than restated here — a second hand-written list is what
#: drifts, and a drifted list means a state with no series at all.
def _states(model: type[Any], constraint_name: str) -> tuple[str, ...]:
    import re

    for constraint in model.__table__.constraints:
        if constraint.name == constraint_name:
            return tuple(
                sorted(set(re.findall(r"'([a-z_]+)'", str(constraint.sqltext))))
            )
    raise RuntimeError(f"{model.__name__} lost its {constraint_name} constraint")


DELIVERY_STATES: Final[tuple[str, ...]] = _states(
    integration.DeliveryAttempt, "ck_delivery_attempts_state"
)
RECEIPT_STATES: Final[tuple[str, ...]] = _states(
    integration.InboxReceipt, "ck_inbox_receipts_state"
)

#: The module's health signals, taken from the dataclass's own fields so the
#: label set cannot drift from the report it transports.
HEALTH_SIGNALS: Final[tuple[str, ...]] = tuple(
    sorted(f.name for f in dataclasses.fields(integration.HealthReport))
)

#: The retention tombstone key `dotmac-integration` writes over an expired
#: payload. A CROSS-REPOSITORY wire contract: the Starter pins this exact
#: literal in `tests/unit/test_integration_retention.py
#: ::test_the_redaction_marker_is_a_wire_contract`.
#:
#: Matched as a literal rather than imported because the pinned release
#: (`dotmac-integration 0.1.0a1`) predates the retention module. When the pin
#: moves to a release that exports `REDACTION_MARKER`, import it and delete
#: this constant — the metric is meaningless if the two ever disagree.
REDACTION_MARKER: Final = "__dotmac_redacted__"


# ── Families ────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class MetricFamily:
    """One metric, and the complete set of label values it may ever carry."""

    name: str
    help: str
    kind: str
    #: `None` for an unlabelled family. Exactly one label is supported on
    #: purpose: two labels multiply, and a control plane's metrics have no
    #: question that needs the product.
    label: str | None = None
    allowed: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in ("gauge", "counter"):
            raise ValueError(f"{self.name}: kind must be gauge or counter")
        if (self.label is None) != (not self.allowed):
            raise ValueError(
                f"{self.name}: a labelled family must declare its complete "
                "allowed set, and an unlabelled one must declare none. An open "
                "label set is how a subscriber identifier becomes a time series"
            )


@dataclass(frozen=True, slots=True)
class Sample:
    """One value, optionally on one declared label."""

    family: str
    value: float
    label_value: str | None = None


FAMILIES: Final[tuple[MetricFamily, ...]] = (
    # ── The module's verdict, transported ───────────────────────────────────
    MetricFamily(
        "integrator_health_signal",
        "dotmac_integration.health_report counts, by signal. The MODULE's "
        "verdict about what is stuck; this deployment does not recompute it.",
        "gauge",
        label="signal",
        allowed=HEALTH_SIGNALS,
    ),
    # ── Distributions: facts, not verdicts ──────────────────────────────────
    MetricFamily(
        "integrator_delivery_queue_depth",
        "Outbound deliveries by lifecycle state.",
        "gauge",
        label="state",
        allowed=DELIVERY_STATES,
    ),
    MetricFamily(
        "integrator_receipt_queue_depth",
        "Inbound receipts by lifecycle state.",
        "gauge",
        label="state",
        allowed=RECEIPT_STATES,
    ),
    MetricFamily(
        "integrator_delivery_due",
        "Deliveries whose next attempt is due now and which no worker holds.",
        "gauge",
    ),
    MetricFamily(
        "integrator_delivery_leased",
        "Deliveries a worker currently holds a live lease on.",
        "gauge",
    ),
    MetricFamily(
        "integrator_delivery_lease_expired",
        "Deliveries whose lease has expired — a worker died holding them.",
        "gauge",
    ),
    # ── Ages: the half a count cannot tell you ──────────────────────────────
    MetricFamily(
        "integrator_delivery_oldest_due_age_seconds",
        "Queue lag: how long the oldest due delivery has been waiting. Omitted "
        "when nothing is due — a zero would read as healthy.",
        "gauge",
    ),
    MetricFamily(
        "integrator_receipt_oldest_unprocessed_age_seconds",
        "Age of the oldest inbound receipt that has not reached an outcome. A "
        "count alone hides one item stuck since March.",
        "gauge",
    ),
    MetricFamily(
        "integrator_checkpoint_oldest_lag_seconds",
        "How long since the least recently advanced polling cursor moved.",
        "gauge",
    ),
    # ── Payload retention backlog ───────────────────────────────────────────
    MetricFamily(
        "integrator_receipt_retained_payloads",
        "Receipts still holding an un-redacted provider payload.",
        "gauge",
    ),
    MetricFamily(
        "integrator_receipt_oldest_retained_payload_age_seconds",
        "Age of the oldest un-redacted payload. Deliberately carries no "
        "retention period: the period is the deployment's decision and lives "
        "in the alert rule, not in this process.",
        "gauge",
    ),
    # ── The worker itself ───────────────────────────────────────────────────
    MetricFamily(
        "integrator_worker_running",
        "1 when the background sweep task is alive, 0 otherwise.",
        "gauge",
    ),
    MetricFamily(
        "integrator_worker_last_sweep_timestamp_seconds",
        "Unix time of the last COMPLETED lease sweep. Omitted until the first "
        "one finishes, so a never-started worker cannot look recent.",
        "gauge",
    ),
    MetricFamily(
        "integrator_worker_sweep_failures_total",
        "Lease sweeps that raised. The loop survives them, which is exactly why "
        "they need counting.",
        "counter",
    ),
    # ── Refusals ────────────────────────────────────────────────────────────
    MetricFamily(
        "integrator_ingress_refusals_total",
        "Requests refused, by declared reason.",
        "counter",
        label="reason",
        allowed=REFUSAL_REASONS,
    ),
    MetricFamily(
        "integrator_ingress_signature_verifications_total",
        "Signature checks, by outcome.",
        "counter",
        label="outcome",
        allowed=SIGNATURE_OUTCOMES,
    ),
    MetricFamily(
        "integrator_ingress_challenges_total",
        "Provider verification handshakes, by outcome.",
        "counter",
        label="outcome",
        allowed=CHALLENGE_OUTCOMES,
    ),
)

_BY_NAME: Final[dict[str, MetricFamily]] = {f.name: f for f in FAMILIES}


# ── Counters ────────────────────────────────────────────────────────────────


class IngressCounters:
    """Process-local counters over the three closed vocabularies.

    Process-local, and that is honest rather than a limitation: several replicas
    each expose their own, and Prometheus sums them. A shared counter in the
    database would be a write on every refused request — the cheapest possible
    denial-of-service against a public webhook endpoint.

    Every method REFUSES an undeclared value. That refusal is the privacy
    guarantee: a caller cannot pass a provider's error string, an endpoint key
    or a phone number, because the only accepted arguments are members of a
    tuple declared in this file.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._refusals: dict[str, int] = dict.fromkeys(REFUSAL_REASONS, 0)
        self._signatures: dict[str, int] = dict.fromkeys(SIGNATURE_OUTCOMES, 0)
        self._challenges: dict[str, int] = dict.fromkeys(CHALLENGE_OUTCOMES, 0)
        self._sweep_failures = 0

    @staticmethod
    def _checked(value: str, allowed: Sequence[str], what: str) -> str:
        if value not in allowed:
            raise UndeclaredLabel(
                f"{value!r} is not a declared {what}. Add it to the closed set "
                f"in telemetry.py ({sorted(allowed)}) after deciding it is safe "
                "to publish — a label value reaches every dashboard and every "
                "ticket that quotes one"
            )
        return value

    def record_refusal(self, reason: str) -> None:
        key = self._checked(reason, REFUSAL_REASONS, "refusal reason")
        with self._lock:
            self._refusals[key] += 1

    def record_signature(self, outcome: str) -> None:
        key = self._checked(outcome, SIGNATURE_OUTCOMES, "signature outcome")
        with self._lock:
            self._signatures[key] += 1

    def record_challenge(self, outcome: str) -> None:
        key = self._checked(outcome, CHALLENGE_OUTCOMES, "challenge outcome")
        with self._lock:
            self._challenges[key] += 1

    def record_sweep_failure(self) -> None:
        with self._lock:
            self._sweep_failures += 1

    def samples(self) -> list[Sample]:
        with self._lock:
            refusals = dict(self._refusals)
            signatures = dict(self._signatures)
            challenges = dict(self._challenges)
            failures = self._sweep_failures
        return [
            *(
                Sample("integrator_ingress_refusals_total", count, reason)
                for reason, count in refusals.items()
            ),
            *(
                Sample(
                    "integrator_ingress_signature_verifications_total",
                    count,
                    outcome,
                )
                for outcome, count in signatures.items()
            ),
            *(
                Sample("integrator_ingress_challenges_total", count, outcome)
                for outcome, count in challenges.items()
            ),
            Sample("integrator_worker_sweep_failures_total", failures),
        ]


#: The one instance the process shares. A module-level singleton because a
#: counter that is not shared counts nothing.
counters: Final[IngressCounters] = IngressCounters()


# ── Collection ──────────────────────────────────────────────────────────────


def _age_seconds(moment: datetime, stamp: datetime | None) -> float | None:
    if stamp is None:
        return None
    stamped = stamp if stamp.tzinfo is not None else stamp.replace(tzinfo=UTC)
    return max(0.0, (moment - stamped).total_seconds())


def _counts_by_state(
    db: Session, model: type[Any], allowed: Sequence[str]
) -> dict[str, int]:
    """Every declared state, including the ones at zero.

    Reporting a zero here rather than omitting it is the opposite choice from
    the age gauges, and for the opposite reason: an absent `dead_letter` series
    would make an alert on it silently never fire.
    """
    rows = db.execute(
        sa.select(model.state, sa.func.count()).group_by(model.state)
    ).all()
    observed = {str(state): int(count) for state, count in rows}
    return {state: observed.get(state, 0) for state in allowed}


def snapshot(db: Session, *, now: datetime | None = None) -> list[Sample]:
    """Read every gauge from the ledgers. Counts and ages, nothing decided."""
    moment = now or datetime.now(UTC)
    delivery = integration.DeliveryAttempt
    receipt = integration.InboxReceipt
    checkpoint = integration.PollingCheckpoint

    samples: list[Sample] = []

    # The module's verdict, transported unchanged.
    report = integration.health_report(db)
    for signal, value in report.as_dict().items():
        samples.append(Sample("integrator_health_signal", float(value), signal))

    for state, count in _counts_by_state(db, delivery, DELIVERY_STATES).items():
        samples.append(Sample("integrator_delivery_queue_depth", float(count), state))
    for state, count in _counts_by_state(db, receipt, RECEIPT_STATES).items():
        samples.append(Sample("integrator_receipt_queue_depth", float(count), state))

    due_predicate = (
        delivery.state.in_(("pending", "retryable")),
        sa.or_(
            delivery.next_attempt_at.is_(None),
            delivery.next_attempt_at <= moment,
        ),
    )
    samples.append(
        Sample("integrator_delivery_due", float(_count(db, delivery, *due_predicate)))
    )
    samples.append(
        Sample(
            "integrator_delivery_leased",
            float(
                _count(
                    db,
                    delivery,
                    delivery.state == "in_flight",
                    delivery.leased_until.is_not(None),
                    delivery.leased_until >= moment,
                )
            ),
        )
    )
    samples.append(
        Sample(
            "integrator_delivery_lease_expired",
            float(
                _count(
                    db,
                    delivery,
                    delivery.state == "in_flight",
                    delivery.leased_until.is_not(None),
                    delivery.leased_until < moment,
                )
            ),
        )
    )

    # ── Ages. Omitted when there is nothing to measure. ─────────────────────
    oldest_due = db.execute(
        sa.select(sa.func.min(delivery.next_attempt_at)).where(*due_predicate)
    ).scalar_one_or_none()
    _append_age(
        samples, "integrator_delivery_oldest_due_age_seconds", moment, oldest_due
    )

    oldest_unprocessed = db.execute(
        sa.select(sa.func.min(receipt.received_at)).where(
            receipt.state.notin_(("processed", "dead_letter"))
        )
    ).scalar_one_or_none()
    _append_age(
        samples,
        "integrator_receipt_oldest_unprocessed_age_seconds",
        moment,
        oldest_unprocessed,
    )

    # `advanced_at` is NULL until a cursor first moves, and a checkpoint that
    # has never advanced is the worst case rather than the absent one — so it
    # falls back to when the row was created.
    oldest_checkpoint = db.execute(
        sa.select(
            sa.func.min(sa.func.coalesce(checkpoint.advanced_at, checkpoint.created_at))
        )
    ).scalar_one_or_none()
    _append_age(
        samples, "integrator_checkpoint_oldest_lag_seconds", moment, oldest_checkpoint
    )

    # ── Payload-retention backlog ───────────────────────────────────────────
    retained = (
        receipt.payload_json.is_not(None),
        receipt.payload_json[REDACTION_MARKER].is_(None),
    )
    samples.append(
        Sample(
            "integrator_receipt_retained_payloads",
            float(_count(db, receipt, *retained)),
        )
    )
    oldest_retained = db.execute(
        sa.select(sa.func.min(receipt.received_at)).where(*retained)
    ).scalar_one_or_none()
    _append_age(
        samples,
        "integrator_receipt_oldest_retained_payload_age_seconds",
        moment,
        oldest_retained,
    )

    return samples


def _count(db: Session, model: type[Any], *where: Any) -> int:
    query = sa.select(sa.func.count()).select_from(model).where(*where)
    return int(db.execute(query).scalar_one() or 0)


def _append_age(
    samples: list[Sample], family: str, moment: datetime, stamp: datetime | None
) -> None:
    age = _age_seconds(moment, stamp)
    if age is not None:
        samples.append(Sample(family, age))


def collect(engine: Engine, worker: Any | None = None) -> list[Sample]:
    """Everything this process can say about itself, right now."""
    with Session(engine) as db:
        samples = snapshot(db)
    samples.extend(counters.samples())
    if worker is not None:
        samples.append(
            Sample("integrator_worker_running", 1.0 if worker.running else 0.0)
        )
        last = getattr(worker, "last_sweep_epoch", None)
        if last is not None:
            samples.append(
                Sample("integrator_worker_last_sweep_timestamp_seconds", float(last))
            )
    return samples


# ── Rendering ───────────────────────────────────────────────────────────────


def _lines(samples: Iterable[Sample]) -> Iterator[str]:
    grouped: dict[str, list[Sample]] = {}
    for sample in samples:
        family = _BY_NAME.get(sample.family)
        if family is None:
            raise UndeclaredLabel(
                f"{sample.family!r} is not a declared metric family. Declare it "
                "in FAMILIES, with its complete allowed label set"
            )
        if family.label is None and sample.label_value is not None:
            raise UndeclaredLabel(
                f"{family.name} takes no label, but a sample carried "
                f"{sample.label_value!r}"
            )
        if family.label is not None and sample.label_value not in family.allowed:
            # THE guard. A `provider_event_id`, an endpoint key or a phone
            # number reaches this branch and stops here, rather than reaching a
            # time series database that keeps it for a year.
            raise UndeclaredLabel(
                f"{sample.label_value!r} is not a declared value for "
                f"{family.name}{{{family.label}}}. Allowed: {sorted(family.allowed)}. "
                "A label set that accepts arbitrary values is how an identifier "
                "leaks into every dashboard that renders it"
            )
        grouped.setdefault(sample.family, []).append(sample)

    for family in FAMILIES:
        rows = grouped.get(family.name)
        if not rows:
            continue
        yield f"# HELP {family.name} {family.help}"
        yield f"# TYPE {family.name} {family.kind}"
        for sample in rows:
            if family.label is None:
                yield f"{family.name} {sample.value:g}"
            else:
                labels = f'{{{family.label}="{sample.label_value}"}}'
                yield f"{family.name}{labels} {sample.value:g}"


def render(samples: Iterable[Sample]) -> str:
    """Prometheus text exposition, hand-rendered.

    Hand-rendered rather than through a client library: this assembly pins its
    dependencies exactly, the format is a dozen lines, and pulling in a registry
    would add a global mutable singleton whose label API accepts any string —
    which is precisely the property this file exists to remove.
    """
    return "\n".join(_lines(samples)) + "\n"


def scrape(engine: Engine, worker: Any | None = None) -> str:
    """Collect and render in one call, for the `/metrics` handler."""
    return render(collect(engine, worker))


def now_epoch() -> float:
    """Wall-clock seconds, isolated so the worker can be tested without sleeping."""
    return time.time()
