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
import secrets
import threading
import time
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

import dotmac_integration as integration
import sqlalchemy as sa
from fastapi import HTTPException, Request
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

__all__ = [
    "CHALLENGE_OUTCOMES",
    "DELIVERY_STATES",
    "FAMILIES",
    "HEALTH_SIGNALS",
    "INGRESS_CODES",
    "PRODUCT_ACCEPTANCES",
    "RECEIPT_STATES",
    "REDACTION_MARKER",
    "REFUSAL_REASONS",
    "SIGNATURE_OUTCOMES",
    "VERIFICATION_KEY_POSITIONS",
    "IngressCounters",
    "MetricFamily",
    "ScrapeGuard",
    "Sample",
    "UndeclaredLabel",
    "collect",
    "counters",
    "now_epoch",
    "render",
    "scrape",
    "scrape_is_authorized",
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
    # The OPERATOR surface: the request was authentic and still could not be
    # served. Ingress refusals are NOT here — see `INGRESS_CODES` below.
    "malformed_identifier",
    "not_found",
    "not_repairable",
)

#: Every outcome the ingress engine can reach, success and refusal alike,
#: sourced from `dotmac_integration.IngressCode` rather than restated.
#:
#: This REPLACED six hand-written reasons ("signature_invalid",
#: "unknown_target", "replay_window_expired" and three more) that were declared
#: before the ingress adapter existed. Not one of them was a name the engine
#: actually produces, so the vocabulary they described was a guess — and the
#: guess would have been discovered by an operator reading a dashboard that
#: never moved, months after the alert on it was written.
#:
#: Read from the enum for the reason `DELIVERY_STATES` is read from a CHECK
#: constraint: a second hand-maintained list drifts, and a drifted list means a
#: real outcome with no series at all. Adding an outcome to the module now adds
#: its series here with no edit; the closed set stays closed because the enum is.
INGRESS_CODES: Final[tuple[str, ...]] = tuple(
    sorted(code.value for code in integration.IngressCode)
)

#: What the destination application said about a delivered observation, from
#: `dotmac_integration.ProductAcceptance` rather than restated. Five values,
#: and the two that look redundant are the interesting ones: `already_applied`
#: is the EVIDENCE that the idempotency key did its job — collapsing it into
#: `accepted` would hide a double-send behind a success — and `indeterminate`
#: says retrying is NOT safe, which is the opposite instruction to
#: `unavailable`. An alert that cannot tell those apart is an alert that pages
#: for the wrong reason.
PRODUCT_ACCEPTANCES: Final[tuple[str, ...]] = tuple(
    sorted(acceptance.value for acceptance in integration.ProductAcceptance)
)

#: A signature was checked and it either verified or it did not. Two values, and
#: deliberately not a third: "error" would collapse "we could not check" into
#: "it failed", and those need different alerts.
SIGNATURE_OUTCOMES: Final[tuple[str, ...]] = ("accepted", "rejected")

#: Bounded projection of SPI 1.2's ordered matched positions. The raw integer
#: cannot become a label (and therefore cannot create unbounded cardinality),
#: while ``first`` versus ``later`` still answers whether rotation traffic has
#: drained from older verification material.
VERIFICATION_KEY_POSITIONS: Final[tuple[str, ...]] = ("first", "later")

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
#: payload. IMPORTED, not restated: the metric counts receipts that do NOT
#: carry this key, so a copy that drifted by one character would count every
#: redacted row as still holding content and the backlog would never fall.
#:
#: It was a local literal while the pin was `0.1.0a1`, which predates the
#: retention module. `0.1.0a3` exports it, so the copy is gone — which was the
#: instruction the literal carried, not a nice-to-have.
REDACTION_MARKER: Final = integration.REDACTION_MARKER


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
    # ── Receipt → product delivery ──────────────────────────────────────────
    MetricFamily(
        "integrator_receipt_deliveries_total",
        "Receipts landed in the destination application, by what the product "
        "said. `already_applied` is the idempotency key working, not a "
        "duplicate; `indeterminate` needs a human.",
        "counter",
        label="acceptance",
        allowed=PRODUCT_ACCEPTANCES,
    ),
    MetricFamily(
        "integrator_receipt_lost_claims_total",
        "Settlements refused because the lease expired mid-call and another "
        "worker took over. A rising rate means the lease is shorter than the "
        "product's real latency — invisible otherwise, and eventually work "
        "done twice.",
        "counter",
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
    MetricFamily(
        "integrator_worker_dispatch_failures_total",
        "Outbound dispatch passes that raised. Kept distinct from lease sweep "
        "failures because the operator remedies are different.",
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
        "integrator_ingress_outcomes_total",
        "Inbound provider requests by the ENGINE's own outcome code. Includes "
        "the success codes: a refusal rate is meaningless without a "
        "denominator, and 'accepted' falling to zero is the interesting alert.",
        "counter",
        label="code",
        allowed=INGRESS_CODES,
    ),
    MetricFamily(
        "integrator_ingress_signature_verifications_total",
        "Signature checks, by outcome.",
        "counter",
        label="outcome",
        allowed=SIGNATURE_OUTCOMES,
    ),
    MetricFamily(
        "integrator_ingress_verification_key_matches_total",
        "Authenticated checks by ordered verification-key position class.",
        "counter",
        label="position",
        allowed=VERIFICATION_KEY_POSITIONS,
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
        self._verification_key_matches: dict[str, int] = dict.fromkeys(
            VERIFICATION_KEY_POSITIONS, 0
        )
        self._challenges: dict[str, int] = dict.fromkeys(CHALLENGE_OUTCOMES, 0)
        self._ingress: dict[str, int] = dict.fromkeys(INGRESS_CODES, 0)
        self._acceptances: dict[str, int] = dict.fromkeys(PRODUCT_ACCEPTANCES, 0)
        self._lost_claims = 0
        self._sweep_failures = 0
        self._dispatch_failures = 0

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

    def record_verification(self, result: integration.VerificationResult) -> None:
        """Count SPI evidence without publishing a raw position or identifier."""
        outcome = "accepted" if result.accepted else "rejected"
        with self._lock:
            self._signatures[outcome] += 1
            for position in result.matched_secret_positions:
                key = "first" if position == 0 else "later"
                self._verification_key_matches[key] += 1

    def record_challenge(self, outcome: str) -> None:
        key = self._checked(outcome, CHALLENGE_OUTCOMES, "challenge outcome")
        with self._lock:
            self._challenges[key] += 1

    def record_ingress_outcome(self, code: str) -> None:
        """One inbound request reached one engine outcome.

        `code` is an `IngressCode` VALUE, and the check refuses anything else —
        which is what keeps a provider's error string, a `provider_event_id` or
        an endpoint key from becoming a time series even though all three are in
        scope a few frames away.
        """
        key = self._checked(code, INGRESS_CODES, "ingress outcome code")
        with self._lock:
            self._ingress[key] += 1

    def record_product_acceptance(self, acceptance: str) -> None:
        key = self._checked(acceptance, PRODUCT_ACCEPTANCES, "product acceptance")
        with self._lock:
            self._acceptances[key] += 1

    def record_lost_claim(self) -> None:
        with self._lock:
            self._lost_claims += 1

    def record_sweep_failure(self) -> None:
        with self._lock:
            self._sweep_failures += 1

    def record_dispatch_failure(self) -> None:
        with self._lock:
            self._dispatch_failures += 1

    def samples(self) -> list[Sample]:
        with self._lock:
            refusals = dict(self._refusals)
            signatures = dict(self._signatures)
            verification_key_matches = dict(self._verification_key_matches)
            challenges = dict(self._challenges)
            ingress = dict(self._ingress)
            acceptances = dict(self._acceptances)
            lost = self._lost_claims
            sweep_failures = self._sweep_failures
            dispatch_failures = self._dispatch_failures
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
                Sample(
                    "integrator_ingress_verification_key_matches_total",
                    count,
                    position,
                )
                for position, count in verification_key_matches.items()
            ),
            *(
                Sample("integrator_ingress_challenges_total", count, outcome)
                for outcome, count in challenges.items()
            ),
            *(
                Sample("integrator_ingress_outcomes_total", count, code)
                for code, count in ingress.items()
            ),
            *(
                Sample("integrator_receipt_deliveries_total", count, acceptance)
                for acceptance, count in acceptances.items()
            ),
            Sample("integrator_receipt_lost_claims_total", lost),
            Sample("integrator_worker_sweep_failures_total", sweep_failures),
            Sample("integrator_worker_dispatch_failures_total", dispatch_failures),
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
    # `.as_string()` is LOAD-BEARING, and its absence was a real defect on this
    # branch. Without it SQLAlchemy renders the extracted element for SQLite as
    # `JSON_QUOTE(JSON_EXTRACT(...))`, and `JSON_QUOTE(NULL)` returns the STRING
    # 'null' rather than SQL NULL — so `IS NULL` was never true, the predicate
    # matched NOTHING, and the backlog gauge read a permanent, reassuring zero.
    #
    # It rendered correctly on PostgreSQL (`payload_json -> 'k'` really is SQL
    # NULL for a missing key), which is exactly what makes the class of bug
    # dangerous: the metric would have been right in production and wrong in
    # every test, so the natural repair is to "fix the test" and delete the
    # only signal that the query is dialect-sensitive at all.
    #
    # `dotmac_integration.retention._expired_with_content` carries the identical
    # predicate, with the identical `.as_string()`, for the identical reason.
    # Two copies of one predicate is the smell; they cannot be collapsed until
    # the pin moves to a release that exports it (see `REDACTION_MARKER`).
    retained = (
        receipt.payload_json.is_not(None),
        receipt.payload_json[REDACTION_MARKER].as_string().is_(None),
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


#: Hosts a scrape may come from when no token is configured. The fail-closed
#: fallback, not a convenience: a `/metrics` with neither a token nor a client
#: restriction publishes queue depths, dead-letter counts and this deployment's
#: operational shape to anyone who can reach the port.
_LOOPBACK: Final[frozenset[str]] = frozenset({"127.0.0.1", "::1", "localhost"})


def scrape_is_authorized(
    *, token: str | None, authorization: str | None, client_host: str | None
) -> bool:
    """The fleet's observability auth standard, as one testable predicate.

    `Authorization: Bearer <METRICS_TOKEN>`, compared in CONSTANT TIME. The
    caller answers 404 rather than 403 on a false — a 403 is an oracle telling
    a prober the endpoint exists.

    With no token configured this falls back to loopback only, never to open.
    A deployment that wants no scrape endpoint sets `METRICS_ENABLED=false`;
    an unset token is a half-configured deployment, and half-configured must
    mean closed. `validate_settings` makes it fatal in production rather than
    letting a routable replica sit on the loopback fallback, which would be an
    endpoint nobody can scrape on a port anybody can reach.

    Written as a pure function so it can be driven with a wrong token, a
    right token, a missing header and a remote client without an HTTP client
    in the loop.
    """
    if token is None or not token.strip():
        return client_host in _LOOPBACK
    if not authorization:
        return False
    scheme, _, presented = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return False
    # `compare_digest`, not `==`. String equality returns early on the first
    # differing byte, and the timing of that is a byte-at-a-time oracle over
    # the token.
    return secrets.compare_digest(presented.strip(), token.strip())


class ScrapeGuard:
    """`scrape_is_authorized` as a DEPENDENCY, so the surface auditor can see it.

    An instance rather than a closure because `surface.audit_routes` identifies
    guards structurally, by walking a route's dependency tree. A check performed
    in the handler BODY — which is what this replaced — is invisible to that
    walk, so a future `/metrics` variant mounted without any authentication at
    all would have audited clean. The guard being a dependency is what makes
    "every scrape route authenticates" a property of the surface rather than a
    property of one handler someone remembered to write.

    It raises **404**, and the body is FastAPI's own `{"detail": "Not Found"}`
    rather than a hand-written one. That is the second half of the same
    reasoning that chose 404 over 403: a 403 tells a prober the path exists, and
    so does a 404 whose body does not match what this application returns for a
    path that genuinely does not exist. Unauthorized is now byte-identical to
    absent.
    """

    def __init__(self, settings: Any) -> None:
        self._settings = settings

    def __call__(self, request: Request) -> None:
        if not scrape_is_authorized(
            token=self._settings.metrics_token,
            authorization=request.headers.get("authorization"),
            client_host=request.client.host if request.client else None,
        ):
            raise HTTPException(status_code=404, detail="Not Found")
