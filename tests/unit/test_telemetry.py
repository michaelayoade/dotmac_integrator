"""What the metrics say, and what they deliberately refuse to say.

The two behaviours worth defending here:

* **a count alone hides one stuck item.** Every backlog that can age reports a
  depth AND the age of its oldest member, and the age is what the alerts fire
  on. A queue of one receipt stuck since March looks identical to a healthy
  queue of one until you ask how old it is.
* **an age with nothing to measure is ABSENT, not zero.** Zero means "the
  oldest due delivery is due right now" — the healthiest possible reading of
  the unhealthiest possible cause, which is no data at all.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import dotmac_integration as integration
import pytest
from sqlalchemy import Table, create_engine
from sqlalchemy.orm import Session

from dotmac_integrator import telemetry
from dotmac_integrator.telemetry import (
    DELIVERY_STATES,
    RECEIPT_STATES,
    IngressCounters,
    Sample,
    render,
    snapshot,
)

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)


@pytest.fixture()
def db() -> Iterator[Session]:
    """SQLite standing in for the platform plane.

    Tenancy and privilege isolation are not testable here and are not what these
    tests claim — the `mod_intg` catalog contract is audited against a real
    PostgreSQL in the Starter. What SQLite proves is the SHAPE of the queries
    and of the rendered exposition, which is all a metric needs to be right.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        execution_options={"schema_translate_map": {"mod_intg": None}},
    )
    for model in (
        integration.ConnectorInstallation,
        integration.CapabilityBinding,
        integration.InboxReceipt,
        integration.DeliveryAttempt,
        integration.PollingCheckpoint,
    ):
        # `Table.create`, reached through the declarative `__table__`, which the
        # checker types as the abstract `FromClause`. Narrowed rather than
        # ignored: this is a real Table and saying so keeps strict mode honest.
        table = model.__table__
        assert isinstance(table, Table)
        table.create(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture()
def binding(db: Session) -> integration.CapabilityBinding:
    import uuid

    installation = integration.ConnectorInstallation(
        id=uuid.uuid4(),
        connector_key="conformance_fake",
        connector_version="1.0.0",
        spi_range=">=1.0,<2.0",
        manifest_digest="d" * 64,
        name="primary",
        state="enabled",
    )
    db.add(installation)
    db.flush()
    record = integration.CapabilityBinding(
        id=uuid.uuid4(),
        installation_id=installation.id,
        capability_id="message.observation.v1",
        state="enabled",
    )
    db.add(record)
    db.flush()
    return record


def _value(
    samples: list[Sample], family: str, label: str | None = None
) -> float | None:
    for sample in samples:
        if sample.family == family and sample.label_value == label:
            return sample.value
    return None


# ── Depths ──────────────────────────────────────────────────────────────────


def test_every_declared_state_gets_a_series_even_at_zero(
    db: Session, binding: integration.CapabilityBinding
) -> None:
    """The opposite choice from the age gauges, for the opposite reason: an
    ABSENT `dead_letter` series makes an alert on it silently never fire."""
    samples = snapshot(db, now=NOW)
    for state in DELIVERY_STATES:
        assert _value(samples, "integrator_delivery_queue_depth", state) == 0.0
    for state in RECEIPT_STATES:
        assert _value(samples, "integrator_receipt_queue_depth", state) == 0.0


def test_the_module_owns_the_health_verdict_and_this_process_transports_it(
    db: Session, binding: integration.CapabilityBinding
) -> None:
    """Every field of the module's own report becomes a series, and nothing
    here recomputes one. Two answers to "is this stuck" is the parallel
    authority ADR-0024 forbids."""
    samples = snapshot(db, now=NOW)
    for signal in integration.health_report(db).as_dict():
        assert _value(samples, "integrator_health_signal", signal) is not None


# ── Ages: the half a count cannot tell you ──────────────────────────────────


def test_an_age_gauge_is_absent_rather_than_zero_when_nothing_is_waiting(
    db: Session, binding: integration.CapabilityBinding
) -> None:
    samples = snapshot(db, now=NOW)
    for family in (
        "integrator_delivery_oldest_due_age_seconds",
        "integrator_receipt_oldest_unprocessed_age_seconds",
        "integrator_checkpoint_oldest_lag_seconds",
        "integrator_receipt_oldest_retained_payload_age_seconds",
    ):
        assert _value(samples, family) is None, (
            f"{family} reported a value with nothing to measure. Zero reads as "
            "'due right now', which is the healthiest interpretation of no data"
        )


def test_one_ancient_receipt_shows_up_as_an_age_not_just_a_count(
    db: Session, binding: integration.CapabilityBinding
) -> None:
    """The whole argument for the age gauges, in one test. The depth is 1 —
    indistinguishable from a healthy queue — and the age is five months."""
    receipt, _ = integration.receive_verified(
        db,
        installation_id=binding.installation_id,
        capability_binding_id=binding.id,
        provider_event_id="wamid.STUCK",
        event_type="message.received",
        payload={"messages": []},
    )
    receipt.received_at = NOW - timedelta(days=150)
    receipt.state = "retryable"
    db.flush()

    samples = snapshot(db, now=NOW)

    assert _value(samples, "integrator_receipt_queue_depth", "retryable") == 1.0
    age = _value(samples, "integrator_receipt_oldest_unprocessed_age_seconds")
    assert age == timedelta(days=150).total_seconds()


def test_queue_lag_measures_the_oldest_due_delivery(
    db: Session, binding: integration.CapabilityBinding
) -> None:
    delivery, _ = integration.enqueue_delivery(
        db,
        installation_id=binding.installation_id,
        event_type="message.send",
        idempotency_key="k-1",
        payload={"body": "x"},
    )
    delivery.next_attempt_at = NOW - timedelta(minutes=42)
    db.flush()

    samples = snapshot(db, now=NOW)

    assert _value(samples, "integrator_delivery_due") == 1.0
    assert _value(samples, "integrator_delivery_oldest_due_age_seconds") == 42 * 60


def test_a_live_lease_and_an_expired_one_are_different_numbers(
    db: Session, binding: integration.CapabilityBinding
) -> None:
    """Conflating them is how a dead worker looks busy."""
    live, _ = integration.enqueue_delivery(
        db,
        installation_id=binding.installation_id,
        event_type="message.send",
        idempotency_key="live",
        payload={"body": "x"},
    )
    live.state = "in_flight"
    live.leased_until = NOW + timedelta(minutes=4)
    stranded, _ = integration.enqueue_delivery(
        db,
        installation_id=binding.installation_id,
        event_type="message.send",
        idempotency_key="stranded",
        payload={"body": "y"},
    )
    stranded.state = "in_flight"
    stranded.leased_until = NOW - timedelta(minutes=4)
    db.flush()

    samples = snapshot(db, now=NOW)

    assert _value(samples, "integrator_delivery_leased") == 1.0
    assert _value(samples, "integrator_delivery_lease_expired") == 1.0


# ── Payload-retention backlog ───────────────────────────────────────────────


def test_a_redacted_payload_leaves_the_retention_backlog(
    db: Session, binding: integration.CapabilityBinding
) -> None:
    """The backlog counts receipts still holding REAL content. A tombstone is
    not content, and counting it would make the metric never fall.

    The marker is matched as a literal because the pinned module release
    predates the retention slice; the Starter pins the same literal, so the two
    cannot drift silently.
    """
    kept, _ = integration.receive_verified(
        db,
        installation_id=binding.installation_id,
        capability_binding_id=binding.id,
        provider_event_id="wamid.KEPT",
        event_type="message.received",
        payload={"messages": []},
    )
    kept.received_at = NOW - timedelta(days=200)
    aged, _ = integration.receive_verified(
        db,
        installation_id=binding.installation_id,
        capability_binding_id=binding.id,
        provider_event_id="wamid.AGED",
        event_type="message.received",
        payload={"messages": []},
    )
    aged.received_at = NOW - timedelta(days=400)
    aged.payload_json = {telemetry.REDACTION_MARKER: {"redacted_at": "2026-08-01"}}
    db.flush()

    samples = snapshot(db, now=NOW)

    assert _value(samples, "integrator_receipt_retained_payloads") == 1.0
    assert (
        _value(samples, "integrator_receipt_oldest_retained_payload_age_seconds")
        == timedelta(days=200).total_seconds()
    )


def test_the_retention_metric_carries_no_period(
    db: Session, binding: integration.CapabilityBinding
) -> None:
    """The gauge is an AGE, not a breach. "How old is too old" is the
    deployment's decision and lives in the alert rule — putting a period here
    would fork it from the module that enforces it."""
    for family in telemetry.FAMILIES:
        if "retention" in family.name or "retained" in family.name:
            assert "days" not in family.name
            assert not any(ch.isdigit() for ch in family.name)


# ── Rendering ───────────────────────────────────────────────────────────────


def test_the_exposition_carries_help_and_type_for_every_family_it_emits() -> None:
    output = render([Sample("integrator_delivery_due", 3.0)])
    assert "# HELP integrator_delivery_due" in output
    assert "# TYPE integrator_delivery_due gauge" in output
    assert "integrator_delivery_due 3" in output
    assert output.endswith("\n")


def test_a_family_with_no_samples_emits_no_header() -> None:
    """A `# HELP` with nothing under it is a metric that looks scraped and
    carries nothing."""
    output = render([Sample("integrator_delivery_due", 1.0)])
    assert "integrator_receipt_queue_depth" not in output


def test_counters_render_under_their_declared_labels() -> None:
    counters = IngressCounters()
    counters.record_refusal("signature_invalid")
    counters.record_refusal("signature_invalid")
    counters.record_signature("rejected")
    counters.record_challenge("refused")

    output = render(counters.samples())

    assert 'integrator_ingress_refusals_total{reason="signature_invalid"} 2' in output
    assert (
        'integrator_ingress_signature_verifications_total{outcome="rejected"} 1'
        in output
    )
    assert 'integrator_ingress_challenges_total{outcome="refused"} 1' in output


def test_every_declared_refusal_reason_gets_a_series_from_the_first_scrape() -> None:
    """A counter that appears only after its first increment makes
    `increase()` over the window that contains that increment unusable."""
    output = render(IngressCounters().samples())
    for reason in telemetry.REFUSAL_REASONS:
        assert f'reason="{reason}"' in output


def test_the_sweep_failure_counter_is_exported() -> None:
    """The loop survives a failed sweep, which is exactly what makes it
    invisible: the process stays healthy and nothing gets released."""
    counters = IngressCounters()
    counters.record_sweep_failure()
    assert "integrator_worker_sweep_failures_total 1" in render(counters.samples())
