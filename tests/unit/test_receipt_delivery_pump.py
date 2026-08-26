"""The pump drives the module's claim; it does not own one.

`ReceiptClaims` and `deliver_receipt` are `dotmac_integration`'s, and the
at-most-once property is theirs: a conditional UPDATE where ``rowcount == 1``
IS the claim, and three phases with no session held across the network. What is
testable HERE is that this assembly drives them faithfully — the ordering
survives, a lost claim does not kill the loop, and an unclaimed receipt is a
normal outcome rather than an error.

The claim's RACE is not testable here and is not claimed to be: the statement
uses `make_interval`, so it runs on PostgreSQL and its canaries live with the
module. What SQLite proves is control flow.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import dotmac_integration as integration
import pytest
from sqlalchemy import create_engine

from dotmac_integrator import delivery, telemetry


class _Scope:
    kind = "team"
    ref = "inbox-1"


class _Destination:
    capability_binding_id = uuid4()
    capability_id = "messaging.receive.v1"
    application = "sub"
    scope = _Scope()
    contract_version = 1
    destination_revision_id = uuid4()


def _claim(receipt_id: UUID, attempt: int = 1) -> integration.ReceiptClaim:
    return integration.ReceiptClaim(
        receipt_id=receipt_id,
        attempt=attempt,
        leased_until=datetime.now(UTC) + timedelta(minutes=5),
        destination=_Destination(),
        provider_event_id=f"provider-{receipt_id}",
        event_type="message.received",
        observation={"messages": []},
        correlation_id=str(receipt_id),
    )


class _Store:
    """A `ReceiptClaimStore`, recording the ORDER it was driven in."""

    def __init__(self, *, claimable: bool = True, settles: bool = True) -> None:
        self.calls: list[str] = []
        self._claimable = claimable
        self._settles = settles

    def claim(
        self, *, receipt_id: UUID, now: datetime | None = None
    ) -> integration.ReceiptClaim | None:
        self.calls.append("claim")
        return _claim(receipt_id) if self._claimable else None

    def settle(
        self, claim: integration.ReceiptClaim, outcome: integration.ProductOutcome
    ) -> bool:
        self.calls.append("settle")
        return self._settles


class _Gateway:
    def __init__(self, outcome: integration.ProductOutcome, log: list[str]) -> None:
        self._outcome = outcome
        self._log = log

    def deliver(
        self, request: integration.ProductRequest
    ) -> integration.ProductOutcome:
        self._log.append("deliver")
        return self._outcome


ACCEPTED = integration.ProductOutcome(acceptance=integration.ProductAcceptance.ACCEPTED)

#: Never connected, and never dialled: the refusal below is decided before a
#: query would be issued, which is exactly why it belongs in `tests/unit`.
#: `create_engine` is lazy, so constructing one costs nothing.
_UNUSED_ENGINE = create_engine(
    "postgresql+psycopg://platform_api@127.0.0.1:1/integrator_test"
)


def _reset_port() -> None:
    """Put the module-level holder back. It is process-wide state, so a test
    that installed a port and left it there would decide the next test's
    outcome."""
    delivery._PORT = None
    delivery._REGISTRY = None


def test_the_claim_commits_before_the_product_is_contacted() -> None:
    """The phase boundary, asserted as an ORDER.

    A network call inside the claim transaction holds a row lock for the
    duration of someone else's outage: one slow product and the connection pool
    is gone, having done no work. `deliver_receipt` guarantees the ordering; this
    asserts the assembly did not defeat it by, say, wrapping the call.
    """
    store = _Store()
    gateway = _Gateway(ACCEPTED, store.calls)

    report = integration.deliver_receipt(
        receipt_id=uuid4(), store=store, gateway=gateway
    )

    assert store.calls == ["claim", "deliver", "settle"]
    assert report.claimed is True


def test_an_unclaimed_receipt_is_a_value_and_never_reaches_the_product() -> None:
    """Two workers sweeping one queue is the NORMAL case — the selector is a
    hint and the conditional UPDATE is the decision, so the loser must simply
    move on. Contacting the product anyway would deliver a receipt this worker
    does not hold, on top of whichever worker legitimately does."""
    store = _Store(claimable=False)
    gateway = _Gateway(ACCEPTED, store.calls)

    report = integration.deliver_receipt(
        receipt_id=uuid4(), store=store, gateway=gateway
    )

    assert report.claimed is False
    assert "deliver" not in store.calls
    assert report.unclaimed_reason


def test_a_lost_claim_is_raised_rather_than_silently_succeeding() -> None:
    """`rowcount == 0` on settle is the database saying this worker was
    superseded. Swallowing it would make a worker that failed to record its
    outcome look exactly like one that succeeded."""
    store = _Store(settles=False)
    gateway = _Gateway(ACCEPTED, store.calls)

    with pytest.raises(integration.LostClaim):
        integration.deliver_receipt(receipt_id=uuid4(), store=store, gateway=gateway)


def test_a_transport_failure_becomes_a_retryable_outcome_not_an_exception() -> None:
    """Safe to retry because the idempotency key is stable across attempts —
    attempt 2 presents the key attempt 1 did, so a product that already
    committed answers ALREADY_APPLIED rather than acting twice."""
    store = _Store()

    class _Failing:
        def deliver(
            self, request: integration.ProductRequest
        ) -> integration.ProductOutcome:
            raise integration.TransportFailure("connection reset")

    report = integration.deliver_receipt(
        receipt_id=uuid4(), store=store, gateway=_Failing()
    )
    assert report.claimed is True
    assert report.outcome is not None
    assert report.outcome.acceptance is integration.ProductAcceptance.UNAVAILABLE


def test_the_idempotency_key_does_not_carry_the_attempt_number() -> None:
    """The whole at-most-once property. A key carrying the attempt would make
    every retry a fresh consequence, turning the retry curve into a duplication
    machine — a timeout after the product committed would then act twice."""
    receipt_id = uuid4()
    first = integration.build_product_request(_claim(receipt_id, attempt=1))
    second = integration.build_product_request(_claim(receipt_id, attempt=4))
    assert first.idempotency_key == second.idempotency_key


# ── The port is a seam, and it fails closed ─────────────────────────────────


def test_an_object_without_deliver_is_refused_at_install_not_mid_claim() -> None:
    with pytest.raises(delivery.ProductPortNotInstalled):
        delivery.install_product_port(object(), registry=integration.EMPTY_REGISTRY)


def test_a_port_that_does_not_declare_its_direction_is_refused_at_install() -> None:
    """Required, never defaulted.

    Defaulting `writes` to True would let a client for the destination's SHADOW
    port — which records nothing — settle receipts as `processed`; defaulting it
    to False would silently stop a real deployment. Neither default is safe, so
    a port that does not say is not installed.
    """

    class _Undeclared:
        def deliver(
            self, request: integration.ProductRequest
        ) -> integration.ProductOutcome:
            return ACCEPTED

    with pytest.raises(delivery.ProductPortNotInstalled) as refused:
        delivery.install_product_port(
            _Undeclared(), registry=integration.EMPTY_REGISTRY
        )
    assert "writes" in str(refused.value)


def test_the_delivery_pump_refuses_to_run_against_a_shadow_port() -> None:
    """The worst available failure is a shadow run that looks like a cutover.

    The destination's shadow port records NOTHING, so every receipt the pump
    settled against it would be marked delivered for an observation the
    destination never saw — and it would look exactly like a successful
    migration while the events were being lost.
    """

    class _Shadow:
        writes = False

        def deliver(
            self, request: integration.ProductRequest
        ) -> integration.ProductOutcome:  # pragma: no cover - never reached
            raise AssertionError("a shadow port must never be asked to deliver")

    delivery.install_product_port(_Shadow(), registry=integration.EMPTY_REGISTRY)
    try:
        assert delivery.product_port_installed() is True
        assert delivery.product_port_writes() is False
        with pytest.raises(delivery.ShadowPortInstalled):
            delivery.deliver_due_receipts(_UNUSED_ENGINE, limit=1)
    finally:
        _reset_port()


def test_a_writing_port_declares_so_and_the_pump_accepts_it() -> None:
    """Read positively: the refusal above would also pass over an install that
    rejected everything."""

    class _Writer:
        writes = True

        def deliver(
            self, request: integration.ProductRequest
        ) -> integration.ProductOutcome:  # pragma: no cover - not driven here
            return ACCEPTED

    delivery.install_product_port(_Writer(), registry=integration.EMPTY_REGISTRY)
    try:
        assert delivery.product_port_writes() is True
    finally:
        _reset_port()


def test_the_pump_refuses_rather_than_marking_receipts_done_with_no_port() -> None:
    """Fail closed, and loudly. "Nothing to do" would be a control plane that
    answered 200 to the provider and then quietly dropped the events — the
    provider will not send them again."""
    with pytest.raises(delivery.ProductPortNotInstalled):
        delivery.product_port()


def test_the_delivery_vocabulary_is_the_MODULES_own() -> None:
    assert set(telemetry.PRODUCT_ACCEPTANCES) == {
        acceptance.value for acceptance in integration.ProductAcceptance
    }
    # `already_applied` is the EVIDENCE the idempotency key worked. Collapsing
    # it into `accepted` would hide a double-send behind a success, and
    # `indeterminate` says retrying is NOT safe — the opposite instruction to
    # `unavailable`. An alert that cannot tell them apart pages for the wrong
    # reason.
    assert "already_applied" in telemetry.PRODUCT_ACCEPTANCES
    assert "indeterminate" in telemetry.PRODUCT_ACCEPTANCES


def test_a_receipt_identifier_cannot_become_a_delivery_label() -> None:
    with pytest.raises(telemetry.UndeclaredLabel):
        telemetry.counters.record_product_acceptance(str(uuid4()))
