"""The destination credential reaches no log, no traceback and no metric label.

ADR-0009 says a secret is HELD and its VALUE is never written down. The
destination port is where that gets hard, because the credential is presented on
every delivery and the delivery talks to something this deployment does not
control: the destination's own refusal text is third-party content, and a
destination that echoed the credential it had just rejected would put it on this
deployment's receipt row, in its log, and in whatever ships that log.

Three surfaces, three mechanisms, and — per ADR-0018 — three SENSITIVITY PROOFS.
A `not in` assertion passes trivially when the value never had a route there, so
each check below is paired with a demonstration that the same value DOES appear
once the mechanism is removed.

=================== ========================================================
log line / row      `secret_resolver.redact` over every outbound string
frame LOCALS        `del` in a `finally`, so the value is gone before an
                    exception carries the frame out — a standard traceback
                    renders source lines, but an error REPORTER configured
                    to capture locals uploads `frame.f_locals` verbatim
metric label        `telemetry.render`'s closed vocabulary, which refuses a
                    label value nobody declared
=================== ========================================================
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Any
from uuid import UUID

import dotmac_integration as integration
import dotmac_kernel.secret_sources as ks
import pytest
from sqlalchemy import create_engine

from dotmac_integrator import telemetry
from dotmac_integrator.product_port import (
    HttpAnswer,
    ObservationPortClient,
    ProductPortDescriptorReconciler,
    ProductPortMode,
    UrllibTransport,
)
from dotmac_integrator.secret_resolver import redact

#: A credential-shaped string with no other reason to appear anywhere. Long
#: enough to be redactable (`MINIMUM_REDACTABLE_LENGTH`) and distinctive enough
#: that a substring search cannot match it by accident.
CREDENTIAL = "dmk_live_9f3c1a77b2e64d08a5471c6ee0b3d92f"
CREDENTIAL_REF = "env://INTEGRATOR_SECRET_DESTINATION_KEY"

LOCAL_BINDING = UUID("11111111-1111-4111-8111-111111111111")
REMOTE_BINDING = UUID("22222222-2222-4222-8222-222222222222")


@pytest.fixture(autouse=True)
def held_credential() -> Iterator[None]:
    class _Source:
        def load(self) -> Mapping[str, str]:
            return {CREDENTIAL_REF: CREDENTIAL}

    ks.clear_secret_source()
    ks.install_secret_source(_Source())
    yield
    ks.clear_secret_source()


class _Scope:
    kind = "inbox"
    ref = "support"


class _ProductPort:
    delivery_path = f"/api/v1/integration/observations/{REMOTE_BINDING}"
    mirror_path = f"{delivery_path}/mirror"
    activation_state = "enabled"


class _Destination:
    capability_binding_id = LOCAL_BINDING
    capability_id = "messaging.receive.v1"
    application = "sub"
    scope = _Scope()
    contract_version = 1
    destination_revision_id = UUID("44444444-4444-4444-8444-444444444444")
    product_port = _ProductPort()


OBSERVATION: dict[str, object] = {
    "provider": "chat_widget",
    "provider_account_scope": "acct-1",
    "provider_event_id": "evt-1",
    "channel": "chat_widget",
    "observed_at": "2026-08-16T09:30:00+00:00",
    "message": {
        "contact_address": "visitor-1",
        "body": "hello",
        "external_message_id": "evt-1",
    },
}


def _request() -> Any:
    return integration.build_product_request(
        integration.ReceiptClaim(
            receipt_id=UUID("33333333-3333-4333-8333-333333333333"),
            attempt=1,
            leased_until=datetime.now(UTC) + timedelta(minutes=5),
            destination=_Destination(),
            provider_event_id=str(OBSERVATION["provider_event_id"]),
            event_type="messaging.receive.v1",
            observation=dict(OBSERVATION),
            correlation_id="corr-1",
        )
    )


def _client(transport: Any) -> ObservationPortClient:
    return ObservationPortClient(
        application="sub",
        base_url="https://destination.example",
        api_key_ref=CREDENTIAL_REF,
        mode=ProductPortMode.WRITE,
        timeout_seconds=1.0,
        transport=transport,
    )


# ── 1. A refusal that quotes the credential ─────────────────────────────────


class _EchoingDestination:
    """A destination that puts the presented credential into its refusal.

    Not a strawman. A gateway logging "invalid key: <key>" and returning that
    string is an ordinary implementation, and it is the case where the caller's
    own redaction is the only thing standing between a credential and a
    permanent row.
    """

    def post(
        self, url: str, *, body: bytes, headers: Mapping[str, str], timeout: float
    ) -> HttpAnswer:
        return HttpAnswer(
            status=401,
            body=json.dumps(
                {
                    "detail": {
                        "code": "unauthorized",
                        "message": f"api key {headers['X-Api-Key']} is not valid",
                    }
                }
            ).encode(),
        )


def test_a_destination_that_echoes_the_credential_cannot_get_it_onto_a_row(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)

    outcome = _client(_EchoingDestination()).deliver(_request())

    assert outcome.acceptance is integration.ProductAcceptance.UNAVAILABLE
    # The row: `error_detail` is written to `inbox_receipts` by the module's
    # settle statement and outlives every log retention policy there is.
    assert CREDENTIAL not in (outcome.error_detail or "")
    assert CREDENTIAL not in (outcome.error_code or "")
    assert "«redacted»" in (outcome.error_detail or "")
    # The log: nothing this delivery emitted may carry it either.
    assert CREDENTIAL not in caplog.text


def test_the_redaction_is_what_removes_it() -> None:
    """Sensitivity proof (ADR-0018) for the check above.

    Without this, the assertion passes identically against a destination that
    never echoed anything — which is the failure mode of every `not in` test.
    """
    echoed = f"api key {CREDENTIAL} is not valid"

    assert CREDENTIAL in echoed
    assert CREDENTIAL not in redact(echoed)


# ── 2. Frame locals ─────────────────────────────────────────────────────────


def _locals_along(exc: BaseException) -> str:
    """Every frame local along the traceback AND the cause chain, rendered.

    Rendered rather than compared by identity because an error reporter renders
    them: what matters is whether the credential is readable in the upload, not
    whether the same object is still referenced.
    """
    rendered: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        traceback: TracebackType | None = current.__traceback__
        while traceback is not None:
            for name, value in traceback.tb_frame.f_locals.items():
                rendered.append(f"{name}={value!r}")
            traceback = traceback.tb_next
        current = current.__cause__ or current.__context__
    return "\n".join(rendered)


def test_no_frame_on_the_failing_path_still_holds_the_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real transport, failing the way a network fails.

    `UrllibTransport.post` builds a `Request` holding the credential and
    `_post` holds the resolved value; both are deleted in a `finally`, which
    runs BEFORE the exception leaves the frame. So by the time an error reporter
    walks this traceback there is nothing left to read.
    """

    def _refuse_to_connect(*_: object, **__: object) -> None:
        raise OSError("connection reset by peer")

    transport = UrllibTransport()
    monkeypatch.setattr(transport._opener, "open", _refuse_to_connect)

    with pytest.raises(integration.TransportFailure) as failure:
        _client(transport).deliver(_request())

    assert CREDENTIAL not in _locals_along(failure.value)
    assert CREDENTIAL not in str(failure.value)


def test_descriptor_fetch_failure_keeps_the_credential_out_of_every_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _refuse_to_connect(*_: object, **__: object) -> None:
        raise OSError("connection reset by peer")

    transport = UrllibTransport()
    monkeypatch.setattr(transport._opener, "open", _refuse_to_connect)
    reconciler = ProductPortDescriptorReconciler(
        engine=create_engine("sqlite+pysqlite:///:memory:"),
        local_binding_id=LOCAL_BINDING,
        descriptor_url="https://destination.example/descriptor",
        expected_digest="a" * 64,
        api_key_ref=CREDENTIAL_REF,
        mode=ProductPortMode.MIRROR,
        timeout_seconds=1.0,
        transport=transport,
    )

    with pytest.raises(integration.TransportFailure) as failure:
        reconciler.reconcile()

    assert CREDENTIAL not in _locals_along(failure.value)
    assert CREDENTIAL not in str(failure.value)


def test_the_frame_local_detector_bites() -> None:
    """Sensitivity proof (ADR-0018).

    A credential held in a frame that raises IS readable through the traceback.
    This is the diff `finally: del` exists to prevent, and without this proof
    the check above would pass over a function that never held one.
    """

    def _keeps_it() -> None:
        headers = {"X-Api-Key": CREDENTIAL}
        raise OSError(f"failed with {len(headers)} headers")

    with pytest.raises(OSError) as leaked:
        _keeps_it()

    assert CREDENTIAL in _locals_along(leaked.value)


# ── 3. Metric labels ────────────────────────────────────────────────────────


def test_the_credential_cannot_become_a_metric_label() -> None:
    """Structural, not a convention: `render` and every counter method refuse a
    value that is not in a closed declared set, so there is no code path that
    would publish one."""
    with pytest.raises(telemetry.UndeclaredLabel):
        telemetry.counters.record_product_acceptance(CREDENTIAL)
    with pytest.raises(telemetry.UndeclaredLabel):
        telemetry.render(
            [telemetry.Sample("integrator_receipt_deliveries_total", 1.0, CREDENTIAL)]
        )


def test_the_label_guard_bites_on_a_declared_value() -> None:
    """Sensitivity proof (ADR-0018): the refusals above are about the VALUE, not
    about the family being unusable. A declared acceptance renders fine."""
    rendered = telemetry.render(
        [telemetry.Sample("integrator_receipt_deliveries_total", 1.0, "accepted")]
    )
    assert 'acceptance="accepted"' in rendered
