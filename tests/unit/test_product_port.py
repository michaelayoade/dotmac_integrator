"""The client against the destination's MERGED port.

Every expectation here is transcribed from `dotmac_sub`'s
`app/api/integrator_observations.py`, `app/schemas/integrator_observation.py`
and `app/services/team_inbox_integrator_envelope.py`. A failure in this file is
either a defect in the client or a contract change in that repository — it is
never a reason to relax an assertion.

Three of these tests are the ones that would otherwise be discovered in
production, at the cost of real customer messages:

* the fingerprint is computed over the destination's OWN canonical body, so a
  sparse observation cannot silently fail every delivery;
* `provider_event_id` crosses the wire RAW, because the destination namespaces
  it and a pre-prefixed id would be a second observation rather than a dedupe;
* a 409 identity collision ESCALATES rather than reporting `already_applied`,
  because the two producers disagree about what the provider said and a human
  has to decide which is wrong.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import dotmac_integration as integration
import dotmac_kernel.secret_sources as ks
import pytest

from dotmac_integrator import product_port
from dotmac_integrator.product_port import (
    EnvelopeNotConstructible,
    HttpAnswer,
    ObservationPortClient,
    ProductPortMode,
    ShadowClientCannotWrite,
    build_envelope,
    canonical_body,
    parse_bindings,
    parse_capabilities,
)

API_KEY_REF = "env://INTEGRATOR_SECRET_DESTINATION_KEY"
API_KEY = "a-destination-machine-credential-0123456789"

LOCAL_BINDING = UUID("11111111-1111-4111-8111-111111111111")
REMOTE_BINDING = UUID("22222222-2222-4222-8222-222222222222")


@pytest.fixture(autouse=True)
def held_credential() -> Iterator[None]:
    """The credential, HELD — which is the only way it is ever available."""

    class _Source:
        def load(self) -> Mapping[str, str]:
            return {API_KEY_REF: API_KEY}

    ks.clear_secret_source()
    ks.install_secret_source(_Source())
    yield
    ks.clear_secret_source()


class _Scope:
    kind = "inbox"
    ref = "support"


class _Destination:
    capability_binding_id = LOCAL_BINDING
    capability_id = "messaging.receive.v1"
    application = "sub"
    scope = _Scope()
    contract_version = 1
    destination_revision_id = uuid4()


class _RecordingTransport:
    """Answers whatever it is told to, and keeps what it was asked."""

    def __init__(self, *answers: HttpAnswer) -> None:
        self._answers = list(answers)
        self.calls: list[dict[str, Any]] = []

    def post(
        self, url: str, *, body: bytes, headers: Mapping[str, str], timeout: float
    ) -> HttpAnswer:
        self.calls.append(
            {"url": url, "body": json.loads(body), "headers": dict(headers)}
        )
        return self._answers.pop(0) if self._answers else _ok()


def _answer(status: int, payload: object, retry_after: str | None = None) -> HttpAnswer:
    return HttpAnswer(
        status=status,
        body=json.dumps(payload).encode(),
        retry_after=retry_after,
    )


def _ok(replayed: bool = False) -> HttpAnswer:
    return _answer(
        200,
        {
            "observation_id": "f0a1b2c3-0000-4000-8000-000000000001",
            "outcome": "recorded",
            "processing_status": "processed",
            "replayed": replayed,
        },
    )


MESSAGE_OBSERVATION: dict[str, object] = {
    "provider": "meta_cloud_api",
    "provider_account_scope": "acct-1",
    "provider_event_id": "wamid.HBgNMjM0",
    "channel": "whatsapp",
    "observed_at": "2026-08-16T09:30:00+00:00",
    "message": {
        "contact_address": "+2348012345678",
        "body": "my line is down",
        "external_message_id": "wamid.HBgNMjM0",
    },
}


def _claim(observation: dict[str, object], attempt: int = 1) -> Any:
    return integration.ReceiptClaim(
        receipt_id=UUID("33333333-3333-4333-8333-333333333333"),
        attempt=attempt,
        leased_until=datetime.now(UTC) + timedelta(minutes=5),
        destination=_Destination(),
        provider_event_id=str(
            observation.get("provider_event_id", "missing-provider-event-id")
        ),
        event_type="messaging.receive.v1",
        observation=observation,
        correlation_id="corr-1",
    )


def _request(observation: dict[str, object] | None = None, attempt: int = 1) -> Any:
    return integration.build_product_request(
        _claim(dict(observation or MESSAGE_OBSERVATION), attempt=attempt)
    )


def _client(
    *answers: HttpAnswer, mode: ProductPortMode = ProductPortMode.WRITE
) -> tuple[ObservationPortClient, _RecordingTransport]:
    transport = _RecordingTransport(*answers)
    return (
        ObservationPortClient(
            application="sub",
            base_url="https://destination.example",
            api_path_prefix="/api/v1",
            remote_bindings={LOCAL_BINDING: REMOTE_BINDING},
            api_key_ref=API_KEY_REF,
            mode=mode,
            timeout_seconds=5.0,
            transport=transport,
        ),
        transport,
    )


# ── The envelope ────────────────────────────────────────────────────────────


def _destination_fingerprint(body: Mapping[str, object]) -> str:
    """The destination's `canonical_fingerprint`, retyped from ITS source.

    Retyped deliberately, and it is the one place in this repository where
    retyping is right: a test that imported the client's own implementation
    would prove the client agrees with itself. This is a transcription of
    `team_inbox_integrator_envelope.canonical_fingerprint`, and it is what the
    destination will actually compute.
    """
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def test_the_canonical_body_carries_every_field_the_destination_dumps() -> None:
    """The failure this prevents costs EVERY delivery, not one.

    The destination recomputes the fingerprint over explicitly supplied fields
    in its model dump. This client supplies one complete representation,
    including null scalar fields and an empty attachment list, and fingerprints
    that exact body rather than the connector's sparse dict.
    """
    slot, body = canonical_body(MESSAGE_OBSERVATION)

    assert slot == "message"
    assert set(body) == {field.name for field in product_port.MESSAGE_FIELDS} | {
        "contact_profile",
        "attachments",
    }
    assert body["contact_name"] is None
    assert body["attachments"] == []
    assert body["contact_profile"] is None


def test_the_fingerprint_matches_what_the_destination_will_compute() -> None:
    envelope = build_envelope(_request())
    _, body = canonical_body(MESSAGE_OBSERVATION)

    assert envelope["payload_fingerprint"] == _destination_fingerprint(body)
    assert (
        envelope[  # the body sent IS the body fingerprinted
            "message"
        ]
        == body
    )


def test_a_sparse_body_would_not_match_and_that_is_why_it_is_expanded() -> None:
    """Sensitivity proof (ADR-0018) for the test above.

    Without it the expansion check passes for the wrong reason: any fingerprint
    over any body matches a fingerprint over the same body. This shows the two
    bodies genuinely differ, so the expansion is load-bearing rather than
    decorative.
    """
    sparse = json.loads(json.dumps(MESSAGE_OBSERVATION))["message"]
    _, expanded = canonical_body(MESSAGE_OBSERVATION)

    assert _destination_fingerprint(sparse) != _destination_fingerprint(expanded)


def test_the_provider_event_id_crosses_the_wire_raw() -> None:
    """The destination prefixes it with its own observation-kind namespace.

    Pre-prefixing here would produce `message:message:…`, a DIFFERENT identity
    from the one the destination's own receiver computes for the same upstream
    event — so the producer-overlap window would double-record every message
    instead of deduplicating it.
    """
    envelope = build_envelope(_request())

    assert envelope["provider_event_id"] == "wamid.HBgNMjM0"
    assert not str(envelope["provider_event_id"]).startswith("message:")


def test_the_envelope_is_addressed_only_from_the_resolved_destination() -> None:
    """Capability, version and scope come from trusted state, never the payload."""
    envelope = build_envelope(_request())

    assert envelope["capability_id"] == "messaging.receive.v1"
    assert envelope["contract_version"] == 1
    assert envelope["scope"] == {"kind": "inbox", "ref": "support"}


def test_transport_evidence_stays_out_of_the_product_port() -> None:
    observation = json.loads(json.dumps(MESSAGE_OBSERVATION))
    observation["transport_evidence"] = {
        "locator": "entry[0].changes[0].value.messages[0]",
        "identity_source": "provider",
        "provider_message_type": "text",
    }
    request = _request(observation)

    envelope = build_envelope(request)

    assert "transport_evidence" not in envelope
    assert (
        request.observation["transport_evidence"] == observation["transport_evidence"]
    )


def test_a_location_only_message_matches_the_destinations_typed_shape() -> None:
    observation = json.loads(json.dumps(MESSAGE_OBSERVATION))
    observation["message"]["body"] = ""
    observation["message"]["attachments"] = [
        {
            "asset_type": "location",
            "location": {
                "latitude": 9.0765,
                "longitude": 7.3986,
                "name": "Abuja",
            },
        }
    ]

    envelope = build_envelope(_request(observation))
    message = envelope["message"]
    assert isinstance(message, dict)
    attachments = message["attachments"]
    assert isinstance(attachments, list)
    attachment = attachments[0]
    assert isinstance(attachment, dict)
    location = attachment["location"]

    assert location == {
        "latitude": 9.0765,
        "longitude": 7.3986,
        "name": "Abuja",
        "address": None,
    }


def test_a_message_with_no_text_and_no_attachment_is_refused_locally() -> None:
    observation = json.loads(json.dumps(MESSAGE_OBSERVATION))
    observation["message"]["body"] = "   "

    with pytest.raises(EnvelopeNotConstructible, match="text or at least one"):
        build_envelope(_request(observation))


def test_the_destination_message_body_limit_is_enforced_before_the_wire() -> None:
    observation = json.loads(json.dumps(MESSAGE_OBSERVATION))
    observation["message"]["body"] = "x" * 10_001

    with pytest.raises(EnvelopeNotConstructible, match="at most 10000"):
        build_envelope(_request(observation))


def test_invalid_coordinates_are_refused_before_the_wire() -> None:
    observation = json.loads(json.dumps(MESSAGE_OBSERVATION))
    observation["message"]["body"] = ""
    observation["message"]["attachments"] = [
        {
            "asset_type": "location",
            "location": {"latitude": 91.0, "longitude": 7.3986},
        }
    ]

    with pytest.raises(EnvelopeNotConstructible, match="latitude"):
        build_envelope(_request(observation))


def test_the_pinned_connector_location_event_constructs_the_sub_envelope() -> None:
    """Discovery → exact-byte verification → normalization → product port.

    This is deployment composition evidence, so it intentionally drives the
    installed plugin rather than importing a connector checkout. Generic source
    stays provider-free; this test proves the exact pinned wheel interoperates
    with the destination contract this deployment implements.
    """
    registry = integration.discover()
    assert len(registry.plugins) == 1
    plugin = registry.plugins[0]
    assert isinstance(plugin, integration.IngressPlugin)
    capability = plugin.manifest.capabilities[0].capability_id
    handler = plugin.ingress_handler_for(capability)
    signing_material = "test-signing-material"
    document = {
        "entry": [
            {
                "id": "account-1",
                "changes": [
                    {
                        "value": {
                            "metadata": {"phone_number_id": "number-1"},
                            "messages": [
                                {
                                    "id": "wamid.location-1",
                                    "from": "2348012345678",
                                    "timestamp": "1786959000",
                                    "type": "location",
                                    "location": {
                                        "latitude": 9.0765,
                                        "longitude": 7.3986,
                                        "name": "Abuja",
                                    },
                                }
                            ],
                        }
                    }
                ],
            }
        ]
    }
    raw = json.dumps(document, separators=(",", ":")).encode()
    signature = (
        "sha256=" + hmac.new(signing_material.encode(), raw, hashlib.sha256).hexdigest()
    )
    ingress_request = integration.IngressRequest(
        raw_body=raw,
        headers={"x-hub-signature-256": signature},
    )
    config: dict[str, object] = {
        "signing_slots": ["active"],
        "handshake_slot": "verify",
    }

    verified = handler.verify(
        ingress_request,
        config=config,
        secrets={"active": signing_material},
    )
    events, _acknowledgement = handler.normalize(ingress_request, config=config)

    assert isinstance(verified, integration.VerificationResult)
    assert verified.accepted
    assert verified.matched_secret_positions == (0,)
    assert len(events) == 1
    assert "transport_evidence" in events[0].payload

    envelope = build_envelope(_request(dict(events[0].payload)))
    message = envelope["message"]
    assert isinstance(message, dict)
    attachments = message["attachments"]
    assert isinstance(attachments, list)
    attachment = attachments[0]
    assert isinstance(attachment, dict)
    location = attachment["location"]
    assert isinstance(location, dict)
    assert location["name"] == "Abuja"
    assert "transport_evidence" not in envelope


def test_a_payload_naming_an_addressing_key_is_refused_rather_than_ignored() -> None:
    """Ignoring it would be safe in the narrow sense — the trusted value still
    wins, because there is no branch that reads addressing out of the payload —
    and it would leave a connector quietly sending a field nobody reads, which
    is how a real disagreement about the contract goes unnoticed."""
    hostile = dict(MESSAGE_OBSERVATION)
    hostile["capability_id"] = "billing.charge.v9"
    hostile["scope"] = {"kind": "inbox", "ref": "somebody-elses"}

    with pytest.raises(EnvelopeNotConstructible) as refused:
        build_envelope(_request(hostile))

    assert "capability_id" in str(refused.value)


def test_an_envelope_carrying_neither_observation_is_refused_before_the_wire() -> None:
    with pytest.raises(EnvelopeNotConstructible):
        build_envelope(_request({"provider": "p", "channel": "c"}))


def test_a_coercible_type_is_refused_rather_than_sent() -> None:
    """A string where an integer is declared is the subtle one.

    The destination's validator COERCES it, so its canonical body would hold
    `512` where ours held `"512"` — and the delivery would fail on a
    fingerprint mismatch, which names neither the field nor the type.
    """
    observation = json.loads(json.dumps(MESSAGE_OBSERVATION))
    observation["message"]["attachments"] = [
        {"asset_type": "image", "file_size": "512"}
    ]

    with pytest.raises(EnvelopeNotConstructible) as refused:
        build_envelope(_request(observation))
    assert "file_size" in str(refused.value)


def test_a_naive_observed_at_is_refused_because_the_destination_refuses_it() -> None:
    observation = json.loads(json.dumps(MESSAGE_OBSERVATION))
    observation["observed_at"] = "2026-08-16T09:30:00"

    with pytest.raises(EnvelopeNotConstructible):
        build_envelope(_request(observation))


# ── Addressing ──────────────────────────────────────────────────────────────


def test_the_url_carries_the_DESTINATIONS_binding_id_not_this_ones() -> None:
    """The two UUIDs live in two databases and are not interchangeable.

    Posting the local one would 404 in the best case and write to somebody
    else's binding in the worst.
    """
    client, transport = _client(_ok())
    client.deliver(_request())

    url = transport.calls[0]["url"]
    assert url == (
        f"https://destination.example/api/v1/integration/observations/{REMOTE_BINDING}"
    )
    assert str(LOCAL_BINDING) not in url


def test_an_unmapped_binding_is_retryable_and_never_reaches_the_wire() -> None:
    """Loud, and non-destructive. Nothing was sent, so retrying is safe, and
    dead-lettering a customer's message over a missing map entry would destroy
    events to punish a typo."""
    transport = _RecordingTransport()
    client = ObservationPortClient(
        application="sub",
        base_url="https://destination.example",
        api_path_prefix="/api/v1",
        remote_bindings={},
        api_key_ref=API_KEY_REF,
        mode=ProductPortMode.WRITE,
        timeout_seconds=5.0,
        transport=transport,
    )

    outcome = client.deliver(_request())

    assert outcome.acceptance is integration.ProductAcceptance.UNAVAILABLE
    assert outcome.error_code == "integrator.destination_not_addressable"
    assert transport.calls == []


def test_a_binding_naming_another_application_is_not_delivered() -> None:
    class _Elsewhere(_Destination):
        application = "erp"

    claim = integration.ReceiptClaim(
        receipt_id=uuid4(),
        attempt=1,
        leased_until=datetime.now(UTC) + timedelta(minutes=5),
        destination=_Elsewhere(),
        provider_event_id=str(MESSAGE_OBSERVATION["provider_event_id"]),
        event_type="messaging.receive.v1",
        observation=dict(MESSAGE_OBSERVATION),
        correlation_id="corr-1",
    )
    client, transport = _client()

    outcome = client.deliver(integration.build_product_request(claim))

    assert outcome.acceptance is integration.ProductAcceptance.UNAVAILABLE
    assert transport.calls == []


def test_the_idempotency_key_is_the_engines_and_survives_a_retry() -> None:
    """The engine derives it from receipt + destination, never the attempt.

    The destination does not read the header — its dedup is the content-derived
    `(binding, provider_event_id)` receipt identity, which is stable across
    attempts for the same reason. Both are asserted, because it is the ENVELOPE
    that carries the at-most-once property here.
    """
    client, transport = _client(_ok(), _ok(replayed=True))
    client.deliver(_request(attempt=1))
    client.deliver(_request(attempt=4))

    first, second = transport.calls
    assert first["headers"]["Idempotency-Key"] == second["headers"]["Idempotency-Key"]
    assert first["body"]["provider_event_id"] == second["body"]["provider_event_id"]
    assert first["body"]["payload_fingerprint"] == second["body"]["payload_fingerprint"]


def test_the_credential_is_presented_as_the_header_the_destination_reads() -> None:
    client, transport = _client(_ok())
    client.deliver(_request())

    assert transport.calls[0]["headers"]["X-Api-Key"] == API_KEY


# ── The acceptance mapping ──────────────────────────────────────────────────


def test_a_first_delivery_is_accepted_and_carries_the_destinations_ref() -> None:
    client, _ = _client(_ok())
    outcome = client.deliver(_request())

    assert outcome.acceptance is integration.ProductAcceptance.ACCEPTED
    assert outcome.consequence_happened
    assert outcome.product_ref == "f0a1b2c3-0000-4000-8000-000000000001"


def test_a_replayed_receipt_is_already_applied_and_not_a_second_accept() -> None:
    """`replayed` is the destination saying it recognised this identity and did
    nothing further — the evidence that the deduplication worked. Collapsing it
    into ACCEPTED would hide a double-send behind a success."""
    client, _ = _client(_ok(replayed=True))
    outcome = client.deliver(_request())

    assert outcome.acceptance is integration.ProductAcceptance.ALREADY_APPLIED
    assert outcome.consequence_happened


def test_an_identity_collision_escalates_rather_than_deduplicating() -> None:
    """THE mapping that must not be got wrong.

    A 409 collision is the observation owner reporting that one provider
    identity carries DIFFERENT evidence — the two producers disagree about what
    the provider said. Reading it as `already_applied` would silently discard
    real content; reading it as retryable would deliver the same disagreement
    again. It needs a human, which is what `INDETERMINATE` means.
    """
    client, _ = _client(
        _answer(
            409,
            {
                "detail": {
                    "code": "integrator_observation_identity_collision",
                    "message": "same identity, different digest",
                }
            },
        )
    )
    outcome = client.deliver(_request())

    assert outcome.acceptance is integration.ProductAcceptance.INDETERMINATE
    assert not outcome.consequence_happened
    assert (
        outcome.as_outcome().status is integration.OutcomeStatus.RECONCILIATION_REQUIRED
    )


def test_the_observation_owners_own_collision_code_escalates_too() -> None:
    """The port maps `record_provider_observation`'s own refusal to 409. The
    owning service raised it; this is not a transport-level duplicate."""
    client, _ = _client(
        _answer(
            409,
            {
                "detail": {
                    "code": (
                        "communications.team_inbox_observations"
                        ".provider_event_identity_collision"
                    ),
                    "message": "reused identity",
                }
            },
        )
    )
    assert (
        client.deliver(_request()).acceptance
        is integration.ProductAcceptance.INDETERMINATE
    )


def test_an_undeployed_contract_version_is_terminal() -> None:
    """The destination answers 409 rather than 400 precisely so a caller does
    not retry a body that can never be accepted."""
    client, _ = _client(
        _answer(
            409,
            {
                "detail": {
                    "code": (
                        "communications.team_inbox_integrator_envelope"
                        ".unsupported_contract_version"
                    ),
                    "message": "v2 is not deployed",
                }
            },
        )
    )
    outcome = client.deliver(_request())

    assert outcome.acceptance is integration.ProductAcceptance.REJECTED
    assert outcome.as_outcome().status is integration.OutcomeStatus.TERMINAL


def test_a_receipt_conflict_is_retryable_because_nothing_was_recorded() -> None:
    client, _ = _client(
        _answer(409, {"detail": {"code": "integrator_observation_receipt_conflict"}})
    )
    assert (
        client.deliver(_request()).acceptance
        is integration.ProductAcceptance.UNAVAILABLE
    )


def test_an_unknown_capability_is_terminal_and_a_missing_binding_is_not() -> None:
    """The 404 split, which is the subtlest decision in the mapping.

    The destination answers 404 for a capability it does not accept — permanent,
    and it says so with a typed code — and ALSO for a binding that is missing,
    disabled, quarantined or retired, which it deliberately reports without
    saying which. The second is temporary far more often than not and is what a
    wrong `PRODUCT_PORT_BINDINGS` entry looks like, so treating it as terminal
    would dead-letter real messages over an hour's quarantine.
    """
    typed, _ = _client(
        _answer(
            404,
            {
                "detail": {
                    "code": (
                        "communications.team_inbox_integrator_envelope"
                        ".unknown_capability"
                    )
                }
            },
        )
    )
    untyped, _ = _client(
        _answer(404, {"detail": "Integrator observation binding not found"})
    )

    assert typed.deliver(_request()).acceptance is (
        integration.ProductAcceptance.REJECTED
    )
    assert untyped.deliver(_request()).acceptance is (
        integration.ProductAcceptance.UNAVAILABLE
    )


@pytest.mark.parametrize("status", [400, 422])
def test_a_refused_envelope_is_terminal(status: int) -> None:
    """Retrying identical bytes is refused identically. The payload survives on
    the receipt row, and `POST /operations/receipts/{id}/replay` is the recovery
    path once the connector is fixed."""
    client, _ = _client(_answer(status, {"detail": {"code": "x.invalid_envelope"}}))
    assert (
        client.deliver(_request()).acceptance is integration.ProductAcceptance.REJECTED
    )


@pytest.mark.parametrize("status", [401, 403, 429, 500, 502, 503])
def test_a_credential_or_capacity_refusal_is_retryable(status: int) -> None:
    """Nothing was recorded, so the same envelope may be sent again — and
    dead-lettering here would destroy events over a key rotation gap."""
    client, _ = _client(_answer(status, {"detail": "no"}))
    assert (
        client.deliver(_request()).acceptance
        is integration.ProductAcceptance.UNAVAILABLE
    )


def test_a_retry_after_is_relayed_and_an_absurd_one_is_bounded() -> None:
    client, _ = _client(_answer(429, {"detail": "slow down"}, retry_after="30"))
    assert client.deliver(_request()).retry_after_seconds == 30

    client, _ = _client(_answer(429, {"detail": "slow down"}, retry_after="Tue, 1 Jan"))
    assert client.deliver(_request()).retry_after_seconds is None


def test_an_unreadable_success_is_retryable_rather_than_lost() -> None:
    """Safe for the same reason a timeout is: if the destination committed
    before producing an unreadable body, the next attempt carries the same
    provider event identity and comes back replayed."""

    class _Garbage:
        def post(self, url: str, **_: Any) -> HttpAnswer:
            return HttpAnswer(status=200, body=b"<html>gateway</html>")

    client = ObservationPortClient(
        application="sub",
        base_url="https://destination.example",
        api_path_prefix="/api/v1",
        remote_bindings={LOCAL_BINDING: REMOTE_BINDING},
        api_key_ref=API_KEY_REF,
        mode=ProductPortMode.WRITE,
        timeout_seconds=5.0,
        transport=_Garbage(),
    )

    with pytest.raises(integration.TransportFailure):
        client.deliver(_request())


# ── The shadow port ─────────────────────────────────────────────────────────


def test_a_shadow_client_refuses_to_deliver_at_all() -> None:
    """The narrowness of the destination's shadow scope, honoured on this side.

    A shadow client that answered a retryable outcome would look like an
    unreachable destination; one that answered ACCEPTED would mark a customer's
    message delivered when the destination never saw it. It raises instead,
    because the deployment is wired wrongly and nothing about that is a
    per-receipt condition.
    """
    client, transport = _client(mode=ProductPortMode.MIRROR)

    assert client.writes is False
    with pytest.raises(ShadowClientCannotWrite):
        client.deliver(_request())
    assert transport.calls == []


def test_the_shadow_pass_posts_the_same_envelope_to_the_mirror_route() -> None:
    """Same body, different path. A shadow run over a differently-assembled
    body would prove something about a body nobody will ever send."""
    writer, sent = _client(_ok())
    writer.deliver(_request())

    shadow, mirrored = _client(
        _answer(
            200,
            {
                "verdict": "agrees",
                "identity": "meta_cloud_api:acct-1:message:wamid.HBgNMjM0",
                "counterpart_identity": None,
                "blocking_reasons": [],
                "disagreements": [],
                "agrees": True,
            },
        ),
        mode=ProductPortMode.MIRROR,
    )
    verdict = shadow.mirror(_request())

    assert mirrored.calls[0]["url"].endswith("/mirror")
    assert mirrored.calls[0]["body"] == sent.calls[0]["body"]
    assert verdict.verdict == "agrees"
    assert verdict.agrees is True


def test_a_verdict_keeps_field_names_and_drops_the_provider_identity() -> None:
    """`identity` names the provider's event and account scope. A verdict object
    holding one would eventually be logged by somebody."""
    shadow, _ = _client(
        _answer(
            200,
            {
                "verdict": "field_disagreement",
                "identity": "meta_cloud_api:+2348012345678:message:wamid.HBgNMjM0",
                "counterpart_identity": "meta_cloud_api:acct-1:message:wamid.HBgNMjM0",
                "blocking_reasons": ["normalized_field_disagreement"],
                "disagreements": [
                    {"field": "contact_address", "integrator": "a", "sub": "b"}
                ],
                "agrees": False,
            },
        ),
        mode=ProductPortMode.MIRROR,
    )
    verdict = shadow.mirror(_request())

    assert verdict.disagreeing_fields == ("contact_address",)
    assert verdict.blocking_reasons == ("normalized_field_disagreement",)
    rendered = repr(verdict)
    assert "+2348012345678" not in rendered
    assert "wamid" not in rendered


def test_the_verdict_redaction_bites() -> None:
    """Sensitivity proof (ADR-0018). The `not in` assertions above would pass
    trivially if the report had never carried an identity at all."""
    report = {
        "verdict": "agrees",
        "identity": "meta_cloud_api:+2348012345678:message:wamid.HBgNMjM0",
        "agrees": True,
    }
    assert "+2348012345678" in json.dumps(report)
    assert "+2348012345678" not in repr(product_port.MirrorVerdict.from_report(report))


# ── Composition ─────────────────────────────────────────────────────────────


def test_bindings_parse_and_an_ambiguous_pair_is_refused() -> None:
    assert parse_bindings(f"{LOCAL_BINDING}={REMOTE_BINDING}") == {
        LOCAL_BINDING: REMOTE_BINDING
    }
    with pytest.raises(ValueError):
        parse_bindings(f"{LOCAL_BINDING}={REMOTE_BINDING},{LOCAL_BINDING}={uuid4()}")
    with pytest.raises(ValueError):
        parse_bindings("not-a-pair")


def test_capabilities_parse_into_the_modules_own_registry() -> None:
    registry = parse_capabilities(
        "messaging.receive.v1 = sub/communications : Inbound message observations"
    )
    contract = registry.get("messaging.receive.v1")

    assert contract.owner.application == "sub"
    assert contract.contract_version == 1
    with pytest.raises(ValueError):
        parse_capabilities("messaging.receive.v1")


def test_a_base_url_without_a_scheme_is_refused_at_construction() -> None:
    with pytest.raises(ValueError):
        ObservationPortClient(
            application="sub",
            base_url="destination.example",
            api_path_prefix="/api/v1",
            remote_bindings={},
            api_key_ref=API_KEY_REF,
            mode=ProductPortMode.WRITE,
            timeout_seconds=5.0,
            transport=_RecordingTransport(),
        )
