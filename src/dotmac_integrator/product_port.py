"""The network half of receipt delivery: speaking one destination's HTTP port.

`dotmac_integration.receipt_delivery` owns claiming, the three phases, retry
classification and the idempotency key. It cannot own one thing — the protocol
the destination application speaks — and this file is that one thing and nothing
else. Read :class:`ObservationPortClient.deliver` and you have read the whole
contribution: build an envelope from the CLAIM, post it, and translate the
answer into `ProductAcceptance`.

## Why this may be written here now, when it could not be before

Authoring a wire contract inside the transport is what ADR-0024 forbids: the
Integrator would become the sole author of a shape two systems have to agree on,
and the destination would inherit it without ever having reviewed it. This file
is therefore NOT an author. The contract is `dotmac_sub`'s
``app/schemas/integrator_observation.py`` and ``app/api/integrator_observations.py``,
reviewed and merged there; every field name, length, status code and refusal
code below is transcribed from it. A disagreement between this file and that one
is a defect HERE, or a contract change that has to happen THERE first — never
something to smooth over locally.

## Two routes, two scopes, and the narrowness is the safety property

The destination exposes the write port and a strictly narrower shadow port that
records nothing and answers with a parity verdict. They carry different scopes
on the destination's side precisely so that a credential issued for the shadow
window cannot become a writer by accident.

That property is only worth having if this side honours it too, so a client
carries a :class:`ProductPortMode` and it is structural rather than advisory:

* a ``MIRROR`` client's :meth:`ObservationPortClient.deliver` RAISES, so it can
  never settle a receipt as delivered;
* ``delivery.install_product_port`` refuses to install a non-writing client as
  the delivery pump's port at all;
* the worker runs the shadow pass instead, which claims nothing and settles
  nothing.

A shadow deployment that quietly marked receipts `processed` would be the worst
available outcome: it would look like a successful cutover and would have
delivered nothing.

## The destination declares its own binding id

The port is keyed on the DESTINATION's own capability-binding UUID, which lives
in the destination's database. This deployment's
`DestinationBinding.capability_binding_id` is a different UUID in a different
database, and the two are not interchangeable. There is deliberately no
derivation, no truncation and no "they're both UUIDs" assumption here: posting
the wrong one 404s in the best case and writes to somebody else's binding in the
worst.

The assembly authenticates the product-owned descriptor, pins its digest, and a
named reconciler stores that immutable declaration against the local binding.
There is no operator-maintained second map to drift. A missing projection is
refused BEFORE the network and reported `UNAVAILABLE`, so an operator can repair
it without discarding a customer's message.

## Provider identity comes from the durable receipt

`ProductRequest` carries the destination, receipt id, event type, normalized
observation and the provider identity the ingress engine persisted and
deduplicated. A connector's transitional payload copy is checked when present
but never selected as the identity. A payload that cannot otherwise form an
envelope is refused before the network as `REJECTED`.

## The fingerprint has to be computed over the same bytes twice

The destination recomputes the transport fingerprint over the observation
sub-document *as its own model dumps it* — every declared field present,
optionals explicitly null, empty collections as ``[]`` — and refuses the
envelope if it disagrees. A fingerprint computed over a sparse dict would
therefore fail EVERY delivery, and it would fail with a message about a mangled
body rather than about a missing key. :func:`canonical_body` is what makes the
two computations agree: it expands the connector's payload into the destination
model's complete shape, and the same expanded body is both fingerprinted and
sent.

## The credential is HELD, and it is held by name

ADR-0009: the API key is loaded at startup by `secret_loading` and resolved here
with a dict lookup. This module opens no store client, and it holds no value of
its own between calls — a rotation through `POST /operations/secrets/refresh`
takes effect on the next delivery rather than at the next restart.

Nothing in this file interpolates the key into a message, a log line or a metric
label, and the frame that holds it deletes both the key and the request object
before the answer is looked at, so an error reporter capturing frame locals has
nothing to capture. Every outbound string additionally goes through
`secret_resolver.redact`, because the destination's own refusal text is
third-party content and a port that echoed the credential it just rejected would
otherwise put it on the receipt row.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import ssl
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Final, Protocol
from urllib.parse import urlsplit
from uuid import UUID

import dotmac_integration as integration
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from dotmac_integrator.secret_resolver import redact, resolve_secrets

logger = logging.getLogger(__name__)

__all__ = [
    "PRODUCT_PORT_SECRET_NAME",
    "ATTACHMENT_FIELDS",
    "CONTACT_PROFILE_FIELDS",
    "DELIVERY_RECEIPT_FIELDS",
    "ENVELOPE_FIELDS",
    "LOCATION_FIELDS",
    "MESSAGE_FIELDS",
    "EnvelopeNotConstructible",
    "HttpAnswer",
    "MirrorVerdict",
    "ObservationPortClient",
    "ProductPortDescriptorError",
    "ProductPortDescriptorReconciler",
    "ProductPortMode",
    "ShadowClientCannotWrite",
    "Transport",
    "UnmappedDestinationBinding",
    "UrllibTransport",
    "build_envelope",
    "build_from_settings",
    "canonical_body",
    "canonical_fingerprint",
]

#: The logical name the credential is resolved under. A logical name rather than
#: the reference itself, because `resolve_secrets` reports what is MISSING by
#: name and "api_key" is what an operator reading that refusal needs to see.
PRODUCT_PORT_SECRET_NAME: Final = "api_key"


# ── Refusals raised before anything is sent ─────────────────────────────────


class EnvelopeNotConstructible(ValueError):
    """The normalized payload cannot form the destination's envelope.

    A connector defect or a contract drift, never a network condition. Raised
    before the request is built so a malformed observation never reaches the
    destination, and reported terminally: the same bytes will not become valid
    by being sent again.
    """


class UnmappedDestinationBinding(LookupError):
    """This receipt cannot be ADDRESSED: no destination-side binding, or the
    resolved binding names an application this client does not serve.

    Its own type, and not folded into :class:`EnvelopeNotConstructible`, because
    the two need opposite answers: a malformed payload is terminal and this is a
    configuration gap that an operator closes without touching a single event.
    """


class ShadowClientCannotWrite(RuntimeError):
    """A shadow client was asked to deliver.

    Raised rather than downgraded to a retryable outcome. A shadow client that
    answered `UNAVAILABLE` would look like an unreachable destination and would
    burn every receipt's attempts against a port that was never going to record
    anything; raising says the deployment is wired wrongly, which it is.
    """


# ── The wire contract, transcribed ──────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class WireField:
    """One field of the destination's merged schema.

    `kind` is the JSON type the destination declares. It is checked rather than
    coerced, and that check is what makes the fingerprint agreement provable: a
    string ``"512"`` sent for an integer field is silently coerced by the
    destination's validator, whose model dump then holds ``512`` — a different
    canonical body, a fingerprint mismatch, and a refusal that names neither the
    field nor the type.
    """

    name: str
    kind: type
    required: bool = False
    max_length: int | None = None
    allow_empty: bool = False
    minimum: int | float | None = None
    maximum: int | float | None = None


#: The message observation, field for field. Mirrors
#: `IntegratorMessageObservation`; `attachments` and `contact_profile` are
#: handled separately because they are nested models rather than scalars.
MESSAGE_FIELDS: Final[tuple[WireField, ...]] = (
    WireField("contact_address", str, required=True, max_length=320),
    WireField("body", str, required=True, max_length=10_000, allow_empty=True),
    WireField("contact_name", str, max_length=255),
    WireField("subject", str, max_length=500),
    WireField("external_message_id", str, required=True, max_length=255),
    WireField("external_thread_id", str, max_length=255),
    WireField("provider_account_id", str, max_length=255),
    WireField("external_account_id", str, max_length=255),
    WireField("page_id", str, max_length=255),
    WireField("instagram_account_id", str, max_length=255),
    WireField("surface", str, max_length=60),
    WireField("permalink_url", str, max_length=2000),
    WireField("media_url", str, max_length=2000),
)

#: Mirrors `IntegratorContactProfile`.
CONTACT_PROFILE_FIELDS: Final[tuple[WireField, ...]] = (
    WireField("display_name", str, max_length=255),
    WireField("username", str, max_length=255),
    WireField("profile_pic", str, max_length=2000),
)

#: Mirrors `IntegratorAttachment`.
ATTACHMENT_FIELDS: Final[tuple[WireField, ...]] = (
    WireField("asset_type", str, required=True, max_length=40),
    WireField("file_name", str, max_length=255),
    WireField("mime_type", str, max_length=160),
    WireField("provider_media_id", str, max_length=255),
    WireField("source_url", str, max_length=2000),
    WireField("caption", str, max_length=2000),
    WireField("file_size", int, minimum=0),
    WireField("download_status", str, max_length=40),
)

#: Mirrors `IntegratorLocation`, nested under one attachment. Coordinates are
#: numeric facts, not presentation strings, and the destination validates their
#: geographic bounds before any domain consequence runs.
LOCATION_FIELDS: Final[tuple[WireField, ...]] = (
    WireField("latitude", float, required=True, minimum=-90, maximum=90),
    WireField("longitude", float, required=True, minimum=-180, maximum=180),
    WireField("name", str, max_length=255),
    WireField("address", str, max_length=500),
)

#: Mirrors `IntegratorDeliveryReceiptObservation`. `error_codes` is a list of
#: strings and is handled separately.
DELIVERY_RECEIPT_FIELDS: Final[tuple[WireField, ...]] = (
    WireField("external_message_id", str, required=True, max_length=255),
    WireField("status", str, required=True, max_length=40),
    WireField("recipient_id", str, max_length=255),
)

#: Provider context supplied by the connector. Event identity comes from the
#: durable receipt and is checked against a connector's transitional duplicate.
ENVELOPE_FIELDS: Final[tuple[WireField, ...]] = (
    WireField("provider", str, required=True, max_length=80),
    WireField("provider_account_scope", str, required=True, max_length=160),
    WireField("channel", str, required=True, max_length=40),
    WireField("observed_at", str, required=True),
)

#: The two observation slots. Exactly one is present in an envelope; the
#: destination refuses both and neither.
_MESSAGE_KEY: Final = "message"
_RECEIPT_KEY: Final = "delivery_receipt"
_OBSERVATION_SLOTS: Final[frozenset[str]] = frozenset({_MESSAGE_KEY, _RECEIPT_KEY})

#: Evidence used to diagnose the connector's translation remains on the
#: Integrator receipt. It is deliberately absent from the destination's domain
#: contract: transport provenance is not customer/message state.
_LOCAL_ONLY_OBSERVATION_FIELDS: Final[frozenset[str]] = frozenset(
    {"provider_event_id", "transport_evidence"}
)

#: The destination's scope field, which carries this deployment's own binding
#: scope as provenance. Bounded here so an over-long scope is named locally
#: rather than arriving as a generic validation refusal.
_SCOPE_KIND_MAX: Final = 60
_SCOPE_REF_MAX: Final = 160


def _checked(
    field: WireField, value: object, *, where: str
) -> str | int | float | None:
    if value is None:
        if field.required:
            raise EnvelopeNotConstructible(
                f"{where}.{field.name} is required by the destination's "
                "envelope and the normalized observation does not carry it"
            )
        return None
    # `bool` is a subclass of `int`, so an unguarded isinstance would let True
    # through as a file size and the destination would dump it as `true`.
    if isinstance(value, bool) or not isinstance(value, field.kind):
        raise EnvelopeNotConstructible(
            f"{where}.{field.name} must be {field.kind.__name__}, not "
            f"{type(value).__name__}. The destination coerces rather than "
            "refuses, so its canonical body would differ from ours and every "
            "delivery would fail on the fingerprint instead of on this field"
        )
    if isinstance(value, str):
        if field.required and not value and not field.allow_empty:
            raise EnvelopeNotConstructible(
                f"{where}.{field.name} is required and is empty"
            )
        if field.max_length is not None and len(value) > field.max_length:
            raise EnvelopeNotConstructible(
                f"{where}.{field.name} is {len(value)} characters and the "
                f"destination accepts at most {field.max_length}"
            )
        return value
    if isinstance(value, int | float):
        if field.minimum is not None and value < field.minimum:
            raise EnvelopeNotConstructible(
                f"{where}.{field.name} must be at least {field.minimum}"
            )
        if field.maximum is not None and value > field.maximum:
            raise EnvelopeNotConstructible(
                f"{where}.{field.name} must be at most {field.maximum}"
            )
        return value
    raise EnvelopeNotConstructible(  # pragma: no cover - no other kind is declared
        f"{where}.{field.name} declares an unsupported wire type "
        f"{field.kind.__name__}"
    )


def _expand(
    source: Mapping[str, object], fields: tuple[WireField, ...], *, where: str
) -> dict[str, object]:
    """Every declared field, present, in the destination's own shape.

    This client chooses one explicit representation and fingerprints exactly
    what it sends. The destination preserves explicitly sent nulls in its
    ``exclude_unset`` dump, so its canonical body is equivalent; a sparse
    connector dict is never fingerprinted by accident.
    """
    unknown = sorted(set(source) - {field.name for field in fields})
    if unknown:
        raise EnvelopeNotConstructible(
            f"{where} carries {unknown}, which the destination's schema forbids "
            "(it declares extra='forbid'). A new field is a contract change in "
            "the destination's repository, not a local addition"
        )
    return {
        field.name: _checked(field, source.get(field.name), where=where)
        for field in fields
    }


def _mapping(value: object, *, where: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise EnvelopeNotConstructible(
            f"{where} must be an object, not {type(value).__name__}"
        )
    return {str(key): item for key, item in value.items()}


def canonical_body(observation: Mapping[str, object]) -> tuple[str, dict[str, object]]:
    """The observation sub-document, expanded exactly as the destination dumps it.

    Returns the slot name (`message` or `delivery_receipt`) and the body. The
    slot is returned rather than inferred twice, because the envelope has to put
    the body under the same key the fingerprint covered.
    """
    has_message = observation.get(_MESSAGE_KEY) is not None
    has_receipt = observation.get(_RECEIPT_KEY) is not None
    if has_message == has_receipt:
        raise EnvelopeNotConstructible(
            "the normalized observation carries "
            f"{'both' if has_message else 'neither'} of {_MESSAGE_KEY!r} and "
            f"{_RECEIPT_KEY!r}; the destination accepts exactly one"
        )

    if has_message:
        source = _mapping(observation[_MESSAGE_KEY], where=_MESSAGE_KEY)
        nested = {
            key: source[key]
            for key in ("contact_profile", "attachments")
            if key in source
        }
        scalars = {k: v for k, v in source.items() if k not in nested}
        body = _expand(scalars, MESSAGE_FIELDS, where=_MESSAGE_KEY)

        profile = nested.get("contact_profile")
        body["contact_profile"] = (
            None
            if profile is None
            else _expand(
                _mapping(profile, where="message.contact_profile"),
                CONTACT_PROFILE_FIELDS,
                where="message.contact_profile",
            )
        )

        attachments = nested.get("attachments") or []
        if not isinstance(attachments, list | tuple):
            raise EnvelopeNotConstructible(
                "message.attachments must be a list of objects, not "
                f"{type(attachments).__name__}"
            )
        expanded_attachments: list[dict[str, object]] = []
        for item in attachments:
            attachment = _mapping(item, where="message.attachments[]")
            location = attachment.get("location")
            scalars = {
                key: value for key, value in attachment.items() if key != "location"
            }
            expanded = _expand(
                scalars,
                ATTACHMENT_FIELDS,
                where="message.attachments[]",
            )
            expanded["location"] = (
                None
                if location is None
                else _expand(
                    _mapping(location, where="message.attachments[].location"),
                    LOCATION_FIELDS,
                    where="message.attachments[].location",
                )
            )
            expanded_attachments.append(expanded)
        body["attachments"] = expanded_attachments
        if not str(body["body"]).strip() and not expanded_attachments:
            raise EnvelopeNotConstructible(
                "message requires text or at least one attachment"
            )
        return _MESSAGE_KEY, body

    source = _mapping(observation[_RECEIPT_KEY], where=_RECEIPT_KEY)
    codes = source.get("error_codes") or []
    scalars = {k: v for k, v in source.items() if k != "error_codes"}
    body = _expand(scalars, DELIVERY_RECEIPT_FIELDS, where=_RECEIPT_KEY)
    if not isinstance(codes, list | tuple) or any(
        not isinstance(code, str) for code in codes
    ):
        raise EnvelopeNotConstructible(
            "delivery_receipt.error_codes must be a list of strings"
        )
    body["error_codes"] = list(codes)
    return _RECEIPT_KEY, body


def canonical_fingerprint(body: Mapping[str, object]) -> str:
    """Canonical-JSON SHA-256 over an observation body, as BOTH sides compute it.

    Byte-for-byte the destination's `canonical_fingerprint`: sorted keys, no
    whitespace, `default=str`. It is duplicated rather than imported for the
    reason ADR-0024 gives — the two applications share no code — and it is
    duplicated in one place, with the destination's own implementation named
    here, so a divergence has one file to look in.
    """
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _observed_at(value: object) -> str:
    """An ISO-8601 instant WITH an offset. The destination refuses a naive one."""
    text = str(value)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise EnvelopeNotConstructible(
            f"observed_at {text!r} is not an ISO-8601 instant"
        ) from exc
    if parsed.tzinfo is None:
        raise EnvelopeNotConstructible(
            "observed_at must be timezone-aware; the destination refuses a naive "
            "instant rather than guessing a zone for it"
        )
    return text


def build_envelope(request: Any) -> dict[str, object]:
    """The destination's envelope, assembled from the claim and nothing else.

    Everything that ADDRESSES the destination — capability, contract version and
    scope — comes from `request.destination`, which the claim transaction
    resolved from an immutable configuration revision. Everything that DESCRIBES
    the observation comes from the connector's normalized payload. No value
    crosses between those two halves, which is why a provider payload cannot
    redirect a delivery: there is no branch here that reads an addressing key
    out of `observation`.

    `transport_evidence` is the one local-only member: it remains on the module's
    receipt for repair and never becomes product state. A payload carrying an
    addressing key anyway is REFUSED rather than ignored.
    Ignoring it would be safe in the narrow sense — the trusted value still
    wins — and it would leave a connector quietly sending a field nobody reads,
    which is how a real disagreement about the contract goes unnoticed until it
    matters.
    """
    destination = request.destination
    observation = dict(request.observation or {})

    durable_identity = str(request.provider_event_id)
    payload_identity = observation.get("provider_event_id")
    if payload_identity is not None and payload_identity != durable_identity:
        raise EnvelopeNotConstructible(
            "observation.provider_event_id disagrees with the durable receipt; "
            "provider input may evidence identity but may never replace it"
        )
    if not durable_identity or len(durable_identity) > 255:
        raise EnvelopeNotConstructible(
            "the durable receipt provider_event_id must contain 1 to 255 characters"
        )

    slot, body = canonical_body(observation)
    identity = _expand(
        {
            key: observation[key]
            for key in observation
            if key not in _OBSERVATION_SLOTS | _LOCAL_ONLY_OBSERVATION_FIELDS
        },
        ENVELOPE_FIELDS,
        where="observation",
    )

    kind, ref = destination.scope.kind, destination.scope.ref
    if len(kind) > _SCOPE_KIND_MAX or len(ref) > _SCOPE_REF_MAX:
        raise EnvelopeNotConstructible(
            f"destination scope {kind}:{ref} exceeds the envelope's limits "
            f"({_SCOPE_KIND_MAX}/{_SCOPE_REF_MAX} characters)"
        )

    return {
        "capability_id": destination.capability_id,
        "contract_version": request.contract_version,
        "provider": identity["provider"],
        "provider_account_scope": identity["provider_account_scope"],
        # RAW. The destination prefixes this with its own observation-kind
        # namespace; pre-prefixing here would produce a second identity for one
        # upstream event.
        "provider_event_id": durable_identity,
        "channel": identity["channel"],
        "observed_at": _observed_at(identity["observed_at"]),
        "payload_fingerprint": canonical_fingerprint(body),
        "scope": {"kind": kind, "ref": ref},
        slot: body,
    }


# ── The transport seam ──────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class HttpAnswer:
    """One HTTP answer, reduced to what the acceptance mapping reads."""

    status: int
    body: bytes
    retry_after: str | None = None


class Transport(Protocol):
    """How a request reaches the destination. A seam so tests need no server.

    An implementation returns an :class:`HttpAnswer` for ANY status the
    destination produced, including refusals, and raises
    `dotmac_integration.TransportFailure` only when there was no answer at all.
    Collapsing the two would make a 400 look like an outage and retry a body
    that can never be accepted.
    """

    def post(
        self, url: str, *, body: bytes, headers: Mapping[str, str], timeout: float
    ) -> HttpAnswer: ...

    def get(
        self, url: str, *, headers: Mapping[str, str], timeout: float
    ) -> HttpAnswer: ...


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Never forward a held product credential to a redirect-selected origin."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


class UrllibTransport:
    """The standard library, deliberately.

    No HTTP dependency is added for one POST of a JSON document. That is not
    asceticism: this assembly pins its dependencies exactly (AGENTS.md § 3), and
    every dependency on the delivery path is one more thing whose CVE feed has
    to be watched for a deployment whose entire outbound surface is a single
    known URL. `ssl.create_default_context` gives certificate and hostname
    verification, which is the property that actually matters here.

    The cost is honest and stated: no connection reuse between deliveries. If a
    profile ever shows that dominating, the fix is a pooled client behind this
    same seam, not a change to anything above it.
    """

    def __init__(self) -> None:
        self._context = ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._context),
            _RefuseRedirects(),
        )

    def post(
        self, url: str, *, body: bytes, headers: Mapping[str, str], timeout: float
    ) -> HttpAnswer:
        # `headers` carries the credential and `request` holds a copy of it, so
        # BOTH are deleted in a `finally` — every path, including the one where
        # an exception is on its way out. A traceback keeps its frames alive and
        # an error reporter reads their locals afterwards, so clearing them
        # before the exception propagates is what makes the capture impossible
        # rather than unlikely. `assembly.py` makes the same move for the
        # ingress endpoint key, for the same reason.
        request = urllib.request.Request(
            url, data=body, headers=dict(headers), method="POST"
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:  # noqa: S310
                return HttpAnswer(
                    status=int(response.status),
                    body=response.read(),
                    retry_after=response.headers.get("Retry-After"),
                )
        except urllib.error.HTTPError as answer:
            # An HTTP refusal is an ANSWER. The destination was reached, it
            # decided, and that decision has to be classified rather than
            # retried as though nobody was home.
            return HttpAnswer(
                status=int(answer.code),
                body=answer.read(),
                retry_after=answer.headers.get("Retry-After"),
            )
        except Exception as exc:
            # Nothing arrived, or nothing came back. Safe to retry: the next
            # attempt presents the same envelope and therefore the same
            # provider event identity, which the destination deduplicates.
            raise integration.TransportFailure(
                f"the destination could not be reached: {type(exc).__name__}",
                error_code="destination_unreachable",
            ) from exc
        finally:
            del request, headers

    def get(
        self, url: str, *, headers: Mapping[str, str], timeout: float
    ) -> HttpAnswer:
        request = urllib.request.Request(url, headers=dict(headers), method="GET")
        try:
            with self._opener.open(request, timeout=timeout) as response:  # noqa: S310
                return HttpAnswer(
                    status=int(response.status),
                    body=response.read(),
                    retry_after=response.headers.get("Retry-After"),
                )
        except urllib.error.HTTPError as answer:
            return HttpAnswer(status=int(answer.code), body=answer.read())
        except Exception as exc:
            raise integration.TransportFailure(
                f"the product descriptor could not be read: {type(exc).__name__}",
                error_code="product_descriptor_unreachable",
            ) from exc
        finally:
            del request, headers


# ── Modes ───────────────────────────────────────────────────────────────────


class ProductPortMode(str, Enum):
    """Which of the destination's two ports this client speaks to.

    `MIRROR` is the default everywhere a default is offered. A deployment that
    was misconfigured into the shadow port produces evidence and records
    nothing; one misconfigured into the write port records facts nobody agreed
    to record, and there is no un-recording it.
    """

    #: The write port. Records an observation and answers with its consequence.
    WRITE = "write"
    #: The shadow port. Records NOTHING and answers with a parity verdict.
    MIRROR = "mirror"


def _sequence(value: object) -> tuple[object, ...]:
    """A JSON array, or nothing. A missing key is not a malformed report."""
    return tuple(value) if isinstance(value, list | tuple) else ()


@dataclass(frozen=True, slots=True)
class MirrorVerdict:
    """One shadow comparison. Evidence, never a consequence."""

    verdict: str
    agrees: bool
    blocking_reasons: tuple[str, ...] = ()
    disagreeing_fields: tuple[str, ...] = ()

    @classmethod
    def from_report(cls, report: Mapping[str, object]) -> MirrorVerdict:
        """Read the destination's report, keeping only what is safe to hold.

        `identity` and `counterpart_identity` are DROPPED. They carry the
        provider's event identity and account scope, which is exactly the class
        of value that must not reach a log line or a metric label — and a
        verdict object that held one would eventually be logged by somebody.
        The field NAMES that disagree are kept; the values are not.
        """
        return cls(
            verdict=str(report.get("verdict") or "unknown"),
            agrees=bool(report.get("agrees")),
            blocking_reasons=tuple(
                str(reason) for reason in _sequence(report.get("blocking_reasons"))
            ),
            disagreeing_fields=tuple(
                str(item.get("field"))
                for item in _sequence(report.get("disagreements"))
                if isinstance(item, Mapping)
            ),
        )


# ── The client ──────────────────────────────────────────────────────────────

#: Refusal codes the destination answers with, and what each one means for a
#: retry. A MAPPING rather than an `if` chain: a code added without deciding its
#: retry semantics is then a missing entry with a documented fallback, not a
#: silent fall-through to whichever branch happened to be last.
_ACCEPTANCE_BY_CODE: Final[Mapping[str, integration.ProductAcceptance]] = {
    # The destination has not deployed this contract version. A real
    # disagreement about the contract; the same body can never be accepted.
    "unsupported_contract_version": integration.ProductAcceptance.REJECTED,
    # This deployment does not accept the capability at all.
    "unknown_capability": integration.ProductAcceptance.REJECTED,
    # One provider identity carrying DIFFERENT evidence. Not a duplicate: the
    # observation owner refuses the write rather than overwriting, and the two
    # producers disagree about what the provider said. A human decides which is
    # wrong, so this escalates instead of retrying or dead-lettering.
    "identity_collision": integration.ProductAcceptance.INDETERMINATE,
    "provider_event_identity_collision": integration.ProductAcceptance.INDETERMINATE,
    # The transport receipt raced another writer. Nothing was recorded from this
    # call and the next attempt presents the same identity.
    "receipt_conflict": integration.ProductAcceptance.UNAVAILABLE,
}

#: The longest `Retry-After` this client will relay. A transport sanity bound on
#: a header another deployment wrote, not a retry decision: past it the value is
#: far likelier to be a mistake than an instruction, and ignoring it hands the
#: wait back to `dotmac_integration.retry`, which owns it.
_LONGEST_BELIEVABLE_RETRY_AFTER: Final = 3600

#: Statuses whose meaning does not depend on a code in the body.
_ACCEPTANCE_BY_STATUS: Final[Mapping[int, integration.ProductAcceptance]] = {
    # Malformed envelope, or an observation the destination's owner refused.
    # Retrying identical content is refused identically.
    400: integration.ProductAcceptance.REJECTED,
    422: integration.ProductAcceptance.REJECTED,
    # The credential is wrong, missing its scope, or revoked. Nothing was
    # recorded, so retrying is safe — and it is the right answer during a key
    # rotation, where dead-lettering would destroy events over a credential gap.
    401: integration.ProductAcceptance.UNAVAILABLE,
    403: integration.ProductAcceptance.UNAVAILABLE,
    429: integration.ProductAcceptance.UNAVAILABLE,
}


class ObservationPortClient:
    """A `dotmac_integration.ProductPortClient` for one destination application.

    Constructed once at startup and held (ADR-0009's shape): nothing here is
    looked up while a receipt is being delivered except the credential, which is
    a dict lookup over already-held material.
    """

    def __init__(
        self,
        *,
        application: str,
        base_url: str,
        api_key_ref: str,
        mode: ProductPortMode,
        timeout_seconds: float,
        transport: Transport | None = None,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValueError(
                f"the destination base URL {base_url!r} must be http:// or "
                "https://; a bare host would be posted to as a relative path"
            )
        self._application = application
        self._base = base_url.rstrip("/")
        self._api_key_ref = api_key_ref
        self._mode = mode
        self._timeout = timeout_seconds
        self._transport: Transport = transport or UrllibTransport()

    @property
    def application(self) -> str:
        return self._application

    @property
    def mode(self) -> ProductPortMode:
        return self._mode

    @property
    def writes(self) -> bool:
        """Whether this client may settle a receipt as delivered.

        The installation contract reads this, so a shadow client cannot be
        installed as the delivery pump's port. Declared rather than inferred
        from the mode by whoever is asking, so there is one answer.
        """
        return self._mode is ProductPortMode.WRITE

    # ── The module's seam ───────────────────────────────────────────────────

    def deliver(self, request: Any) -> integration.ProductOutcome:
        """Phase 2 of `deliver_receipt`. No session, no transaction, only the wire."""
        if not self.writes:
            raise ShadowClientCannotWrite(
                "this client speaks the destination's SHADOW port, which records "
                "nothing. Settling a receipt against it would mark a customer's "
                "message delivered when the destination never saw it. Run the "
                "shadow pass, or re-scope the deployment to the write port "
                "deliberately"
            )
        try:
            url, envelope = self._address(request)
        except UnmappedDestinationBinding as exc:
            # Loud, and before the network. Reported retryable because nothing
            # was sent and an operator closes the gap without touching events.
            logger.warning(
                "a receipt could not be addressed: its local binding has no "
                "reconciled product descriptor, or the resolved application is "
                "not this client's. Refresh the product-port descriptor. (No "
                "identifier is logged; the receipt row names the binding.)"
            )
            return integration.ProductOutcome(
                acceptance=integration.ProductAcceptance.UNAVAILABLE,
                error_code="integrator.destination_not_addressable",
                error_detail=redact(str(exc)),
            )
        except EnvelopeNotConstructible as exc:
            return integration.ProductOutcome(
                acceptance=integration.ProductAcceptance.REJECTED,
                error_code="integrator.envelope_not_constructible",
                error_detail=redact(str(exc)),
            )

        answer = self._post(url, envelope, request)
        return self._outcome(answer)

    def mirror(self, request: Any) -> MirrorVerdict:
        """Compare one envelope against the destination's own receiver.

        Writes nothing on either side. It builds the SAME envelope
        :meth:`deliver` would build — that is what makes the evidence worth
        collecting, since a shadow run over a differently-built body proves
        something about a body nobody will ever send.
        """
        url, envelope = self._address(request, mirror=True)
        answer = self._post(url, envelope, request)
        if answer.status != 200:
            raise integration.TransportFailure(
                f"the shadow port answered {answer.status}",
                error_code="mirror_refused",
            )
        return MirrorVerdict.from_report(self._decoded(answer))

    # ── Internals ──────────────────────────────────────────────────────────

    def _address(
        self, request: Any, *, mirror: bool = False
    ) -> tuple[str, dict[str, object]]:
        destination = request.destination
        if destination.application != self._application:
            raise UnmappedDestinationBinding(
                f"this client serves {self._application!r} and the resolved "
                f"binding names {destination.application!r}. One application has "
                "one authenticated client"
            )
        descriptor = getattr(destination, "product_port", None)
        if descriptor is None:
            raise UnmappedDestinationBinding(
                f"local capability binding {destination.capability_binding_id} "
                "has no reconciled product-owned port descriptor"
            )
        allowed_states = {"configured_disabled", "enabled"} if mirror else {"enabled"}
        if descriptor.activation_state not in allowed_states:
            raise UnmappedDestinationBinding(
                f"the product declares its port {descriptor.activation_state!r}; "
                f"it is not eligible for {'mirror' if mirror else 'write'} delivery"
            )
        path = descriptor.mirror_path if mirror else descriptor.delivery_path
        return f"{self._base}{path}", build_envelope(request)

    def _post(
        self, url: str, envelope: Mapping[str, object], request: Any
    ) -> HttpAnswer:
        """Send it. The only frame that holds the credential.

        The idempotency key is presented as a header even though the destination
        does not read one: its dedup is the content-derived
        `(binding, provider_event_id)` receipt identity, which is likewise stable
        across attempts, so at-most-once holds either way. Sending it anyway
        means an operator correlating a retry storm across two deployments has
        the engine's own key in both access logs.
        """
        key = resolve_secrets({PRODUCT_PORT_SECRET_NAME: self._api_key_ref})[
            PRODUCT_PORT_SECRET_NAME
        ]
        try:
            return self._transport.post(
                url,
                body=json.dumps(envelope, separators=(",", ":")).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-Api-Key": key,
                    "Idempotency-Key": request.idempotency_key,
                    "X-Correlation-Id": request.correlation_id,
                },
                timeout=self._timeout,
            )
        finally:
            # In a `finally`, so the value is gone from this frame before an
            # exception raised inside the transport propagates through it.
            del key

    @staticmethod
    def _decoded(answer: HttpAnswer) -> dict[str, object]:
        """A JSON object, or a TRANSPORT failure.

        An answer that cannot be read is `UNAVAILABLE` rather than a defect,
        and that is safe for the same reason a timeout is: if the destination
        committed before producing an unreadable body, the next attempt carries
        the same provider event identity and comes back `replayed`.
        """
        try:
            decoded = json.loads(answer.body or b"{}")
        except ValueError as exc:
            raise integration.TransportFailure(
                f"the destination answered {answer.status} with a body that is "
                "not JSON",
                error_code="unusable_answer",
            ) from exc
        if not isinstance(decoded, dict):
            raise integration.TransportFailure(
                f"the destination answered {answer.status} with a "
                f"{type(decoded).__name__} rather than an object",
                error_code="unusable_answer",
            )
        return {str(key): value for key, value in decoded.items()}

    @classmethod
    def _refusal(cls, answer: HttpAnswer) -> tuple[str | None, str | None]:
        """The destination's typed code and message, when it gave one.

        A refusal `detail` is either an object carrying a code, or a plain
        string. The two are NOT the same refusal — see :meth:`_outcome` for why
        that distinction decides whether a 404 is terminal.
        """
        try:
            body: object = json.loads(answer.body or b"{}")
        except ValueError:
            return None, None
        detail = body.get("detail") if isinstance(body, dict) else None
        if isinstance(detail, Mapping):
            code = detail.get("code")
            message = detail.get("message")
            return (
                str(code) if code is not None else None,
                str(message) if message is not None else None,
            )
        if isinstance(detail, str):
            return None, detail
        return None, None

    def _outcome(self, answer: HttpAnswer) -> integration.ProductOutcome:
        """The destination's answer, in the engine's vocabulary.

        The distinction the whole file exists to get right: `ACCEPTED` and
        `ALREADY_APPLIED` both mean the destination HOLDS the consequence, so
        neither is retried; `UNAVAILABLE` means nothing landed and the same
        envelope may be sent again; `INDETERMINATE` means a human decides.
        """
        if answer.status == 200:
            receipt = self._decoded(answer)
            replayed = bool(receipt.get("replayed"))
            return integration.ProductOutcome(
                # `replayed` is the destination saying it recognised this
                # identity and did nothing further — which is precisely
                # ALREADY_APPLIED, and precisely what a retried timeout must
                # produce. Collapsing it into ACCEPTED would hide a double-send.
                acceptance=(
                    integration.ProductAcceptance.ALREADY_APPLIED
                    if replayed
                    else integration.ProductAcceptance.ACCEPTED
                ),
                product_ref=str(receipt.get("observation_id") or "") or None,
                evidence={
                    "outcome": str(receipt.get("outcome") or ""),
                    "processing_status": str(receipt.get("processing_status") or ""),
                    "replayed": replayed,
                },
            )

        code, message = self._refusal(answer)
        acceptance = self._classify(answer.status, code)
        return integration.ProductOutcome(
            acceptance=acceptance,
            error_code=redact(code or f"http_{answer.status}")[:120],
            # Third-party text. Redacted on the way out because a destination
            # that echoed the credential it just rejected would otherwise put it
            # on this deployment's receipt row.
            error_detail=redact(message or "")[:2000] or None,
            retry_after_seconds=self._retry_after(answer),
            evidence={"http_status": answer.status},
        )

    @staticmethod
    def _classify(status: int, code: str | None) -> integration.ProductAcceptance:
        """Status plus code onto an acceptance. Every branch is a decision.

        The 404 split is the subtle one. The destination answers 404 both for a
        capability it does not accept — permanent, and it says so with a typed
        code — and for a binding that is missing, disabled, quarantined or
        retired, which it deliberately reports without saying which. The second
        is temporary far more often than not, and it is also what a wrong entry
        in a stale product-port projection looks like. Treating it as terminal would
        dead-letter real messages because an operator quarantined a binding for
        an hour, so the untyped 404 is retryable and the typed one is not.
        """
        if code is not None:
            for suffix, acceptance in _ACCEPTANCE_BY_CODE.items():
                if code.endswith(suffix):
                    return acceptance
        if status == 404:
            return (
                integration.ProductAcceptance.REJECTED
                if code is not None
                else integration.ProductAcceptance.UNAVAILABLE
            )
        if status == 409:
            # An unrecognised 409 is still a disagreement the destination is
            # reporting. Escalating is the conservative reading: retrying could
            # hammer a real conflict and dead-lettering could discard an event
            # that a human would have kept.
            return integration.ProductAcceptance.INDETERMINATE
        return _ACCEPTANCE_BY_STATUS.get(
            status, integration.ProductAcceptance.UNAVAILABLE
        )

    @staticmethod
    def _retry_after(answer: HttpAnswer) -> int | None:
        """`Retry-After`, in seconds, when it is a number we can believe.

        A date-form `Retry-After` is ignored rather than parsed: the engine's own
        wait is a sound fallback, and a clock-skewed absolute time from another
        deployment is a worse answer than no answer.

        The bound is a TRANSPORT sanity check on a foreign header, not a retry
        decision — `dotmac_integration.retry` still owns when to stop trying and
        how long to wait when this returns `None`.
        """
        raw = (answer.retry_after or "").strip()
        if not raw.isdigit():
            return None
        return min(int(raw), _LONGEST_BELIEVABLE_RETRY_AFTER)


# ── Composition ─────────────────────────────────────────────────────────────


class ProductPortDescriptorError(integration.DestinationBindingError):
    """The authenticated product declaration cannot be trusted or projected."""


_DESCRIPTOR_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "application",
        "owner_module",
        "capability_id",
        "capability_summary",
        "contract_version",
        "destination_binding_id",
        "delivery_path",
        "mirror_path",
        "destination_scope",
        "activation_state",
        "source_revision",
        "descriptor_digest",
    }
)


class ProductPortDescriptorReconciler:
    """Read the product owner, then idempotently repair the local projection.

    The authenticated GET completes before a database session exists. The
    module-owned reconcile then runs in one short transaction, so a product
    outage cannot leave a claim or a half-written destination revision.
    """

    def __init__(
        self,
        *,
        engine: Engine,
        local_binding_id: UUID,
        descriptor_url: str,
        expected_digest: str,
        api_key_ref: str,
        mode: ProductPortMode,
        timeout_seconds: float,
        transport: Transport | None = None,
    ) -> None:
        parsed = urlsplit(descriptor_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ProductPortDescriptorError(
                "PRODUCT_PORT_DESCRIPTOR_URL must be an http(s) URL without "
                "credentials, query, or fragment"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
            raise ProductPortDescriptorError(
                "PRODUCT_PORT_DESCRIPTOR_EXPECTED_DIGEST must be 64 lowercase hex"
            )
        self._engine = engine
        self._local_binding_id = local_binding_id
        self._descriptor_url = descriptor_url
        self._expected_digest = expected_digest
        self._api_key_ref = api_key_ref
        self._mode = mode
        self._timeout = timeout_seconds
        self._transport: Transport = transport or UrllibTransport()
        self._base_url = f"{parsed.scheme}://{parsed.netloc}"

    def _read(self) -> integration.ProductPortDescriptorSnapshot:
        key = resolve_secrets({PRODUCT_PORT_SECRET_NAME: self._api_key_ref})[
            PRODUCT_PORT_SECRET_NAME
        ]
        try:
            answer = self._transport.get(
                self._descriptor_url,
                headers={"Accept": "application/json", "X-Api-Key": key},
                timeout=self._timeout,
            )
        finally:
            del key
        if answer.status != 200:
            raise ProductPortDescriptorError(
                f"the product descriptor endpoint answered {answer.status}"
            )
        try:
            document = json.loads(answer.body)
        except ValueError as exc:
            raise ProductPortDescriptorError(
                "the product descriptor endpoint did not return JSON"
            ) from exc
        if not isinstance(document, dict) or set(document) != _DESCRIPTOR_FIELDS:
            raise ProductPortDescriptorError(
                "the product descriptor does not have the exact v1 field set"
            )
        scope = document.get("destination_scope")
        if not isinstance(scope, dict) or set(scope) != {"kind", "ref"}:
            raise ProductPortDescriptorError(
                "the product descriptor destination_scope is not {kind, ref}"
            )
        string_fields = (
            "schema_version",
            "application",
            "owner_module",
            "capability_id",
            "capability_summary",
            "delivery_path",
            "mirror_path",
            "activation_state",
            "source_revision",
            "descriptor_digest",
        )
        if (
            any(
                not isinstance(document[field], str) or not document[field]
                for field in string_fields
            )
            or not isinstance(document["contract_version"], int)
            or isinstance(document["contract_version"], bool)
        ):
            raise ProductPortDescriptorError(
                "the product descriptor contains an invalid typed field"
            )
        if any(
            not isinstance(scope[field], str) or not scope[field]
            for field in ("kind", "ref")
        ):
            raise ProductPortDescriptorError(
                "the product descriptor destination_scope contains an invalid field"
            )
        try:
            snapshot = integration.ProductPortDescriptorSnapshot(
                schema_version=document["schema_version"],
                application=document["application"],
                owner_module=document["owner_module"],
                capability_id=document["capability_id"],
                capability_summary=document["capability_summary"],
                contract_version=document["contract_version"],
                destination_binding_id=UUID(str(document["destination_binding_id"])),
                delivery_path=document["delivery_path"],
                mirror_path=document["mirror_path"],
                destination_scope=integration.LocalScope(
                    kind=scope["kind"], ref=scope["ref"]
                ),
                activation_state=document["activation_state"],
                source_revision=document["source_revision"],
                descriptor_digest=document["descriptor_digest"],
            )
        except (TypeError, ValueError, KeyError) as exc:
            raise ProductPortDescriptorError(
                "the product descriptor contains an invalid typed field"
            ) from exc
        computed = integration.product_port_descriptor_digest(snapshot)
        if not hmac.compare_digest(snapshot.descriptor_digest, computed):
            raise ProductPortDescriptorError(
                "the product descriptor digest does not cover its published facts"
            )
        if not hmac.compare_digest(computed, self._expected_digest):
            raise ProductPortDescriptorError(
                "the product descriptor digest differs from the operator-approved pin"
            )
        return snapshot

    def reconcile(
        self,
    ) -> tuple[ObservationPortClient, integration.CapabilityRegistry]:
        descriptor = self._read()
        registry = integration.CapabilityRegistry.from_declarations(
            [
                integration.CapabilityContract(
                    capability_id=descriptor.capability_id,
                    owner=integration.CapabilityOwner(
                        application=descriptor.application,
                        module=descriptor.owner_module,
                    ),
                    summary=descriptor.capability_summary,
                )
            ]
        )
        with Session(self._engine) as db:
            integration.reconcile_product_port_descriptor(
                db,
                capability_binding_id=self._local_binding_id,
                descriptor=descriptor,
                registry=registry,
                reconciled_by="assembly:product-port-descriptor-reconciler",
            )
            db.commit()
        return (
            ObservationPortClient(
                application=descriptor.application,
                base_url=self._base_url,
                api_key_ref=self._api_key_ref,
                mode=self._mode,
                timeout_seconds=self._timeout,
                transport=self._transport,
            ),
            registry,
        )


def build_from_settings(
    settings: Any, *, engine: Engine, held_references: tuple[str, ...]
) -> tuple[ObservationPortClient, integration.CapabilityRegistry]:
    """The client and the registry this deployment routes by, from configuration.

    `held_references` is what `install_secrets` actually resolved, and an
    unresolved credential REFUSES THE BOOT here. That is deliberately stricter
    than the connector rule beside it: one bad connector reference refuses only
    that installation's enablement, because there is a per-installation gate to
    refuse at. There is no such gate for the destination port — an unheld
    credential would simply fail every delivery with a 401 and back off, which
    reads as the destination being unwell rather than as this deployment never
    having had a credential.
    """
    reference = settings.product_port_api_key_ref.strip()
    if reference not in held_references:
        raise integration.DestinationBindingError(
            f"no material is held for {reference}, the destination credential. "
            "Provision it and restart, or set PRODUCT_PORT_ENABLED=false — a "
            "port with no credential fails every delivery with a refusal that "
            "looks like the destination's problem"
        )
    reconciler = ProductPortDescriptorReconciler(
        engine=engine,
        local_binding_id=UUID(settings.product_port_local_binding_id),
        descriptor_url=settings.product_port_descriptor_url.strip(),
        expected_digest=settings.product_port_descriptor_expected_digest.strip(),
        api_key_ref=reference,
        mode=ProductPortMode(settings.product_port_mode),
        timeout_seconds=settings.product_port_timeout_seconds,
    )
    return reconciler.reconcile()
