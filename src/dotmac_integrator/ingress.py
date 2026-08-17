"""The public ingress adapter's service half: unit of work, cap, counters.

`assembly.py` owns the two routes and nothing else. Everything with a session
in it is here, for the reason `operations.py` states — a handler that queries
grows logic no service test covers.

## What this file does NOT decide

Eligibility, verification, normalisation, the acknowledgement, the status code
and the retry instruction are all `dotmac_integration.ingress`'s. This file
supplies the three things the engine correctly refuses to own: what a unit of
work IS, how the deployment dereferences a secret reference, and how big a
request body this deployment will read. It calls `receive` and
`answer_challenge` and hands back what they returned.

That includes the STATUS. An ingress status code is a retry instruction to the
provider — 200 means "never send this again" — so the engine chooses it and
this file never writes an integer status of its own. The one refusal the edge
raises, the body cap, is constructed as the module's own `PayloadTooLarge` and
passed to the module's `refusal_outcome`, which is how it gets a 413 without
this file naming one.

## Two operations, two eligibility rules, and no shared predicate

The engine exposes them as two functions with two entry points, and they are
called from two routes:

* ``GET  /ingress/{key}`` → :func:`answer_handshake` → `answer_challenge`.
  Answers for a binding that is CONFIGURED but still DISABLED, provided the
  installation is being brought up or is already enabled.
* ``POST /ingress/{key}`` → :func:`receive_delivery` → `receive`. Requires an
  ENABLED binding on an ENABLED installation (`selection._usable`).

**These must never share a predicate**, and the reason is a deadlock rather
than a preference. Several providers refuse to activate a subscription until
the endpoint has answered a GET handshake; if the handshake also required an
enabled binding, and enabling the binding required an active subscription, the
endpoint would refuse the one request that unblocks it, forever. The engine
splits them in `ingress._eligible`; this file's contribution is to keep the two
call sites distinct so nothing here can quietly reunite them.

Splitting eligibility weakens NOTHING about verification. A handshake still
runs the connector's `challenge`, still materialises secrets, and a connector
that does not recognise the request still answers `NotAChallenge`. What is
relaxed is *which binding may be addressed*, not *what the request must prove*.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any

import dotmac_integration as integration
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from dotmac_integrator import telemetry
from dotmac_integrator.secret_resolver import resolve_secrets

__all__ = [
    "BodyTooLarge",
    "build_request",
    "read_capped_body",
    "answer_handshake",
    "receive_delivery",
    "unit_of_work",
]


class BodyTooLarge(Exception):
    """The stream exceeded the cap. Carries NOTHING — not even the size seen.

    A count of bytes read is harmless on its own; a count of bytes read for a
    request that was refused before verification is a measurement of an
    unauthenticated body, and the habit of putting request-derived numbers in
    refusals is how the next one carries a prefix of the content.

    Converted to the module's `PayloadTooLarge` at the route, so the status and
    the code are the engine's rather than this assembly's.
    """


async def read_capped_body(stream: AsyncIterator[bytes], limit: int) -> bytes:
    """Read at most `limit` bytes, refusing AS the body arrives.

    **The cap is applied while reading, not after.** `await request.body()`
    buffers the whole stream and only then offers a length to check, so a
    handler that measures afterwards has already accepted the memory it was
    trying to refuse — the request-size limit becomes an amplifier for exactly
    the denial of service it exists to prevent. There is no header to trust
    instead: `Content-Length` is absent under chunked transfer encoding and is
    attacker-supplied when present, so it can be an early hint and never the
    control.

    It is also applied before any signature check, and that ordering is not
    interchangeable. An HMAC is computed over the WHOLE body, so verifying
    first means buffering first; a 10 GB body from an unauthenticated sender
    would be held in memory in order to discover it was not signed. Refusing on
    byte `limit + 1` means the work done for an unauthenticated request is
    bounded by the cap, whoever sent it and whatever they claimed.

    Raises as soon as the cap is passed, and stops reading. The remaining bytes
    are never pulled off the socket: the response goes back while the sender is
    still sending, which is the correct shape — continuing to drain a body this
    deployment has already refused is doing the attacker's work for them.

    :raises BodyTooLarge: the stream produced more than `limit` bytes.
    """
    chunks: list[bytes] = []
    seen = 0
    async for chunk in stream:
        seen += len(chunk)
        if seen > limit:
            # Before the join, before any digest, and before the endpoint is
            # even looked up. Nothing has been allocated beyond `limit` plus one
            # chunk, and no database connection has been taken.
            raise BodyTooLarge()
        chunks.append(chunk)
    return b"".join(chunks)


def unit_of_work(engine: Engine) -> Callable[[], Any]:
    """The `dotmac_integration.ingress.UnitOfWork` this deployment supplies.

    A FACTORY of context managers, not one context manager: `receive` opens two
    and the second must be a genuinely new transaction, because the whole design
    is that no session is held across the connector call. Handing back one
    reusable object would collapse them into a single long transaction and put a
    plugin call inside it.

    Commit on clean exit, roll back on exception — which is what makes the
    engine's placement of `except IngressRefused` OUTSIDE the `with` block do
    what it says. A refusal raised inside `record_batch` unwinds the whole
    batch here; a caller whose context manager committed regardless would
    persist the events written before the collision and then tell the provider
    5xx, inviting it to redeliver on top of them.
    """

    @contextmanager
    def open_unit_of_work() -> Iterator[Session]:
        db = Session(engine)
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    return open_unit_of_work


def build_request(
    *, raw_body: bytes, headers: Mapping[str, str], params: Mapping[str, str]
) -> Any:
    """The envelope, unmodified.

    Nothing is lowercased, trimmed, decoded or re-encoded on the way in. Every
    provider worth verifying signs the BYTES, so a body that has been through a
    decode/encode round trip fails a signature that should have passed — or
    passes one it should have failed.
    """
    return integration.IngressRequest(raw_body=raw_body, headers=headers, params=params)


def _counted(outcome: Any, *, handshake: bool) -> Any:
    """Record the outcome under the CLOSED vocabularies, and return it.

    Only the engine's own `code` reaches a label. The endpoint key, the
    `provider_event_id`, the acknowledgement bytes and the installation and
    binding ids are all in scope on this line and none of them is passed:
    `telemetry.render` would refuse them, but the honest guarantee is that
    there is no call here that would offer one.
    """
    code = outcome.code.value
    telemetry.counters.record_ingress_outcome(code)
    if handshake:
        telemetry.counters.record_challenge(
            "served" if code == "challenge_answered" else "refused"
        )
    return outcome


def receive_delivery(engine: Engine, *, endpoint: Any, request: Any) -> Any:
    """A provider DELIVERING events. Requires an enabled binding.

    Never falls through to a handshake. A bodyless POST is still a delivery: a
    provider that signs an empty body and expects its event recorded would
    otherwise get a handshake attempt and a 400, with its events dropped while
    it was told the endpoint worked.
    """
    return _counted(
        integration.receive(
            unit_of_work(engine),
            endpoint=endpoint,
            request=request,
            registry=integration.discover(),
            resolve_secrets=resolve_secrets,
            observe_verification=telemetry.counters.record_verification,
        ),
        handshake=False,
    )


def answer_handshake(engine: Engine, *, endpoint: Any, request: Any) -> Any:
    """A provider ACTIVATING a subscription. Writes nothing, ever.

    A SEPARATE call to a SEPARATE engine façade, not `receive_delivery` with a
    flag — see this module's docstring. The binding's own state is irrelevant
    here and decisive there, and one function taking a parameter is one edit
    away from being one predicate again.
    """
    return _counted(
        integration.answer_challenge(
            unit_of_work(engine),
            endpoint=endpoint,
            request=request,
            registry=integration.discover(),
            resolve_secrets=resolve_secrets,
        ),
        handshake=True,
    )
