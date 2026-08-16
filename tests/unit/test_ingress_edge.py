"""The two things the edge owns that the engine cannot: the cap and the URL.

`dotmac_integration` guards everything it can see. It cannot see the URL — the
endpoint key is a bearer credential that arrives in the request line, and by
the time the engine is called it has been wrapped in a `repr`-less
`EndpointAddress`. Nor can it see the socket: it takes an `IngressRequest`
holding bytes that have already been read.

So both remaining failures are this assembly's, and both are tested here.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator

import dotmac_integration as integration
import pytest
from fastapi.testclient import TestClient

from dotmac_integrator import telemetry
from dotmac_integrator.assembly import create_app
from dotmac_integrator.ingress import BodyTooLarge, read_capped_body
from dotmac_integrator.redaction import (
    IngressKeyRedactingFilter,
    install_log_redaction,
    redact_ingress_keys,
)
from tests.support import build_settings

#: A REAL-SHAPED key: 48 lowercase hex, exactly what `secrets.token_hex(24)`
#: produces and exactly what `ingress._ENDPOINT_KEY_RE` accepts. A placeholder
#: like "KEY" would pass every assertion below while proving nothing about the
#: value that actually travels.
SENTINEL = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718"


# ── The cap: bounded as it is READ ──────────────────────────────────────────


async def _chunks(
    *parts: bytes, counter: list[int] | None = None
) -> AsyncIterator[bytes]:
    for part in parts:
        if counter is not None:
            counter.append(len(part))
        yield part


def test_a_body_under_the_cap_is_returned_whole() -> None:
    body = asyncio.run(read_capped_body(_chunks(b"abc", b"def"), 1024))
    assert body == b"abcdef"


def test_the_cap_refuses_and_stops_reading_rather_than_draining_the_stream() -> None:
    """THE property. Refusing after the body is in memory is the denial of
    service the cap exists to prevent — the limit becomes an amplifier for it.

    The counter is the evidence: a stream offering 100 chunks must be abandoned
    a few chunks in, not drained and then measured. If `read_capped_body` used
    `b"".join([c async for c in stream])` and checked the length afterwards,
    every assertion about the RESULT would still pass and this one would fail.
    """
    pulled: list[int] = []
    stream = _chunks(*[b"x" * 10 for _ in range(100)], counter=pulled)

    with pytest.raises(BodyTooLarge):
        asyncio.run(read_capped_body(stream, 25))

    # 10 + 10 + 10 = 30 > 25, so it must stop on the third chunk.
    assert len(pulled) == 3, pulled
    assert sum(pulled) <= 25 + 10


def test_the_refusal_carries_nothing_about_the_body() -> None:
    """Not even the size seen. A byte count for a request refused BEFORE
    verification is a measurement of an unauthenticated body, and putting
    request-derived numbers in refusals is how the next one carries content."""
    with pytest.raises(BodyTooLarge) as caught:
        asyncio.run(read_capped_body(_chunks(b"y" * 50), 10))
    assert str(caught.value) == ""
    assert not caught.value.args


def test_an_oversized_delivery_is_413_with_the_MODULES_code_and_no_database() -> None:
    """The status is the engine's, not this assembly's.

    `build_settings` points at an unreachable DSN, so a route that looked the
    endpoint up before capping would fail to connect rather than answer 413.
    Passing is therefore evidence about ORDER: the cap ran before the lookup,
    which is also before any signature could have been computed.
    """
    settings = build_settings(ingress_max_body_bytes=64)
    client = TestClient(create_app(settings))

    response = client.post(f"/ingress/{SENTINEL}", content=b"z" * 4096)

    assert response.status_code == 413
    assert response.json() == {"code": "payload_too_large"}
    # The engine owns the status, and this is where that is checked: 413 is
    # `PayloadTooLarge.STATUS`, never an integer typed into `assembly.py`.
    assert integration.PayloadTooLarge.STATUS == 413
    assert integration.PayloadTooLarge.CODE.value == "payload_too_large"


def test_the_refusal_body_does_not_echo_the_endpoint_key() -> None:
    settings = build_settings(ingress_max_body_bytes=64)
    client = TestClient(create_app(settings))
    response = client.post(f"/ingress/{SENTINEL}", content=b"z" * 4096)
    assert SENTINEL not in response.text


def test_a_malformed_key_is_not_answered_with_a_validation_error() -> None:
    """A constrained path parameter would make FastAPI answer 422 with the
    rejected value echoed into `detail.input` — the credential, in a response
    body and in the log line that response produces. The parameter is an
    unvalidated `str` precisely so that rejection has no way to happen here."""
    settings = build_settings(ingress_max_body_bytes=8)
    client = TestClient(create_app(settings))
    response = client.post("/ingress/not-a-valid-key-at-all", content=b"z" * 64)
    assert response.status_code == 413
    assert "not-a-valid-key-at-all" not in response.text


# ── The URL: a bearer credential in the request line ────────────────────────


def test_the_pattern_redacts_a_real_key_wherever_it_appears() -> None:
    line = f'127.0.0.1 - "POST /ingress/{SENTINEL} HTTP/1.1" 200'
    redacted = redact_ingress_keys(line)
    assert SENTINEL not in redacted
    assert "<redacted>" in redacted
    # Still a useful access log.
    assert "POST" in redacted and "200" in redacted and "HTTP/1.1" in redacted


def test_a_query_string_survives_and_a_malformed_key_is_still_redacted() -> None:
    """The malformed ones matter MOST: a probe carrying a credential lifted
    from somewhere else, or a truncated key. Matching only the valid 48-hex
    shape would publish exactly those."""
    line = f"GET /ingress/{SENTINEL[:12]}?hub.challenge=1234 HTTP/1.1"
    redacted = redact_ingress_keys(line)
    assert SENTINEL[:12] not in redacted
    assert "hub.challenge=1234" in redacted


def _capture(logger_name: str, *, filtered: bool) -> list[str]:
    """Emit uvicorn's own access-log call and return what a handler would write.

    The format string is uvicorn's (`uvicorn.logging.AccessFormatter`'s
    caller): the path travels in `record.args`, NOT in `record.msg`. A
    redaction that rewrote only `msg` would pass a naive test and leak on every
    real request, because the formatter interpolates `args` back in.
    """
    logger = logging.getLogger(logger_name)
    logger.filters = [
        f for f in logger.filters if not isinstance(f, IngressKeyRedactingFilter)
    ]
    if filtered:
        logger.addFilter(IngressKeyRedactingFilter())

    written: list[str] = []

    class Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            written.append(self.format(record))

    handler = Collector()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        logger.info(
            '%s - "%s %s HTTP/%s" %d',
            "10.0.0.1",
            "POST",
            f"/ingress/{SENTINEL}",
            "1.1",
            200,
        )
    finally:
        logger.removeHandler(handler)
    return written


def test_the_access_log_does_not_carry_the_endpoint_key() -> None:
    written = _capture("uvicorn.access", filtered=True)
    assert written, "the fixture logged nothing"
    assert all(SENTINEL not in line for line in written), written
    assert any("<redacted>" in line for line in written)


def test_the_redaction_is_load_bearing_and_not_a_vacuous_assertion() -> None:
    """THE SENSITIVITY PROOF, and the reason the test above is evidence.

    A `not in` assertion passes trivially if the value never had a route to
    that surface at all. So the same line is emitted with the filter REMOVED,
    and the credential must appear — proving the filter is what removes it
    rather than the credential never having been there.
    """
    written = _capture("uvicorn.access", filtered=False)
    assert any(SENTINEL in line for line in written), (
        "the sentinel never reached the access log even unfiltered, so the "
        "test above proves nothing about the redaction"
    )
    # And restore it, so an ordering change cannot leave the suite unfiltered.
    install_log_redaction()


def test_the_filter_redacts_the_ARGS_not_only_the_message() -> None:
    """The subtle half. In uvicorn's access record the path is an ARG; a
    redaction that rewrote `record.msg` alone would leave it in `record.args`
    for the formatter to interpolate straight back in — and a structured
    handler reading `args` would ship it untouched either way."""
    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="%s %s",
        args=("POST", f"/ingress/{SENTINEL}"),
        exc_info=None,
    )
    assert IngressKeyRedactingFilter().filter(record) is True
    assert SENTINEL not in record.getMessage()
    assert SENTINEL not in str(record.args)
    assert SENTINEL not in str(record.msg)


def test_the_key_cannot_become_a_metric_label() -> None:
    """The third surface. Structural rather than careful: the counter methods
    accept only members of a closed declared vocabulary, so there is no call
    that would offer an endpoint key — the renderer never even gets the
    chance."""
    with pytest.raises(telemetry.UndeclaredLabel):
        telemetry.counters.record_ingress_outcome(SENTINEL)
    with pytest.raises(telemetry.UndeclaredLabel):
        telemetry.counters.record_refusal(SENTINEL)
    with pytest.raises(telemetry.UndeclaredLabel):
        telemetry.render(
            [telemetry.Sample("integrator_ingress_outcomes_total", 1.0, SENTINEL)]
        )


def test_the_label_guard_is_load_bearing_too() -> None:
    """Sensitivity proof for the assertion above: a DECLARED value renders, so
    the refusals are about the vocabulary rather than about `record_*` being
    broken for everything."""
    output = telemetry.render(
        [telemetry.Sample("integrator_ingress_outcomes_total", 1.0, "accepted")]
    )
    assert 'code="accepted"' in output


def test_installing_the_redaction_twice_adds_one_filter() -> None:
    install_log_redaction()
    install_log_redaction()
    logger = logging.getLogger("uvicorn.access")
    installed = [f for f in logger.filters if isinstance(f, IngressKeyRedactingFilter)]
    assert len(installed) == 1
