"""ADR-0009 at runtime: loaded once, refreshed explicitly, never leaked.

Six properties, each of which has a real failure behind it:

1. resolution is a dict lookup — the source is read once, not per call;
2. a source that starts failing after install cannot touch a running process;
3. rotation happens when an operator asks, never on a timer;
4. a FAILED refresh keeps the working set;
5. a failing source raises at install — no degraded start;
6. names and references may be printed; values never.

The sockets are removed for the whole module. A resolution that reached a
network would fail loudly here rather than pass slowly.
"""

from __future__ import annotations

import logging
import socket
from collections.abc import Iterator, Mapping

import dotmac_kernel.secret_sources as ks
import pytest

from dotmac_integrator.secret_resolver import (
    REDACTION,
    SecretsNotHeld,
    held_references,
    missing_references,
    redact,
    resolve_secrets,
)

REF = "env://INTEGRATOR_SECRET_TOKEN"
OTHER = "file:///run/secrets/other"


class _NetworkUsed(RuntimeError):
    pass


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _forbidden(*args: object, **kwargs: object) -> None:
        raise _NetworkUsed(
            "the resolution path opened a socket — a secret is HELD, not "
            "fetched while handling a request (ADR-0009)"
        )

    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)


@pytest.fixture(autouse=True)
def clean_store() -> Iterator[None]:
    ks.clear_secret_source()
    yield
    ks.clear_secret_source()


class _Source:
    """A source that counts its reads and can be made to fail."""

    def __init__(self, material: dict[str, str]) -> None:
        self.material = material
        self.calls = 0
        self.broken = False

    def load(self) -> Mapping[str, str]:
        self.calls += 1
        if self.broken:
            raise ConnectionError("the store is unreachable")
        return dict(self.material)


def test_the_no_network_fixture_actually_fires() -> None:
    """Sensitivity proof: without this, every test below passes because nothing
    tried, not because nothing may."""
    with pytest.raises(_NetworkUsed):
        socket.socket()
    with pytest.raises(_NetworkUsed):
        socket.create_connection(("example.invalid", 80))


def test_resolution_reads_the_source_once_however_many_lookups() -> None:
    source = _Source({REF: "a-real-token"})
    ks.install_secret_source(source)
    for _ in range(50):
        assert resolve_secrets({"api_key": REF}) == {"api_key": "a-real-token"}
    assert source.calls == 1


def test_a_source_that_breaks_after_install_cannot_reach_a_request() -> None:
    source = _Source({REF: "a-real-token"})
    ks.install_secret_source(source)
    source.broken = True
    assert resolve_secrets({"api_key": REF}) == {"api_key": "a-real-token"}


def test_rotation_is_explicit_and_takes_effect_when_asked() -> None:
    source = _Source({REF: "old-material"})
    ks.install_secret_source(source)
    source.material[REF] = "new-material"
    assert resolve_secrets({"k": REF}) == {"k": "old-material"}
    ks.refresh_secrets()
    assert resolve_secrets({"k": REF}) == {"k": "new-material"}


def test_a_failed_refresh_keeps_the_working_set() -> None:
    source = _Source({REF: "working-material"})
    ks.install_secret_source(source)
    source.broken = True
    with pytest.raises(ks.SecretSourceError):
        ks.refresh_secrets()
    assert resolve_secrets({"k": REF}) == {"k": "working-material"}


def test_a_failing_source_raises_at_install() -> None:
    source = _Source({REF: "x"})
    source.broken = True
    with pytest.raises(ks.SecretSourceError, match="could not load secrets"):
        ks.install_secret_source(source)
    assert held_references() == ()


def test_resolution_refuses_a_partial_mapping() -> None:
    """A connector handed half its credentials authenticates as nobody and
    fails at the provider, which is a much worse diagnosis than a refusal."""
    ks.install_secret_source(_Source({REF: "held-material"}))
    with pytest.raises(SecretsNotHeld) as caught:
        resolve_secrets({"api_key": REF, "api_secret": OTHER})
    assert OTHER in str(caught.value)
    assert "held-material" not in str(caught.value)


def test_missing_references_reports_all_of_them_not_the_first() -> None:
    ks.install_secret_source(_Source({}))
    absent = missing_references({"a": REF, "b": OTHER})
    assert absent == {"a": REF, "b": OTHER}


def test_nothing_logged_at_install_contains_a_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger=ks.__name__):
        ks.install_secret_source(_Source({REF: "the-actual-material"}))
    logged = caplog.text
    assert REF in logged, "the reference should be nameable — it is a pointer"
    assert "the-actual-material" not in logged


def test_redaction_removes_a_held_value_from_a_message() -> None:
    ks.install_secret_source(_Source({REF: "sk-live-abcdefghijklmnop"}))
    leaked = "auth failed for token sk-live-abcdefghijklmnop at the provider"
    cleaned = redact(leaked)
    assert "sk-live-abcdefghijklmnop" not in cleaned
    assert REDACTION in cleaned
    assert cleaned.startswith("auth failed for token ")


def test_redaction_is_a_no_op_when_nothing_is_held() -> None:
    """Sensitivity proof for `redact`: it must be the HELD value doing the
    work, not some incidental substitution that would fire on any string."""
    ks.install_secret_source(_Source({}))
    message = "auth failed for token sk-live-abcdefghijklmnop"
    assert redact(message) == message


def test_an_empty_held_set_is_legitimate_and_refuses_every_reference() -> None:
    """A deployment with no connectors configured holds nothing. That is not a
    failure — but it must still refuse an enablement rather than pass `{}`."""
    ks.install_secret_source(_Source({}))
    assert held_references() == ()
    assert resolve_secrets({}) == {}
    with pytest.raises(SecretsNotHeld):
        resolve_secrets({"k": REF})
