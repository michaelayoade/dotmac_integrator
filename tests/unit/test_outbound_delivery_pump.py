"""The assembly drives the module-owned outbound engine faithfully."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from uuid import UUID, uuid4

import dotmac_integration as integration
import pytest
from sqlalchemy import create_engine

from dotmac_integrator import outbound

DELIVERY_ID = UUID("00000000-0000-4000-8000-000000000101")


class _Session:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.closed = False

    def __enter__(self) -> _Session:
        self.events.append("session-open")
        return self

    def __exit__(self, *_args: object) -> None:
        self.closed = True
        self.events.append("session-close")

    def get(self, _model: object, identifier: UUID) -> object | None:
        self.events.append("get")
        return _Delivery(identifier)

    def commit(self) -> None:
        self.events.append("commit")


@dataclass
class _Delivery:
    id: UUID


def _factory(events: list[str]) -> Callable[[], _Session]:
    return lambda: _Session(events)


def test_one_dispatch_closes_the_prepare_session_before_connector_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    prepared = object()
    sessions: list[_Session] = []

    def factory() -> _Session:
        session = _Session(events)
        sessions.append(session)
        return session

    def prepare(db: _Session, delivery: object, *, registry: object) -> object:
        assert db.closed is False
        events.append("prepare")
        return prepared

    def invoke(value: object, *, registry: object, resolve_secrets: object) -> object:
        assert value is prepared
        assert sessions[0].closed is True
        events.append("invoke")
        return object()

    def settle(
        db: _Session, delivery: object, outcome: object, *, prepared: object
    ) -> object:
        assert sessions[1].closed is False
        events.append("settle")
        return delivery

    monkeypatch.setattr(integration, "prepare", prepare)
    monkeypatch.setattr(integration, "invoke", invoke)
    monkeypatch.setattr(integration, "settle", settle)

    result = outbound.dispatch_one(
        DELIVERY_ID,
        session_factory=factory,
        registry=object(),
        resolve_secrets=lambda _refs: {},
    )

    assert result is outbound.DispatchResult.SETTLED
    assert events == [
        "session-open",
        "get",
        "prepare",
        "commit",
        "session-close",
        "invoke",
        "session-open",
        "get",
        "settle",
        "commit",
        "session-close",
    ]


def test_a_contended_claim_never_invokes_a_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(integration, "prepare", lambda *_args, **_kwargs: None)

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a worker without the claim invoked the connector")

    monkeypatch.setattr(integration, "invoke", forbidden)

    result = outbound.dispatch_one(
        DELIVERY_ID,
        session_factory=_factory([]),
        registry=object(),
        resolve_secrets=lambda _refs: {},
    )
    assert result is outbound.DispatchResult.CONTENDED


def test_a_missing_candidate_is_not_treated_as_a_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class Missing(_Session):
        def get(self, _model: object, identifier: UUID) -> None:
            self.events.append("get")
            return None

    monkeypatch.setattr(
        integration,
        "prepare",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("prepare called for a missing row")
        ),
    )
    result = outbound.dispatch_one(
        DELIVERY_ID,
        session_factory=lambda: Missing(events),
        registry=object(),
        resolve_secrets=lambda _refs: {},
    )
    assert result is outbound.DispatchResult.MISSING


def test_a_lost_settlement_is_reported_and_never_committed_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(integration, "prepare", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(integration, "invoke", lambda *_args, **_kwargs: object())

    def lose(*_args: object, **_kwargs: object) -> None:
        raise integration.LostClaim("superseded")

    monkeypatch.setattr(integration, "settle", lose)
    result = outbound.dispatch_one(
        DELIVERY_ID,
        session_factory=_factory(events),
        registry=object(),
        resolve_secrets=lambda _refs: {},
    )
    assert result is outbound.DispatchResult.LOST
    assert events.count("commit") == 1


def test_one_unavailable_delivery_does_not_starve_the_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identifiers = (uuid4(), uuid4(), uuid4())
    outcomes: Iterator[integration.DispatchUnavailable | outbound.DispatchResult] = (
        iter(
            [
                integration.DispatchUnavailable("configuration"),
                outbound.DispatchResult.SETTLED,
                outbound.DispatchResult.CONTENDED,
            ]
        )
    )

    monkeypatch.setattr(outbound, "due_delivery_ids", lambda *_args: identifiers)

    def drive(*_args: object, **_kwargs: object) -> outbound.DispatchResult:
        result = next(outcomes)
        if isinstance(result, integration.DispatchUnavailable):
            raise result
        return result

    monkeypatch.setattr(outbound, "dispatch_one", drive)

    engine = create_engine(
        "postgresql+psycopg://platform_api@127.0.0.1:1/integrator_test"
    )
    report = outbound.dispatch_due_deliveries(
        engine, limit=3, registry=object(), resolve_secrets=lambda _refs: {}
    )
    assert report == {
        "candidates": 3,
        "settled": 1,
        "contended": 1,
        "missing": 0,
        "lost": 0,
        "unavailable": 1,
    }


def test_the_candidate_selector_is_a_hint_not_a_lock() -> None:
    source = outbound.due_delivery_ids.__doc__ or ""
    assert "hint" in source.lower()
    code = __import__("inspect").getsource(outbound.due_delivery_ids)
    assert "with_for_update" not in code
    assert "skip_locked" not in code
