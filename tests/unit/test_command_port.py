"""The product command port authenticates before it can enqueue anything.

The source application names a capability and a stable idempotency key.  It
never names a connector or a provider: selecting the one enabled transport is
the integration module's decision.  These tests exercise both sides of that
boundary without opening a database connection.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from dotmac_integrator import command_port
from dotmac_integrator.assembly import create_app
from dotmac_integrator.settings import Settings
from tests.support import build_settings


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "command_port_enabled": True,
        "command_port_api_key_ref": "env://INTEGRATOR_SECRET_COMMAND_PORT",
    }
    return build_settings(**{**values, **overrides})


def _client(monkeypatch: pytest.MonkeyPatch, *, held: str | None) -> TestClient:
    monkeypatch.setattr(command_port, "get_secret", lambda _reference: held)
    return TestClient(create_app(_settings()))


def _body(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "capability_id": "messaging.send.v1",
        "event_type": "send_text",
        "idempotency_key": "sub:message:42",
        "payload": {"to": "2348000000000", "text": "hello"},
    }
    return {**base, **overrides}


def test_the_command_route_is_absent_until_explicitly_enabled() -> None:
    paths = {
        route.path
        for route in create_app(build_settings()).routes
        if isinstance(route, APIRoute)
    }
    assert "/commands/deliveries" not in paths


@pytest.mark.parametrize("credential", [None, "", "wrong-material"])
def test_a_command_without_the_held_credential_never_reaches_the_service(
    monkeypatch: pytest.MonkeyPatch, credential: str | None
) -> None:
    called = False

    def must_not_enqueue(*_args: Any, **_kwargs: Any) -> dict[str, object]:
        nonlocal called
        called = True
        raise AssertionError("unauthenticated command reached the outbox")

    monkeypatch.setattr(command_port, "enqueue", must_not_enqueue)
    headers = {"X-Api-Key": credential} if credential is not None else {}

    response = _client(monkeypatch, held="held-material").post(
        "/commands/deliveries", json=_body(), headers=headers
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "not found"}
    assert called is False


def test_a_missing_held_reference_is_a_failed_mechanism_not_open_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _client(monkeypatch, held=None).post(
        "/commands/deliveries",
        json=_body(),
        headers={"X-Api-Key": "anything"},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "command authentication unavailable"}


def test_an_authenticated_command_delegates_without_a_provider_identifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def capture(_engine: object, **values: object) -> dict[str, object]:
        seen.update(values)
        return {
            "delivery_id": "00000000-0000-4000-8000-000000000001",
            "state": "pending",
            "is_new": True,
            "payload_digest": "a" * 64,
        }

    monkeypatch.setattr(command_port, "enqueue", capture)
    response = _client(monkeypatch, held="held-material").post(
        "/commands/deliveries",
        json=_body(),
        headers={"X-Api-Key": "held-material"},
    )

    assert response.status_code == 202
    assert response.json()["state"] == "pending"
    assert seen == _body()
    assert not {"connector_key", "installation_id", "provider"} & set(seen)


@pytest.mark.parametrize("field", ["capability_id", "event_type", "idempotency_key"])
def test_command_identity_fields_refuse_whitespace(
    monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    response = _client(monkeypatch, held="held-material").post(
        "/commands/deliveries",
        json=_body(**{field: "  "}),
        headers={"X-Api-Key": "held-material"},
    )
    assert response.status_code == 422


def test_command_auth_uses_constant_time_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compared: list[tuple[str, str]] = []

    def compare(left: str, right: str) -> bool:
        compared.append((left, right))
        return True

    monkeypatch.setattr(command_port, "compare_digest", compare)
    monkeypatch.setattr(
        command_port,
        "enqueue",
        lambda *_args, **_kwargs: {
            "delivery_id": "00000000-0000-4000-8000-000000000001",
            "state": "pending",
            "is_new": True,
            "payload_digest": "a" * 64,
        },
    )
    response = _client(monkeypatch, held="held-material").post(
        "/commands/deliveries",
        json=_body(),
        headers={"X-Api-Key": "presented-material"},
    )

    assert response.status_code != 404
    assert compared == [("presented-material", "held-material")]


class _UnitOfWork:
    def __init__(self) -> None:
        self.committed = False

    def __enter__(self) -> _UnitOfWork:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def commit(self) -> None:
        self.committed = True


@pytest.mark.parametrize(
    ("error_type", "status_code", "detail"),
    [
        (
            command_port.integration.DeliveryIdempotencyConflict,
            409,
            "idempotency key already identifies a different command",
        ),
        (
            command_port.integration.DeliveryEnqueueRaced,
            503,
            "concurrent enqueue is not visible yet; retry this command",
        ),
    ],
)
def test_module_owned_enqueue_refusals_cross_the_port_without_material(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
    status_code: int,
    detail: str,
) -> None:
    db = _UnitOfWork()
    monkeypatch.setattr(command_port, "Session", lambda _engine: db)
    monkeypatch.setattr(
        command_port.integration,
        "resolve_binding",
        lambda *_args, **_kwargs: SimpleNamespace(
            installation_id="installation-material", id="binding-material"
        ),
    )

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise error_type("provider-secret payload-material key-material")

    monkeypatch.setattr(command_port.integration, "enqueue_delivery", refuse)

    with pytest.raises(HTTPException) as caught:
        command_port.enqueue(object(), **_body())  # type: ignore[arg-type]

    assert caught.value.status_code == status_code
    assert caught.value.detail == detail
    assert "material" not in str(caught.value.detail)
    assert db.committed is False
