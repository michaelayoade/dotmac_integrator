"""The dispatch intake route, the dispatch scope and the pump's boot checks."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import ValidationError

from dotmac_integrator import outbound
from dotmac_integrator.assembly import create_app
from dotmac_integrator.product_auth import ProductAuthenticator
from dotmac_integrator.settings import ProductQueryCaller, validate_settings
from tests.support import build_settings

KEY = "dispatch-key-with-enough-entropy"
BINDING = uuid4()
HEADERS = {"X-Api-Key": KEY}


def _caller(*binding_ids: Any) -> ProductQueryCaller:
    return ProductQueryCaller(
        application="academy",
        api_key_ref="file:///run/secrets/dispatch",
        scopes=("integration:dispatch",),
        binding_ids=binding_ids or (BINDING,),
    )


def _client(**overrides: Any) -> TestClient:
    app = create_app(
        build_settings(
            product_dispatch_enabled=True,
            product_query_callers=(_caller(),),
            product_contract_registry_enabled=True,
            product_contract_registry_url="https://app.example/contracts",
            product_contract_registry_expected_digest="a" * 64,
            product_contract_registry_api_key_ref="file:///run/secrets/contracts",
            **overrides,
        )
    )
    app.state.product_query_authenticator = ProductAuthenticator(
        app.state.settings.product_query_callers, secret_lookup=lambda _r: KEY
    )
    return TestClient(app)


def test_the_route_is_absent_while_the_flag_is_off() -> None:
    app = create_app(build_settings())
    assert "/product/v1/dispatches" not in {
        r.path for r in app.routes if isinstance(r, APIRoute)
    }


def test_a_dispatch_caller_is_bound_to_exactly_one_binding() -> None:
    with pytest.raises(ValidationError, match="exactly one binding"):
        _caller(uuid4(), uuid4())


def test_no_key_and_a_wrong_key_are_401() -> None:
    client = _client()
    body = {
        "dispatch_id": "d-1",
        "capability_binding_id": str(BINDING),
        "event_type": "e",
        "payload": {},
    }
    assert client.post("/product/v1/dispatches", json=body).status_code == 401
    assert (
        client.post(
            "/product/v1/dispatches", json=body, headers={"X-Api-Key": "wrong"}
        ).status_code
        == 401
    )


def test_the_route_returns_the_state_and_202_until_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake(engine: Any, principal: Any, body: Any, *, wait_seconds: float) -> Any:
        seen["wait"] = wait_seconds
        seen["key"] = body.dispatch_id
        return {"state": seen.get("state", "pending"), "terminal": seen["term"]}

    monkeypatch.setattr(outbound, "submit_dispatch", fake)
    client = _client()
    body = {
        "dispatch_id": "d-1",
        "capability_binding_id": str(BINDING),
        "event_type": "e",
        "payload": {},
    }
    seen["term"] = False
    assert (
        client.post("/product/v1/dispatches", json=body, headers=HEADERS).status_code
        == 202
    )
    seen["term"] = True
    assert (
        client.post("/product/v1/dispatches", json=body, headers=HEADERS).status_code
        == 200
    )
    assert seen["wait"] <= 20 and seen["key"] == "d-1"


def test_the_wait_can_never_exceed_twenty_seconds() -> None:
    with pytest.raises(ValidationError):
        build_settings(outbound_wait_seconds=21)


def test_the_route_refuses_a_binding_that_is_not_the_callers() -> None:
    response = _client().post(
        "/product/v1/dispatches",
        headers=HEADERS,
        json={
            "dispatch_id": "d-1",
            "capability_binding_id": str(uuid4()),
            "event_type": "e",
            "payload": {},
        },
    )
    assert response.status_code == 403


def test_dispatch_needs_a_dispatch_caller() -> None:
    problems = validate_settings(build_settings(product_dispatch_enabled=True))
    assert any("PRODUCT_DISPATCH_ENABLED" in p for p in problems)


def test_the_pump_is_refused_without_retention_and_a_longer_lease() -> None:
    problems = validate_settings(build_settings(outbound_pump_enabled=True))
    text = "\n".join(problems)
    assert "OUTBOUND_REPLAY_EVIDENCE_RETENTION_DAYS" in text
    assert "OUTBOUND_LEGAL_POLICY_OWNER" in text
    ok = validate_settings(
        build_settings(
            outbound_pump_enabled=True,
            outbound_replay_evidence_retention_days=30,
            outbound_legal_policy_owner="owner",
            worker_enabled=True,
        )
    )
    assert ok == []


def test_a_budget_the_lease_does_not_exceed_refuses_the_pump() -> None:
    problems = validate_settings(
        build_settings(
            outbound_pump_enabled=True,
            outbound_replay_evidence_retention_days=30,
            outbound_legal_policy_owner="owner",
            outbound_data_budget_seconds=100_000,
            worker_enabled=True,
        )
    )
    assert any("lease must be longer" in p for p in problems)
    assert outbound.lease_exceeds_budget(300, 120)
    assert not outbound.lease_exceeds_budget(120, 120)


def test_the_pump_is_off_by_default() -> None:
    s = build_settings()
    assert s.outbound_pump_enabled is False and s.product_dispatch_enabled is False
    assert s.outbound_payload_retention_days == 7
