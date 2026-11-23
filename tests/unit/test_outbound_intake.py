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
from dotmac_integrator.product_auth import ProductAuthenticator, ProductPrincipal
from dotmac_integrator.settings import (
    ProductQueryCaller,
    Settings,
    validate_settings,
)
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

    async def fake(
        engine: Any, principal: Any, body: Any, *, wait_seconds: float, **_kw: Any
    ) -> Any:
        seen["wait"] = wait_seconds
        seen["key"] = body.dispatch_id
        return {"state": seen.get("state", "pending"), "terminal": seen["term"]}

    monkeypatch.setattr(outbound, "submit_dispatch_async", fake)
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
    assert outbound.lease_exceeds_budget(300, 256, 30)
    assert not outbound.lease_exceeds_budget(286, 256, 30)


def _pump_settings(**overrides: object) -> Settings:
    return build_settings(
        outbound_pump_enabled=True,
        outbound_replay_evidence_retention_days=30,
        outbound_legal_policy_owner="owner",
        worker_enabled=True,
        **overrides,
    )


def test_the_default_budget_covers_the_connector_worst_case() -> None:
    """SEND_DEADLINE_SECONDS is 240 and the TLS handshake makes about 255 s."""
    s = build_settings()
    assert s.outbound_data_budget_seconds >= 255
    assert s.outbound_lease_margin_seconds > 0
    assert validate_settings(_pump_settings()) == []


def test_startup_refuses_a_lease_too_short_for_the_connector_deadline() -> None:
    from dotmac_integration import DEFAULT_POLICY

    lease = DEFAULT_POLICY.lease_seconds
    # Deadline alone fits under the lease, the margin does not: refused.
    too_tight = validate_settings(
        _pump_settings(
            outbound_data_budget_seconds=lease - 5,
            outbound_lease_margin_seconds=30,
        )
    )
    assert any("OUTBOUND_LEASE_MARGIN_SECONDS" in p for p in too_tight)
    # A connector deadline at or past the lease is refused.
    assert validate_settings(_pump_settings(outbound_data_budget_seconds=lease))
    # Exactly lease - 1 with no margin is allowed; the boundary is strict.
    assert (
        validate_settings(
            _pump_settings(
                outbound_data_budget_seconds=lease - 1,
                outbound_lease_margin_seconds=0,
            )
        )
        == []
    )
    # The pump off: nothing is checked (flags-off default stays inert).
    assert (
        validate_settings(build_settings(outbound_data_budget_seconds=lease * 10)) == []
    )


def test_the_pump_is_off_by_default() -> None:
    s = build_settings()
    assert s.outbound_pump_enabled is False and s.product_dispatch_enabled is False
    assert s.outbound_payload_retention_days == 7


def test_a_dispatch_scope_stands_alone() -> None:
    with pytest.raises(ValidationError, match="only scope"):
        ProductQueryCaller(
            application="a",
            api_key_ref="file:///x",
            scopes=("integration:dispatch", "integration:query"),
            binding_ids=(BINDING,),
        )


def test_an_oversized_payload_is_413() -> None:
    from fastapi import HTTPException

    principal = ProductPrincipal(
        "academy", frozenset({"integration:dispatch"}), frozenset({BINDING})
    )
    body = outbound.DispatchBody(
        dispatch_id="d",
        capability_binding_id=BINDING,
        event_type="e",
        payload={"x": "y" * 100},
    )
    with pytest.raises(HTTPException) as refused:
        outbound.enqueue_dispatch(
            None,  # type: ignore[arg-type]
            principal,
            body,
            capabilities=object(),
            max_payload_bytes=50,
        )
    assert refused.value.status_code == 413


def test_operator_routes_answer_while_many_dispatches_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wait is `await asyncio.sleep`, so 120 waiting dispatches (three times
    the thread pool) leave the operator surface, and the kill switch with it,
    answering at once."""
    import asyncio
    import time

    import httpx

    from dotmac_integrator.operator_auth import OperatorIdentity, require_operator

    queued = outbound.Enqueued(
        uuid4(),
        "d",
        True,
        {"state": "pending", "terminal": False, "dispatch_id": "d"},
    )
    monkeypatch.setattr(outbound, "enqueue_dispatch", lambda *a, **k: queued)
    monkeypatch.setattr(outbound, "current_view", lambda *a, **k: queued.view)

    app = create_app(
        build_settings(
            product_dispatch_enabled=True,
            product_query_callers=(_caller(),),
            product_contract_registry_enabled=True,
            product_contract_registry_url="https://app.example/contracts",
            product_contract_registry_expected_digest="a" * 64,
            product_contract_registry_api_key_ref="file:///run/secrets/contracts",
            outbound_wait_seconds=2,
            outbound_max_waiters=200,
        )
    )
    app.state.product_query_authenticator = ProductAuthenticator(
        app.state.settings.product_query_callers, secret_lookup=lambda _r: KEY
    )
    app.dependency_overrides[require_operator] = lambda: OperatorIdentity(
        admin_id=uuid4(), label="op", mechanism="platform_admin"
    )
    body = {
        "dispatch_id": "d",
        "capability_binding_id": str(BINDING),
        "event_type": "e",
        "payload": {},
    }

    async def scenario() -> float:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            waiting = [
                asyncio.create_task(
                    c.post("/product/v1/dispatches", json=body, headers=HEADERS)
                )
                for _ in range(120)
            ]
            await asyncio.sleep(0.5)  # every dispatch is now waiting
            started = time.monotonic()
            response = await c.get("/operations/connectors")
            elapsed = time.monotonic() - started
            assert response.status_code == 200
            results = await asyncio.gather(*waiting)
            assert {r.status_code for r in results} == {202}
            return elapsed

    assert asyncio.run(scenario()) < 1.0
