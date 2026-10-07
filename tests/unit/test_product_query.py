"""Provider-neutral product query adapter and HTTP surface."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from dotmac_integrator import assembly, query, runtime_policy, telemetry
from dotmac_integrator.product_auth import ProductPrincipal, require_product_query
from dotmac_integrator.query import ProductQueryRequest, ProductQueryResponse
from dotmac_integrator.settings import ProductQueryCaller, Settings
from dotmac_integrator.surface import RouteClass, audit_routes, classify
from tests.support import build_settings


class RecordingDispatcher:
    def __init__(
        self,
        result: ProductQueryResponse | None = None,
    ) -> None:
        self.calls: list[tuple[str, UUID, dict[str, object]]] = []
        self.result = result or ProductQueryResponse(
            status="ok", observation={"available": True}
        )

    def dispatch(
        self,
        *,
        engine: Any,
        application: str,
        capability_binding_id: UUID,
        payload: dict[str, object],
    ) -> ProductQueryResponse:
        del engine
        self.calls.append((application, capability_binding_id, payload))
        return self.result


class RaisingDispatcher:
    def dispatch(self, **_: object) -> ProductQueryResponse:
        raise RuntimeError("provider exception with secret material")


class RecordingQueryCounters:
    def __init__(self) -> None:
        self.records: list[tuple[str, float]] = []

    def record(self, outcome: str, duration_seconds: float) -> None:
        self.records.append((outcome, duration_seconds))


def test_provider_health_query_accepts_an_empty_payload() -> None:
    request = ProductQueryRequest(
        schema_version="dotmac.io/integration-query-request/v1",
        capability_binding_id=uuid4(),
        payload={},
    )

    assert request.payload == {}


def _settings(binding_id: UUID) -> Settings:
    caller = ProductQueryCaller(
        application="dotmac_erp",
        api_key_ref="file:///run/secrets/product-query/erp",
        scopes=("integration:query",),
        binding_ids=(binding_id,),
    )
    return build_settings(
        product_query_enabled=True,
        product_query_callers=(caller,),
        product_contract_registry_enabled=True,
        product_contract_registry_url="https://erp.example/internal/query-contracts",
        product_contract_registry_expected_digest="a" * 64,
        product_contract_registry_api_key_ref=(
            "file:///run/secrets/product-contracts/erp"
        ),
    )


def _principal(binding_id: UUID) -> ProductPrincipal:
    return ProductPrincipal(
        application="dotmac_erp",
        scopes=frozenset({"integration:query"}),
        binding_ids=frozenset({binding_id}),
    )


def test_product_query_route_passes_only_binding_application_and_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dispatcher = RecordingDispatcher()
    binding_id = uuid4()
    monkeypatch.setattr(
        runtime_policy, "require_declared_runtime_boundaries", lambda: None
    )
    app = assembly.create_app(_settings(binding_id), query_dispatcher=dispatcher)
    app.dependency_overrides[require_product_query] = lambda: _principal(binding_id)

    response = TestClient(app).post(
        "/product/v1/queries",
        json={
            "schema_version": "dotmac.io/integration-query-request/v1",
            "capability_binding_id": str(binding_id),
            "payload": {
                "operation": "device.latest_position",
                "device_ref": "42",
            },
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "schema_version": "dotmac.io/integration-query-response/v1",
        "status": "ok",
        "observation": {"available": True},
    }
    assert dispatcher.calls == [
        (
            "dotmac_erp",
            binding_id,
            {"operation": "device.latest_position", "device_ref": "42"},
        )
    ]


def test_a_product_cannot_query_an_unapproved_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dispatcher = RecordingDispatcher()
    allowed = uuid4()
    requested = uuid4()
    monkeypatch.setattr(
        runtime_policy, "require_declared_runtime_boundaries", lambda: None
    )
    app = assembly.create_app(_settings(allowed), query_dispatcher=dispatcher)
    app.dependency_overrides[require_product_query] = lambda: _principal(allowed)

    response = TestClient(app).post(
        "/product/v1/queries",
        json={
            "schema_version": "dotmac.io/integration-query-request/v1",
            "capability_binding_id": str(requested),
            "payload": {"operation": "device.latest_position"},
        },
    )

    assert response.status_code == 403
    assert dispatcher.calls == []


def test_route_records_one_bounded_outcome_and_duration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding_id = uuid4()
    counters = RecordingQueryCounters()
    clock = iter((10.0, 10.125))
    monkeypatch.setattr(
        runtime_policy, "require_declared_runtime_boundaries", lambda: None
    )
    monkeypatch.setattr(telemetry, "query_counters", counters)
    monkeypatch.setattr(telemetry, "monotonic_seconds", clock.__next__)
    app = assembly.create_app(
        _settings(binding_id), query_dispatcher=RecordingDispatcher()
    )
    app.dependency_overrides[require_product_query] = lambda: _principal(binding_id)

    response = TestClient(app).post(
        "/product/v1/queries",
        json={
            "schema_version": "dotmac.io/integration-query-request/v1",
            "capability_binding_id": str(binding_id),
            "payload": {"operation": "device.latest_position"},
        },
    )

    assert response.status_code == 200
    assert counters.records == [("ok", 0.125)]


def test_unexpected_dispatcher_exception_is_normalized_without_leakage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding_id = uuid4()
    counters = RecordingQueryCounters()
    clock = iter((20.0, 20.5))
    monkeypatch.setattr(
        runtime_policy, "require_declared_runtime_boundaries", lambda: None
    )
    monkeypatch.setattr(telemetry, "query_counters", counters)
    monkeypatch.setattr(telemetry, "monotonic_seconds", clock.__next__)
    app = assembly.create_app(
        _settings(binding_id), query_dispatcher=RaisingDispatcher()
    )
    app.dependency_overrides[require_product_query] = lambda: _principal(binding_id)

    response = TestClient(app).post(
        "/product/v1/queries",
        json={
            "schema_version": "dotmac.io/integration-query-request/v1",
            "capability_binding_id": str(binding_id),
            "payload": {"operation": "device.latest_position"},
        },
    )

    assert response.status_code == 503
    assert response.json() == {
        "schema_version": "dotmac.io/integration-query-response/v1",
        "status": "provider_unavailable",
        "observation": None,
    }
    assert "secret material" not in response.text
    assert counters.records == [("provider_unavailable", 0.5)]


@pytest.mark.parametrize(
    ("status", "expected_http"),
    [
        ("provider_unavailable", 503),
        ("unauthorized_provider_session", 502),
        ("not_found", 404),
        ("invalid_query", 422),
        ("timeout", 504),
        ("malformed_provider_response", 502),
    ],
)
def test_provider_failure_has_fixed_http_and_response_envelope(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    expected_http: int,
) -> None:
    binding_id = uuid4()
    dispatcher = RecordingDispatcher(
        ProductQueryResponse.model_validate({"status": status})
    )
    monkeypatch.setattr(
        runtime_policy, "require_declared_runtime_boundaries", lambda: None
    )
    app = assembly.create_app(_settings(binding_id), query_dispatcher=dispatcher)
    app.dependency_overrides[require_product_query] = lambda: _principal(binding_id)

    response = TestClient(app).post(
        "/product/v1/queries",
        json={
            "schema_version": "dotmac.io/integration-query-request/v1",
            "capability_binding_id": str(binding_id),
            "payload": {"operation": "device.latest_position"},
        },
    )

    assert response.status_code == expected_http
    assert response.json() == {
        "schema_version": "dotmac.io/integration-query-response/v1",
        "status": status,
        "observation": None,
    }


@pytest.mark.parametrize(
    "document",
    [
        {"status": "provider_says_retry", "observation": None},
        {
            "status": "provider_unavailable",
            "observation": None,
            "provider_response": {"secret": "raw"},
        },
        {"status": "provider_unavailable", "observation": {"raw": "body"}},
        {"status": "ok", "observation": None},
    ],
)
def test_dispatcher_response_cannot_choose_arbitrary_status_or_envelope(
    document: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        ProductQueryResponse.model_validate(document)


def test_product_query_surface_is_absent_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runtime_policy, "require_declared_runtime_boundaries", lambda: None
    )
    app = assembly.create_app(build_settings())
    paths = {getattr(route, "path", "") for route in app.routes}

    assert "/product/v1/queries" not in paths


def test_product_route_has_its_own_audited_surface_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding_id = uuid4()
    monkeypatch.setattr(
        runtime_policy, "require_declared_runtime_boundaries", lambda: None
    )
    app = assembly.create_app(
        _settings(binding_id), query_dispatcher=RecordingDispatcher()
    )

    assert classify("/product/v1/queries") is RouteClass.PRODUCT
    assert audit_routes(app, metrics_path=app.state.settings.metrics_path) == []


def test_product_surface_audit_rejects_a_route_without_machine_guard() -> None:
    app = FastAPI()

    @app.post("/product/v1/queries")
    def unguarded_product_route() -> dict[str, str]:
        return {}

    violations = audit_routes(app)

    assert any("require_product_query" in violation for violation in violations)


def test_enabling_product_queries_builds_the_real_dispatcher_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding_id = uuid4()
    monkeypatch.setattr(
        runtime_policy, "require_declared_runtime_boundaries", lambda: None
    )

    dispatcher = RecordingDispatcher()
    monkeypatch.setattr(query, "IntegrationQueryDispatcher", lambda: dispatcher)

    app = assembly.create_app(_settings(binding_id))

    assert "/product/v1/queries" in {getattr(route, "path", "") for route in app.routes}
