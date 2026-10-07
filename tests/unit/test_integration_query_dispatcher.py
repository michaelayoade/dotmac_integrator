from __future__ import annotations

from types import SimpleNamespace
from typing import cast
from uuid import UUID, uuid4

import dotmac_integration as integration
import pytest
from sqlalchemy.engine import Engine

from dotmac_integrator import query


def test_dispatcher_closes_preparation_session_before_provider_invocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {"session_open": False}
    prepared = SimpleNamespace(capability_id="fleet.tracking.position.latest.v1")
    contract = SimpleNamespace(owner=SimpleNamespace(application="dotmac_erp"))
    capabilities = SimpleNamespace(get=lambda capability_id: contract)
    connectors = cast(integration.ConnectorRegistry, object())

    class FakeSession:
        def __init__(self, engine: object) -> None:
            self.engine = engine

        def __enter__(self) -> FakeSession:
            state["session_open"] = True
            return self

        def __exit__(self, *args: object) -> None:
            state["session_open"] = False

    def prepare(
        db: Engine,
        binding_id: UUID,
        payload: dict[str, object],
        **kwargs: object,
    ) -> SimpleNamespace:
        assert state["session_open"] is True
        assert kwargs == {
            "registry": connectors,
            "capability_registry": capabilities,
        }
        return prepared

    def execute(value: object, **kwargs: object) -> integration.QueryResult:
        assert value is prepared
        assert state["session_open"] is False
        assert kwargs["registry"] is connectors
        assert kwargs["capability_registry"] is capabilities
        return integration.QueryResult(
            status=integration.QueryStatus.SUCCEEDED,
            observation={"latitude": 9.0, "longitude": 7.0},
        )

    monkeypatch.setattr(query, "Session", FakeSession)
    monkeypatch.setattr(integration, "capability_registry", lambda: capabilities)
    monkeypatch.setattr(integration, "prepare_query", prepare)
    monkeypatch.setattr(integration, "execute_prepared_query", execute)

    result = query.IntegrationQueryDispatcher(connectors).dispatch(
        engine=cast(Engine, object()),
        application="dotmac_erp",
        capability_binding_id=uuid4(),
        payload={"provider_device_ref": "device-1"},
    )

    assert result.status == "ok"
    assert result.observation == {"latitude": 9.0, "longitude": 7.0}


def test_dispatcher_normalizes_every_internal_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        integration,
        "capability_registry",
        lambda: (_ for _ in ()).throw(RuntimeError("provider secret")),
    )

    registry = cast(integration.ConnectorRegistry, object())
    result = query.IntegrationQueryDispatcher(registry).dispatch(
        engine=cast(Engine, object()),
        application="dotmac_erp",
        capability_binding_id=uuid4(),
        payload={"provider_device_ref": "device-1"},
    )

    assert result.model_dump() == {
        "schema_version": "dotmac.io/integration-query-response/v1",
        "status": "provider_unavailable",
        "observation": None,
    }
