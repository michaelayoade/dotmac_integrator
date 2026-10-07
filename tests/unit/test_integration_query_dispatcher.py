from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import dotmac_integration as integration

from dotmac_integrator import query


def test_dispatcher_closes_preparation_session_before_provider_invocation(
    monkeypatch,
) -> None:
    state = {"session_open": False}
    prepared = SimpleNamespace(capability_id="fleet.tracking.position.latest.v1")
    contract = SimpleNamespace(owner=SimpleNamespace(application="dotmac_erp"))
    capabilities = SimpleNamespace(get=lambda capability_id: contract)
    connectors = object()

    class FakeSession:
        def __init__(self, engine: object) -> None:
            self.engine = engine

        def __enter__(self) -> FakeSession:
            state["session_open"] = True
            return self

        def __exit__(self, *args: object) -> None:
            state["session_open"] = False

    def prepare(db, binding_id, payload, **kwargs):
        assert state["session_open"] is True
        assert kwargs == {
            "registry": connectors,
            "capability_registry": capabilities,
        }
        return prepared

    def execute(value, **kwargs):
        assert value is prepared
        assert state["session_open"] is False
        assert kwargs["registry"] is connectors
        assert kwargs["capability_registry"] is capabilities
        return integration.QueryResult(
            status=integration.QueryStatus.SUCCEEDED,
            observation={"latitude": 9.0, "longitude": 7.0},
        )

    monkeypatch.setattr(query, "Session", FakeSession)
    monkeypatch.setattr(query.integration, "capability_registry", lambda: capabilities)
    monkeypatch.setattr(query.integration, "prepare_query", prepare)
    monkeypatch.setattr(query.integration, "execute_prepared_query", execute)

    result = query.IntegrationQueryDispatcher(connectors).dispatch(
        engine=object(),
        application="dotmac_erp",
        capability_binding_id=uuid4(),
        payload={"provider_device_ref": "device-1"},
    )

    assert result.status == "ok"
    assert result.observation == {"latitude": 9.0, "longitude": 7.0}


def test_dispatcher_normalizes_every_internal_exception(monkeypatch) -> None:
    monkeypatch.setattr(
        query.integration,
        "capability_registry",
        lambda: (_ for _ in ()).throw(RuntimeError("provider secret")),
    )

    result = query.IntegrationQueryDispatcher(object()).dispatch(
        engine=object(),
        application="dotmac_erp",
        capability_binding_id=uuid4(),
        payload={"provider_device_ref": "device-1"},
    )

    assert result.model_dump() == {
        "schema_version": "dotmac.io/integration-query-response/v1",
        "status": "provider_unavailable",
        "observation": None,
    }
