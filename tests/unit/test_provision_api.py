"""Provision API seam: ownership gates and status mapping, engine faked."""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import dotmac_integration as integration
import pytest
from sqlalchemy import create_engine

from dotmac_integrator.provision_api import (
    IntegrationProvisionDispatcher,
    ProvisionStepDocument,
    ProvisionSubmitRequest,
)

_UNUSED_ENGINE = create_engine(
    "postgresql+psycopg://platform_api@127.0.0.1:1/integrator_test"
)
BINDING_ID = uuid4()
OPERATION_ID = uuid4()


class _Session:
    def __init__(self, binding: object) -> None:
        self._binding = binding

    def __enter__(self) -> _Session:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def get(self, model: object, identity: object) -> object:
        return self._binding

    def execute(self, statement: object) -> SimpleNamespace:
        return SimpleNamespace(
            scalars=lambda: SimpleNamespace(all=lambda: ["succeeded", "pending"])
        )

    def commit(self) -> None:
        return None


def _request(binding_id: object = BINDING_ID) -> ProvisionSubmitRequest:
    return ProvisionSubmitRequest(
        schema_version="dotmac.io/integration-provision-request/v1",
        capability_binding_id=binding_id,  # type: ignore[arg-type]
        command_id="cmd-1",
        steps=(
            ProvisionStepDocument(
                step_key="project",
                endpoint_code="radius.projection.upsert",
                input={"subject_ref": "svc-1"},
            ),
        ),
    )


def _wire(monkeypatch: pytest.MonkeyPatch, *, owner_application: str = "sub") -> None:
    binding = SimpleNamespace(id=BINDING_ID, capability_id="network.x.v1")
    monkeypatch.setattr(
        "dotmac_integrator.provision_api.Session", lambda engine: _Session(binding)
    )
    contract = SimpleNamespace(owner=SimpleNamespace(application=owner_application))
    monkeypatch.setattr(
        integration,
        "capability_registry",
        lambda: SimpleNamespace(get=lambda capability_id: contract),
    )


def test_submit_accepts_for_the_owning_application(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _wire(monkeypatch)
    submitted: dict[str, object] = {}

    def submit(db: object, **kwargs: object) -> tuple[SimpleNamespace, bool]:
        submitted.update(kwargs)
        return SimpleNamespace(id=OPERATION_ID, state="planned"), True

    monkeypatch.setattr(integration, "submit_provision_operation", submit)
    view = IntegrationProvisionDispatcher(registry=object()).submit(  # type: ignore[arg-type]
        engine=_UNUSED_ENGINE, application="sub", request=_request()
    )
    assert view.status == "accepted"
    assert view.operation_id == OPERATION_ID
    assert view.operation_state == "planned"
    assert (view.steps_total, view.steps_settled) == (2, 1)
    assert submitted["command_id"] == "cmd-1"


def test_submit_refuses_another_applications_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _wire(monkeypatch, owner_application="other-app")
    view = IntegrationProvisionDispatcher(registry=object()).submit(  # type: ignore[arg-type]
        engine=_UNUSED_ENGINE, application="sub", request=_request()
    )
    assert view.status == "refused"
    assert view.operation_id is None


def test_submit_maps_a_plan_conflict(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch)

    def conflict(db: object, **kwargs: object) -> tuple[object, bool]:
        raise integration.ProvisionConflict("changed plan")

    monkeypatch.setattr(integration, "submit_provision_operation", conflict)
    view = IntegrationProvisionDispatcher(registry=object()).submit(  # type: ignore[arg-type]
        engine=_UNUSED_ENGINE, application="sub", request=_request()
    )
    assert view.status == "conflict"
