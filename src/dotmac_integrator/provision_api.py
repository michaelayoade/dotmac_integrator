"""Product-facing provision submission seam (submit, cancel, read state).

The product authors a plan; this seam validates ownership and hands the
exact steps to the module's durable engine. It never invokes a connector:
submission is a durable write, execution is the worker pump's. Responses
carry state and counts, never step inputs — a provision payload can name
credentials and fleet endpoints, and an API echo would put them somewhere
they were never declared to be.
"""

from __future__ import annotations

from typing import Literal
from uuid import UUID

import dotmac_integration as integration
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

ProvisionSubmitStatus = Literal["accepted", "conflict", "refused", "unavailable"]


class ProvisionStepDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_key: str = Field(min_length=1, max_length=120)
    endpoint_code: str = Field(min_length=1, max_length=160)
    depends_on: tuple[str, ...] = ()
    input: dict[str, object] = Field(max_length=32)


class ProvisionSubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["dotmac.io/integration-provision-request/v1"]
    capability_binding_id: UUID
    command_id: str = Field(min_length=1, max_length=240)
    steps: tuple[ProvisionStepDocument, ...] = Field(min_length=1, max_length=64)
    correlation_id: str | None = Field(default=None, max_length=120)


class ProvisionCancelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["dotmac.io/integration-provision-cancel/v1"]
    reason: str = Field(default="", max_length=240)


class ProvisionOperationView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["dotmac.io/integration-provision-response/v1"] = (
        "dotmac.io/integration-provision-response/v1"
    )
    status: ProvisionSubmitStatus
    operation_id: UUID | None = None
    operation_state: str | None = None
    steps_total: int = 0
    steps_settled: int = 0


class IntegrationProvisionDispatcher:
    """Ownership-checked submission into the module's durable engine."""

    def __init__(self, registry: integration.ConnectorRegistry | None = None) -> None:
        self._registry = registry or integration.discover()

    def submit(
        self,
        *,
        engine: Engine,
        application: str,
        request: ProvisionSubmitRequest,
    ) -> ProvisionOperationView:
        try:
            capabilities = integration.capability_registry()
            with Session(engine) as db:
                binding = db.get(
                    integration.CapabilityBinding, request.capability_binding_id
                )
                if binding is None:
                    return ProvisionOperationView(status="refused")
                if (
                    capabilities.get(binding.capability_id).owner.application
                    != application
                ):
                    return ProvisionOperationView(status="refused")
                steps = tuple(
                    integration.ProvisionStep(
                        step_key=step.step_key,
                        endpoint_code=step.endpoint_code,
                        depends_on=step.depends_on,
                        input=step.input,
                    )
                    for step in request.steps
                )
                operation, _is_new = integration.submit_provision_operation(
                    db,
                    capability_binding_id=request.capability_binding_id,
                    command_id=request.command_id,
                    steps=steps,
                    registry=self._registry,
                    contracts=capabilities,
                    correlation_id=request.correlation_id,
                )
                view = self._view(db, operation, status="accepted")
                db.commit()
                return view
        except integration.ProvisionConflict:
            return ProvisionOperationView(status="conflict")
        except Exception:
            return ProvisionOperationView(status="unavailable")

    def cancel(
        self,
        *,
        engine: Engine,
        application: str,
        operation_id: UUID,
        binding_ids: frozenset[UUID],
        reason: str,
    ) -> ProvisionOperationView:
        try:
            with Session(engine) as db:
                operation = self._owned(db, operation_id, application, binding_ids)
                if operation is None:
                    return ProvisionOperationView(status="refused")
                integration.request_provision_cancel(db, operation, reason=reason)
                view = self._view(db, operation, status="accepted")
                db.commit()
                return view
        except Exception:
            return ProvisionOperationView(status="unavailable")

    def get(
        self,
        *,
        engine: Engine,
        application: str,
        operation_id: UUID,
        binding_ids: frozenset[UUID],
    ) -> ProvisionOperationView:
        try:
            with Session(engine) as db:
                operation = self._owned(db, operation_id, application, binding_ids)
                if operation is None:
                    return ProvisionOperationView(status="refused")
                return self._view(db, operation, status="accepted")
        except Exception:
            return ProvisionOperationView(status="unavailable")

    def _owned(
        self,
        db: Session,
        operation_id: UUID,
        application: str,
        binding_ids: frozenset[UUID],
    ) -> integration.ProvisionOperation | None:
        operation = db.get(integration.ProvisionOperation, operation_id)
        if operation is None or operation.capability_binding_id not in binding_ids:
            return None
        capabilities = integration.capability_registry()
        if capabilities.get(operation.capability_id).owner.application != application:
            return None
        return operation

    @staticmethod
    def _view(
        db: Session,
        operation: integration.ProvisionOperation,
        *,
        status: ProvisionSubmitStatus,
    ) -> ProvisionOperationView:
        from sqlalchemy import select

        rows = (
            db.execute(
                select(integration.ProvisionStepAttempt.state).where(
                    integration.ProvisionStepAttempt.operation_id == operation.id
                )
            )
            .scalars()
            .all()
        )
        settled = sum(
            1
            for state in rows
            if state
            in ("succeeded", "terminal", "cancelled", "reconciliation_required")
        )
        return ProvisionOperationView(
            status=status,
            operation_id=operation.id,
            operation_state=operation.state,
            steps_total=len(rows),
            steps_settled=settled,
        )


__all__ = [
    "IntegrationProvisionDispatcher",
    "ProvisionCancelRequest",
    "ProvisionOperationView",
    "ProvisionStepDocument",
    "ProvisionSubmitRequest",
    "ProvisionSubmitStatus",
]
