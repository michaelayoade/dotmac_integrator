"""Injected provider-neutral query dispatch seam for integration a18."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, Protocol, cast
from uuid import UUID

import dotmac_integration as integration
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from dotmac_integrator.secret_resolver import resolve_secrets

ProductQueryStatus = Literal[
    "ok",
    "provider_unavailable",
    "unauthorized_provider_session",
    "not_found",
    "invalid_query",
    "timeout",
    "malformed_provider_response",
]


class ProductQueryRequest(BaseModel):
    """Assembly envelope; the selected integration domain validates payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["dotmac.io/integration-query-request/v1"]
    capability_binding_id: UUID
    payload: dict[str, object] = Field(max_length=16)


class ProductQueryResponse(BaseModel):
    """Closed response envelope returned by the query-capable module."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["dotmac.io/integration-query-response/v1"] = (
        "dotmac.io/integration-query-response/v1"
    )
    status: ProductQueryStatus
    observation: dict[str, object] | None = None

    @model_validator(mode="after")
    def observation_matches_status(self) -> ProductQueryResponse:
        if self.status == "ok" and self.observation is None:
            raise ValueError("an ok query response requires an observation")
        if self.status != "ok" and self.observation is not None:
            raise ValueError("a failed query response cannot carry an observation")
        return self


class QueryDispatcher(Protocol):
    """Provider-neutral seam implemented by the released integration module."""

    def dispatch(
        self,
        *,
        engine: Engine,
        application: str,
        capability_binding_id: UUID,
        payload: dict[str, object],
    ) -> ProductQueryResponse: ...


class IntegrationQueryDispatcher:
    """Prepare in one short DB scope, then invoke after the session closes."""

    def __init__(self, registry: integration.ConnectorRegistry | None = None) -> None:
        self._registry = registry or integration.discover()

    def dispatch(
        self,
        *,
        engine: Engine,
        application: str,
        capability_binding_id: UUID,
        payload: dict[str, object],
    ) -> ProductQueryResponse:
        try:
            capabilities = integration.capability_registry()
            with Session(engine) as db:
                prepared = integration.prepare_query(
                    db,
                    capability_binding_id,
                    payload,
                    registry=self._registry,
                    capability_registry=capabilities,
                )
            if (
                capabilities.get(prepared.capability_id).owner.application
                != application
            ):
                return ProductQueryResponse(status="invalid_query")
            result = integration.execute_prepared_query(
                prepared,
                registry=self._registry,
                capability_registry=capabilities,
                resolve_secrets=_resolve_query_secrets,
            )
            observation = (
                dict(result.observation) if result.observation is not None else None
            )
            if result.status is integration.QueryStatus.SUCCEEDED:
                return ProductQueryResponse(status="ok", observation=observation)
            status = result.status.value
            if status not in {
                "provider_unavailable",
                "unauthorized_provider_session",
                "not_found",
                "invalid_query",
                "timeout",
                "malformed_provider_response",
            }:
                return ProductQueryResponse(status="malformed_provider_response")
            return ProductQueryResponse(
                status=cast(ProductQueryStatus, status), observation=observation
            )
        except Exception:
            return ProductQueryResponse(status="provider_unavailable")


def _resolve_query_secrets(refs: Mapping[str, object]) -> Mapping[str, object]:
    """Adapt a18's generic immutable reference map to the held resolver."""
    if any(
        not isinstance(name, str) or not isinstance(ref, str)
        for name, ref in refs.items()
    ):
        raise ValueError("query secret references must map strings to strings")
    return resolve_secrets({str(name): str(ref) for name, ref in refs.items()})
