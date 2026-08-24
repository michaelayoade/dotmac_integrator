"""Authenticated, provider-neutral product command intake.

The source application says what capability it needs, supplies the command
shape that capability owns, and gives the logical effect a stable idempotency
key.  It never selects a provider or an installation.  The module's binding
selector resolves exactly one enabled transport and its outbox owns the row.

The API key is held at startup through the same ADR-0009 seam as connector and
destination material.  This request path performs one dictionary lookup and a
constant-time comparison; it cannot reach a secret store.
"""

from __future__ import annotations

from hmac import compare_digest
from typing import Annotated

import dotmac_integration as integration
from dotmac_kernel.secret_sources import get_secret
from fastapi import Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

__all__ = [
    "CommandAuth",
    "DeliveryCommand",
    "enqueue",
    "require_command_port",
]


_Identity = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=240)
]


class DeliveryCommand(BaseModel):
    """One product-decided effect for a declared transport capability."""

    model_config = ConfigDict(extra="forbid")

    capability_id: _Identity
    event_type: _Identity
    idempotency_key: _Identity
    payload: dict[str, object]


def require_command_port(
    request: Request,
    x_api_key: Annotated[str | None, Header(alias="X-Api-Key")] = None,
) -> None:
    """Authenticate one source application without exposing the credential.

    A missing or wrong candidate is a 404, matching the metrics surface: the
    response is not an oracle that confirms this deployment accepts commands.
    A configured reference that was not held is different — the deployment is
    broken, and reporting 503 prevents a product from treating it as a bad key.
    """

    settings = request.app.state.settings
    reference = settings.command_port_api_key_ref.strip()
    expected = get_secret(reference) if reference else None
    if expected is None:
        raise HTTPException(503, "command authentication unavailable")

    candidate = x_api_key or ""
    try:
        accepted = compare_digest(candidate, expected)
    finally:
        # Both are frame locals until this point.  Remove them before any
        # downstream code can raise into a locals-capturing error reporter.
        del candidate
        del expected
        del x_api_key
    if not accepted:
        raise HTTPException(404, "not found")


CommandAuth = Annotated[None, Depends(require_command_port)]


def enqueue(
    engine: Engine,
    *,
    capability_id: str,
    event_type: str,
    idempotency_key: str,
    payload: dict[str, object],
) -> dict[str, object]:
    """Resolve the module-owned binding and commit one durable outbox row."""

    with Session(engine) as db:
        try:
            binding = integration.resolve_binding(db, capability_id=capability_id)
            delivery, is_new = integration.enqueue_delivery(
                db,
                installation_id=binding.installation_id,
                capability_binding_id=binding.id,
                event_type=event_type,
                idempotency_key=idempotency_key,
                payload=payload,
            )
            db.commit()
        except integration.SelectionError as exc:
            # The module's text may name colliding connector installations.
            # That is useful to an operator and is provider information the
            # product command port must not receive.
            raise HTTPException(
                409,
                "no unambiguous enabled transport binding serves this capability",
            ) from exc
        return {
            "delivery_id": str(delivery.id),
            "state": delivery.state,
            "is_new": is_new,
            "payload_digest": delivery.payload_digest,
        }
