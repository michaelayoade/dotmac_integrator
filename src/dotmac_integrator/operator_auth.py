"""Who may operate this control plane, and how that identity reaches the trail.

`/operations/**` can replay a delivery, reclaim a lease and enable a connector
against live provider credentials. It is the control plane's control plane, and
until this module existed it was open.

## An adapter, not a second auth system

`dotmac_kernel.platform_auth` already owns platform-actor identity: signed
bearer tokens with `aud="platform"`, backed by a live `platform_sessions` row,
against a `platform_admins` row that is still active, on the platform host
only. All three of those tables are created by the KERNEL lineage this
assembly already composes, so the identity exists in this deployment's own
database without a second model, a second token population or a second
password hash.

So `require_operator` calls `authenticate_platform_request` — the kernel's own
pure predicate, which takes an explicit `Session` precisely so a different
assembly can supply its own — and does not re-implement one line of token
validation. An auth-tightening fix in the kernel lands here by upgrading the
pin.

The one thing added is the shape the audit needs: `OperatorIdentity` carries
both representations the module wants, because it wants two —
`actor_admin_id: UUID` on the platform audit row and `actor: str` on the
installation row — and a caller that had to remember which is which would
eventually pass neither.

## Fail closed, and no 'none'

`OPERATOR_AUTH_MECHANISMS` has one entry. A deployment naming anything else is
refused by `validate_settings` at boot, and this guard 503s rather than
serving, because "authentication is misconfigured" must never resolve to
"authentication is skipped". There is deliberately no development bypass: the
mechanism needs no external service, only a platform-admin row that
`python -m dotmac_integrator.bootstrap_operator` creates in three seconds.

## Reason is required, not defaulted

Every mutating operator route takes `OperationReason`. The module makes
`reason` mandatory on a replay for the right cause — a repair with no stated
reason is indistinguishable from a mistake six months later — and this
assembly extends it to every mutation it owns rather than inventing a default,
because a fabricated justification in an audit row reads as deliberate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from dotmac_kernel.platform_auth import authenticate_platform_request
from fastapi import Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from dotmac_integrator.settings import OPERATOR_AUTH_MECHANISMS

__all__ = [
    "OperationReason",
    "Operator",
    "OperatorIdentity",
    "require_operator",
]


class OperationReason(BaseModel):
    """Why an operator is doing this. Recorded, never invented."""

    reason: str = Field(min_length=1, max_length=500)


@dataclass(frozen=True, slots=True)
class OperatorIdentity:
    """The authenticated operator, in both shapes the evidence needs.

    `admin_id` is the FK the platform audit row carries; `label` is the string
    the module writes to `created_by`/`updated_by`, which is deliberately not a
    foreign key because the module must not presume this deployment's identity
    model. Two fields rather than one because the two ledgers genuinely differ.
    """

    admin_id: UUID
    label: str
    mechanism: str


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def require_operator(
    request: Request, authorization: str | None = Header(default=None)
) -> OperatorIdentity:
    """THE operator guard. Every `/operations/**` route depends on it.

    Guards reads as well as mutations: the connector inventory and the health
    report describe every integration this fleet runs and which of them are
    stuck, which is reconnaissance rather than a public status page.
    """
    settings = request.app.state.settings
    mechanism = settings.operator_auth_mechanism
    if mechanism not in OPERATOR_AUTH_MECHANISMS:
        # 503, not 401 and certainly not a pass. The deployment is broken, and
        # saying so is better than a 401 that sends an operator hunting for a
        # credential problem that does not exist.
        raise HTTPException(
            503,
            "operator authentication is not configured; refusing to serve the "
            "operations surface",
        )

    token = _bearer(authorization)
    if token is None:
        raise HTTPException(401, "operator authentication required")

    with Session(request.app.state.engine) as db:
        admin = authenticate_platform_request(request, db, token=token)
        if admin is None:
            # One message for every failure mode — bad signature, expired,
            # revoked session, wrong host, inactive admin. Distinguishing them
            # tells an attacker which half of a guess was right.
            raise HTTPException(401, "operator authentication failed")
        return OperatorIdentity(
            admin_id=admin.id, label=admin.email, mechanism=mechanism
        )


#: The annotation every `/operations/**` handler uses. `Annotated` rather than
#: a `Depends(...)` default so the guard is part of the TYPE — a handler that
#: drops it loses a parameter rather than silently keeping a working signature,
#: and `surface.audit_routes` refuses to start either way.
Operator = Annotated[OperatorIdentity, Depends(require_operator)]
