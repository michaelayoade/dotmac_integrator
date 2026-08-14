"""Operational controls: session, fetch, delegate, serialise.

The routes in `assembly.py` hold no session and issue no query — same split the
Starter enforces between `router.py` and `service.py`, for the same reason. This
file is the assembly's service layer, and it is thin by construction: every
function here loads what the module's operation needs, calls it, and converts
the result to JSON.

**No decision is made in this file.** `release_expired_leases`, `health_report`,
`replay_delivery` and `replay_receipt` all belong to `dotmac_integration`. What
is added is a transaction boundary and a serialisation, which are deployment
concerns the module correctly refuses to own.
"""

from __future__ import annotations

import dataclasses
from typing import Any
from uuid import UUID

import dotmac_integration as integration
from fastapi import HTTPException
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session


def _jsonable(value: Any) -> Any:
    """Serialise a module result without importing its private types.

    Deliberately structural rather than a per-type mapping: a mapping would need
    editing every time the module adds a field, and a stale mapping silently
    drops data from an operational report — the one place a reader assumes they
    are seeing everything.
    """
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {k: _jsonable(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_jsonable(v) for v in value]
    if isinstance(value, UUID):
        return str(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def _uuid(raw: str, field: str) -> UUID:
    try:
        return UUID(raw)
    except ValueError as exc:
        raise HTTPException(422, f"{field} is not a UUID: {raw!r}") from exc


def installed_connectors() -> dict[str, Any]:
    """What this deployment can actually dispatch to.

    Entry-point discovery, so the answer is the set of INSTALLED connector
    distributions — not a list this assembly maintains. A connector appears here
    by being installed, which is the only mechanism; there is no registration
    call and no name hardcoded anywhere in this repository.
    """
    registry = integration.discover()
    plugins = getattr(registry, "plugins", ())
    return {
        "spi_version": str(integration.CURRENT_SPI_VERSION),
        "entry_point_group": integration.ENTRY_POINT_GROUP,
        "count": len(plugins),
        "connectors": _jsonable(
            [getattr(p, "manifest", p) for p in plugins],
        ),
    }


def health_report(engine: Engine) -> dict[str, Any]:
    with Session(engine) as db:
        return _jsonable(integration.health_report(db))


def release_expired_leases(engine: Engine) -> dict[str, Any]:
    """Sweep leases whose holder died.

    Committed here because the module's operation is a mutation and the module
    does not own the transaction — `dotmac_kernel.db` holds that authority in the
    Starter, and in this deployment the assembly does.
    """
    with Session(engine) as db:
        released = integration.release_expired_leases(db)
        db.commit()
    return {"released": released}


def replay_delivery(engine: Engine, delivery_id: str, reason: str) -> dict[str, Any]:
    """Replay one delivery.

    `reason` is required by the module and passed through unaltered. An assembly
    that supplied a default here ("replayed via API") would put a fabricated
    justification into the audit record of a manual intervention, which is worse
    than having no record.
    """
    identifier = _uuid(delivery_id, "delivery_id")
    with Session(engine) as db:
        delivery = db.get(integration.DeliveryAttempt, identifier)
        if delivery is None:
            raise HTTPException(404, f"no delivery {delivery_id}")
        try:
            replayed = integration.replay_delivery(db, delivery, reason=reason)
        except integration.NotRepairable as exc:
            raise HTTPException(409, str(exc)) from exc
        db.commit()
        return _jsonable(replayed)


def replay_receipt(engine: Engine, receipt_id: str, reason: str) -> dict[str, Any]:
    identifier = _uuid(receipt_id, "receipt_id")
    with Session(engine) as db:
        receipt = db.get(integration.InboxReceipt, identifier)
        if receipt is None:
            raise HTTPException(404, f"no receipt {receipt_id}")
        try:
            replayed = integration.replay_receipt(db, receipt, reason=reason)
        except integration.NotRepairable as exc:
            raise HTTPException(409, str(exc)) from exc
        db.commit()
        return _jsonable(replayed)
