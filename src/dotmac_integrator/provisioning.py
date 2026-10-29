"""Provisioning-worker adapter: select due operations, drive each unit.

The assembly owns cadence and bounds; the module owns everything inside an
attempt. Per operation, the loop is `prepare` (claim, in a session) ->
`invoke` (connector call, no session) -> `settle` (claim-guarded write, fresh
session), repeated until the operation has nothing claimable or the unit
bound is met. Provisioning runs on its OWN worker loop so a slow provider
poll or a stuck target can never block receipt delivery or lease sweeping —
and none of those can block a disconnect.

`LostClaim` is an ordinary race outcome, counted not raised. Any other
per-operation failure is isolated so one bad operation cannot stop the page;
the module has already made its refusal durable where it makes one.
"""

from __future__ import annotations

import dotmac_integration as integration
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from dotmac_integrator.secret_resolver import resolve_secrets

__all__ = ["provision_due_operations"]

#: Hard bound on units (plan/apply/observe/cancel) driven per operation per
#: pass. A plan with more steps simply continues next pass; the bound keeps
#: one large operation from monopolising the worker.
_MAX_UNITS_PER_OPERATION = 50


def provision_due_operations(engine: Engine, limit: int) -> dict[str, int]:
    """Drive one module-selected page. Returns identifier-free counts."""
    registry = integration.discover()
    with Session(engine) as db:
        operation_ids = integration.due_provision_operations(db, limit=limit)

    settled = 0
    failed = 0
    lost = 0
    for operation_id in operation_ids:
        for _ in range(_MAX_UNITS_PER_OPERATION):
            try:
                with Session(engine) as db:
                    operation = db.get(integration.ProvisionOperation, operation_id)
                    if operation is None:
                        break
                    prepared = integration.prepare_provision(
                        db, operation, registry=registry
                    )
                    db.commit()
                if prepared is None:
                    break
                result = integration.invoke_provision(
                    prepared, registry=registry, resolve_secrets=resolve_secrets
                )
                with Session(engine) as db:
                    integration.settle_provision(db, prepared=prepared, result=result)
                    db.commit()
                settled += 1
            except integration.LostClaim:
                lost += 1
                break
            except Exception:
                # The module's claim/settlement discipline already decided
                # what is durable; this catch isolates the next operation.
                failed += 1
                break

    return {
        "selected": len(operation_ids),
        "settled": settled,
        "failed": failed,
        "lost": lost,
    }
