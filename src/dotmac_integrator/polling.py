"""Polling-worker adapter: select one bounded page, then delegate each job.

The assembly owns the wake-up cadence and page size.  It owns none of the
questions inside an attempt: eligibility, connector selection, failure
classification, retry state and backoff are all ``dotmac_integration``'s.

That boundary is visible in the two module calls below. ``due_polling_jobs`` is
the sole selector and ``poll_once`` is the whole attempt.  A failure is caught
only so one job cannot stop the remaining page; the module has already appended
its durable evidence and advanced its retry floor before re-raising it.
"""

from __future__ import annotations

import dotmac_integration as integration
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from dotmac_integrator.ingress import unit_of_work
from dotmac_integrator.secret_resolver import resolve_secrets

__all__ = ["poll_due_jobs"]


def poll_due_jobs(engine: Engine, limit: int) -> dict[str, int]:
    """Attempt one module-selected page and return identifier-free counts.

    One page per wake-up is deliberate. The module's selector is bounded and
    keyset-paginated for consumers that need a complete walk; this scheduler
    instead returns to its cadence after a bounded amount of provider I/O. A
    successful attempt moves its job to the back of the module-owned ordering,
    while a failed one receives the module-owned backoff.
    """

    registry = integration.discover()
    with Session(engine) as db:
        jobs = integration.due_polling_jobs(db, limit=limit)

    opened = unit_of_work(engine)
    succeeded = 0
    failed = 0
    recorded = 0
    duplicates = 0
    for job in jobs:
        try:
            result = integration.poll_once(
                checkpoint_id=job.checkpoint_id,
                registry=registry,
                resolve_secrets=resolve_secrets,
                unit_of_work=opened,
            )
        except Exception:
            # Do not classify, count attempts, compute a delay or inspect the
            # exception. ``poll_once`` already persisted all of that through a
            # fresh unit of work before it re-raised. This catch only isolates
            # the next independently selected job in the bounded page.
            failed += 1
        else:
            succeeded += 1
            recorded += result.recorded
            duplicates += result.duplicates

    return {
        "selected": len(jobs),
        "succeeded": succeeded,
        "failed": failed,
        "recorded": recorded,
        "duplicates": duplicates,
    }
