"""The poll worker schedules the a16 engine; it does not become one.

The PostgreSQL concurrency, retry and evidence properties belong to
``dotmac-integration``. These tests prove only this assembly's control flow:
one bounded module-selected page, one complete ``poll_once`` call per selected
job, and identifier-free aggregate results even when one attempt fails.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import dotmac_integration as integration
import pytest
from sqlalchemy import create_engine

from dotmac_integrator import polling
from dotmac_integrator.secret_resolver import resolve_secrets

_UNUSED_ENGINE = create_engine(
    "postgresql+psycopg://platform_api@127.0.0.1:1/integrator_test"
)


class _ReadSession:
    def __enter__(self) -> _ReadSession:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_one_pass_delegates_every_selected_job_to_the_complete_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = object()
    jobs = tuple(SimpleNamespace(checkpoint_id=uuid4()) for _ in range(3))
    selected: list[tuple[object, int]] = []
    attempted: list[dict[str, object]] = []

    monkeypatch.setattr(polling, "Session", lambda engine: _ReadSession())
    monkeypatch.setattr(integration, "discover", lambda: registry)

    def due(db: object, *, limit: int) -> tuple[SimpleNamespace, ...]:
        selected.append((db, limit))
        return jobs

    def attempt(**kwargs: object) -> SimpleNamespace:
        attempted.append(kwargs)
        if kwargs["checkpoint_id"] == jobs[1].checkpoint_id:
            # a16 has already appended durable failure evidence and set its
            # retry floor before this reaches the assembly.
            raise integration.PollUnavailable("bounded module refusal")
        return SimpleNamespace(recorded=2, duplicates=1)

    monkeypatch.setattr(integration, "due_polling_jobs", due)
    monkeypatch.setattr(integration, "poll_once", attempt)

    counted = polling.poll_due_jobs(_UNUSED_ENGINE, limit=17)

    assert len(selected) == 1
    assert selected[0][1] == 17
    assert [call["checkpoint_id"] for call in attempted] == [
        job.checkpoint_id for job in jobs
    ]
    assert all(call["registry"] is registry for call in attempted)
    assert all(call["resolve_secrets"] is resolve_secrets for call in attempted)
    assert all(callable(call["unit_of_work"]) for call in attempted)
    assert counted == {
        "selected": 3,
        "succeeded": 2,
        "failed": 1,
        "recorded": 4,
        "duplicates": 2,
    }


def test_a_selector_failure_is_not_misreported_as_an_attempt_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(polling, "Session", lambda engine: _ReadSession())
    monkeypatch.setattr(integration, "discover", object)

    def unavailable(db: object, *, limit: int) -> tuple[object, ...]:
        raise RuntimeError("database unavailable before selection")

    monkeypatch.setattr(integration, "due_polling_jobs", unavailable)

    with pytest.raises(RuntimeError, match="before selection"):
        polling.poll_due_jobs(_UNUSED_ENGINE, limit=1)
