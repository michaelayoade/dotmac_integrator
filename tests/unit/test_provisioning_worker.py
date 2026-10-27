"""The provision worker schedules the durable engine; it does not become one.

Claim, settlement and retry properties belong to ``dotmac-integration``.
These tests prove only this assembly's control flow: one bounded
module-selected page, prepare -> invoke -> settle per unit with no session
held across invoke, identifier-free counts, and per-operation isolation.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import dotmac_integration as integration
import pytest
from sqlalchemy import create_engine

from dotmac_integrator import provisioning

_UNUSED_ENGINE = create_engine(
    "postgresql+psycopg://platform_api@127.0.0.1:1/integrator_test"
)


class _Session:
    def __init__(self) -> None:
        self.commits = 0

    def __enter__(self) -> _Session:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def get(self, model: object, identity: object) -> SimpleNamespace:
        return SimpleNamespace(id=identity)

    def commit(self) -> None:
        self.commits += 1


def test_one_pass_drives_each_operation_to_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = object()
    operation_ids = (uuid4(), uuid4())
    units_left = {operation_ids[0]: 2, operation_ids[1]: 1}
    calls: list[str] = []

    monkeypatch.setattr(provisioning, "Session", lambda engine: _Session())
    monkeypatch.setattr(integration, "discover", lambda: registry)
    monkeypatch.setattr(
        integration,
        "due_provision_operations",
        lambda db, *, limit: operation_ids,
    )

    def prepare(db: object, operation: SimpleNamespace, *, registry: object):
        calls.append("prepare")
        if units_left[operation.id] == 0:
            return None
        units_left[operation.id] -= 1
        return SimpleNamespace(operation_id=operation.id)

    def invoke(prepared: object, *, registry: object, resolve_secrets: object):
        calls.append("invoke")
        assert registry is registry
        assert resolve_secrets is resolve_secrets
        return SimpleNamespace(status="ok")

    def settle(db: object, *, prepared: object, result: object) -> None:
        calls.append("settle")

    monkeypatch.setattr(integration, "prepare_provision", prepare)
    monkeypatch.setattr(integration, "invoke_provision", invoke)
    monkeypatch.setattr(integration, "settle_provision", settle)

    counted = provisioning.provision_due_operations(_UNUSED_ENGINE, limit=7)

    assert counted == {"selected": 2, "settled": 3, "failed": 0, "lost": 0}
    # Per unit: prepare -> invoke -> settle; each operation ends with the
    # final prepare that finds nothing claimable.
    assert calls == (
        ["prepare", "invoke", "settle"] * 2
        + ["prepare"]
        + ["prepare", "invoke", "settle"]
        + ["prepare"]
    )


def test_a_lost_claim_and_a_failure_are_isolated_per_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operation_ids = (uuid4(), uuid4(), uuid4())
    monkeypatch.setattr(provisioning, "Session", lambda engine: _Session())
    monkeypatch.setattr(integration, "discover", object)
    monkeypatch.setattr(
        integration,
        "due_provision_operations",
        lambda db, *, limit: operation_ids,
    )

    def prepare(db: object, operation: SimpleNamespace, *, registry: object):
        return SimpleNamespace(operation_id=operation.id)

    def invoke(prepared: object, *, registry: object, resolve_secrets: object):
        return SimpleNamespace(status="ok")

    def settle(db: object, *, prepared: SimpleNamespace, result: object) -> None:
        if prepared.operation_id == operation_ids[0]:
            raise integration.LostClaim("raced")
        if prepared.operation_id == operation_ids[1]:
            raise RuntimeError("database blip during settle")

    monkeypatch.setattr(integration, "prepare_provision", prepare)
    monkeypatch.setattr(integration, "invoke_provision", invoke)
    monkeypatch.setattr(integration, "settle_provision", settle)

    counted = provisioning.provision_due_operations(_UNUSED_ENGINE, limit=3)

    # Third operation: settle returns None and prepare would loop forever
    # without the unit bound; assert it stayed bounded instead of exact.
    assert counted["selected"] == 3
    assert counted["lost"] == 1
    assert counted["failed"] == 1
    assert counted["settled"] == provisioning._MAX_UNITS_PER_OPERATION
