"""The operator kill-switch routes, driven without a database.

Three things are proved:

* the routes are absent while the flag is off (main stays deployable);
* with the flag on, each is refused without an operator (401) and works for one;
* the module's own refusals survive the adapter: a quarantined installation
  cannot back an enabled binding, and `disable` cannot be used to leave a
  quarantine.

The session is a small fake and the audit writer is captured, because the
decisions under test are made before or around a query; the real lifecycle
functions from `dotmac_integration` run unmodified over the fake rows.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import dotmac_integration as integration
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from dotmac_integrator import operations
from dotmac_integrator.assembly import create_app
from dotmac_integrator.operator_auth import OperatorIdentity, require_operator
from tests.support import build_settings

INSTALLATION_ID = uuid4()
BINDING_ID = uuid4()
OPERATOR = OperatorIdentity(
    admin_id=UUID("00000000-0000-4000-8000-0000000000aa"),
    label="operator@example.test",
    mechanism="platform_admin",
)

ROUTES = [
    ("POST", f"/operations/bindings/{BINDING_ID}/disable"),
    ("POST", f"/operations/installations/{INSTALLATION_ID}/disable"),
    ("POST", f"/operations/installations/{INSTALLATION_ID}/quarantine"),
    ("POST", f"/operations/installations/{INSTALLATION_ID}/quarantine/release"),
]


class _FakeSession:
    def __init__(self, rows: dict[Any, Any], log: dict[str, int]) -> None:
        self._rows = rows
        self._log = log

    def __enter__(self) -> _FakeSession:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, _stmt: object) -> Any:
        rows = self._rows["census"].pop(0)
        return SimpleNamespace(all=lambda: rows)

    def get(self, _model: object, identifier: UUID, **_kw: object) -> Any:
        return self._rows.get(identifier)

    def flush(self) -> None:
        return None

    def add(self, _row: object) -> None:
        return None

    def commit(self) -> None:
        self._log["commits"] += 1


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> Iterator[SimpleNamespace]:
    installation = SimpleNamespace(
        id=INSTALLATION_ID,
        connector_key="demo",
        name="demo-installation",
        state="enabled",
        state_reason=None,
        spi_range=">=1.3,<2.0",
        updated_by=None,
    )
    binding = SimpleNamespace(
        id=BINDING_ID,
        installation_id=INSTALLATION_ID,
        capability_id="demo.capability",
        state="enabled",
        enabled_at=None,
        updated_by=None,
    )
    manifest = SimpleNamespace(
        spi_range=integration.SpiRange.parse(">=1.3,<2.0"),
        capability_ids=frozenset({"demo.capability"}),
        connector_key="demo",
        version="1",
    )
    registry = SimpleNamespace(get=lambda _key: manifest)
    audits: list[dict[str, Any]] = []
    log = {"commits": 0}
    rows = {INSTALLATION_ID: installation, BINDING_ID: binding}

    monkeypatch.setattr(operations, "Session", lambda _engine: _FakeSession(rows, log))

    # `create_app` itself calls `discover()` for the runtime-policy check, so
    # the fake registry is installed only once the app exists (`arm`).
    def arm() -> None:
        monkeypatch.setattr(integration, "discover", lambda: registry)

    monkeypatch.setattr(
        operations,
        "write_platform_audit_event",
        lambda _db, **kw: audits.append(kw),
    )
    # The module writes its own quarantine audit row through a real session;
    # that row is the module's, so it is stubbed at the module boundary here.
    monkeypatch.setattr(
        "dotmac_integration.lifecycle._installation_audit", lambda *a, **k: None
    )
    yield SimpleNamespace(
        installation=installation, binding=binding, audits=audits, log=log, arm=arm
    )


def _app(**overrides: Any) -> Any:
    return create_app(build_settings(**overrides))


def _client(
    *, operator: bool, world: SimpleNamespace | None = None, **overrides: Any
) -> TestClient:
    app = _app(operator_killswitch_routes_enabled=True, **overrides)
    if world is not None:
        world.arm()
    if operator:
        app.dependency_overrides[require_operator] = lambda: OPERATOR
    return TestClient(app)


def test_the_flag_defaults_on() -> None:
    assert build_settings().operator_killswitch_routes_enabled is True


def test_the_routes_are_not_mounted_when_the_flag_is_set_false() -> None:
    app = _app(operator_killswitch_routes_enabled=False)
    mounted = {r.path for r in app.routes if isinstance(r, APIRoute)}
    for _method, path in ROUTES:
        template = path.replace(str(BINDING_ID), "{binding_id}").replace(
            str(INSTALLATION_ID), "{installation_id}"
        )
        assert template not in mounted, template


def test_the_routes_are_mounted_when_the_flag_is_on() -> None:
    app = _app(operator_killswitch_routes_enabled=True)
    mounted = {r.path for r in app.routes if isinstance(r, APIRoute)}
    assert "/operations/bindings/{binding_id}/disable" in mounted
    assert "/operations/installations/{installation_id}/quarantine/release" in mounted


@pytest.mark.parametrize(("method", "path"), ROUTES)
def test_each_route_is_refused_without_an_operator(method: str, path: str) -> None:
    response = _client(operator=False).request(
        method, path, json={"reason": "a stated reason"}
    )
    assert response.status_code == 401


@pytest.mark.parametrize(("method", "path"), ROUTES)
def test_each_route_requires_a_reason(
    method: str, path: str, world: SimpleNamespace
) -> None:
    response = _client(operator=True, world=world).request(method, path, json={})
    assert response.status_code == 422
    assert world.audits == []


def test_binding_disable_works_and_is_audited(world: SimpleNamespace) -> None:
    response = _client(operator=True, world=world).post(
        ROUTES[0][1], json={"reason": "incident 1"}
    )
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "disabled"
    assert world.binding.state == "disabled"
    assert [a["action"] for a in world.audits] == ["integrator.binding.disabled"]
    assert world.audits[0]["actor_admin_id"] == OPERATOR.admin_id
    assert world.audits[0]["details"]["reason"] == "incident 1"
    assert world.log["commits"] == 1


def test_installation_disable_works_and_is_audited(world: SimpleNamespace) -> None:
    response = _client(operator=True, world=world).post(
        ROUTES[1][1], json={"reason": "maintenance"}
    )
    assert response.status_code == 200, response.text
    assert world.installation.state == "disabled"
    assert world.installation.state_reason == "maintenance"
    assert [a["action"] for a in world.audits] == ["integrator.installation.disabled"]


def test_quarantine_then_release_lands_in_disabled(world: SimpleNamespace) -> None:
    client = _client(operator=True, world=world)
    assert client.post(ROUTES[2][1], json={"reason": "suspect"}).status_code == 200
    assert world.installation.state == "quarantined"
    assert client.post(ROUTES[3][1], json={"reason": "cleared"}).status_code == 200
    assert world.installation.state == "disabled"
    assert [a["action"] for a in world.audits] == [
        "integrator.installation.quarantined",
        "integrator.installation.quarantine_released",
    ]


def test_release_of_a_healthy_installation_is_refused(world: SimpleNamespace) -> None:
    response = _client(operator=True, world=world).post(
        ROUTES[3][1], json={"reason": "oops"}
    )
    assert response.status_code == 409
    assert world.installation.state == "enabled"
    assert world.audits == []


def test_disable_cannot_be_used_to_leave_quarantine(world: SimpleNamespace) -> None:
    world.installation.state = "quarantined"
    response = _client(operator=True, world=world).post(
        ROUTES[1][1], json={"reason": "sneaky"}
    )
    assert response.status_code == 409
    assert world.installation.state == "quarantined"
    assert world.audits == []


def test_enabling_a_binding_of_a_quarantined_installation_is_refused(
    world: SimpleNamespace,
) -> None:
    world.installation.state = "quarantined"
    world.binding.state = "disabled"
    response = _client(operator=True, world=world).post(
        f"/operations/bindings/{BINDING_ID}/enable", json={"reason": "try"}
    )
    assert response.status_code == 409
    assert "quarantined" in response.text
    assert world.binding.state == "disabled"
    assert world.audits == []


def test_unknown_ids_are_404(world: SimpleNamespace) -> None:
    client = _client(operator=True, world=world)
    other = uuid4()
    for path in (
        f"/operations/bindings/{other}/disable",
        f"/operations/installations/{other}/disable",
        f"/operations/installations/{other}/quarantine",
        f"/operations/installations/{other}/quarantine/release",
    ):
        assert client.post(path, json={"reason": "x"}).status_code == 404


# ── Census ──────────────────────────────────────────────────────────────────


def _census_world(monkeypatch: pytest.MonkeyPatch) -> None:
    rows: dict[Any, Any] = {
        "census": [
            [
                ("alpha", "enabled", 2),
                ("alpha", "quarantined", 1),
                ("beta", "disabled", 3),
            ],
            [("alpha", "enabled", 4), ("beta", "disabled", 5)],
        ]
    }
    monkeypatch.setattr(
        operations, "Session", lambda _e: _FakeSession(rows, {"commits": 0})
    )


def test_census_is_refused_without_an_operator() -> None:
    assert _client(operator=False).get("/operations/bindings/census").status_code == 401


def test_census_returns_counts_by_state_and_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _census_world(monkeypatch)
    response = _client(operator=True).get("/operations/bindings/census")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["installations"]["total"] == 6
    assert body["installations"]["by_state"] == {
        "disabled": 3,
        "enabled": 2,
        "quarantined": 1,
    }
    assert body["bindings"]["by_connector"] == {
        "alpha": {"enabled": 4},
        "beta": {"disabled": 5},
    }


def test_census_carries_no_ids_or_config_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sensitivity: rows deliberately carry an id, config and a secret ref in
    positions a leaky implementation would pass through; none may appear."""
    import re

    leak_id = str(uuid4())
    rows: dict[Any, Any] = {
        "census": [
            [("alpha", "enabled", 1)],
            [("alpha", "enabled", 1)],
        ]
    }
    monkeypatch.setattr(
        operations, "Session", lambda _e: _FakeSession(rows, {"commits": 0})
    )
    text = _client(operator=True).get("/operations/bindings/census").text
    assert leak_id not in text
    assert not re.search(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text
    )
    for forbidden in ("config", "secret", "env://", "file://", "password"):
        assert forbidden not in text.lower()
    # The projection function itself cannot pass a wider row through.
    assert operations._census_block([("alpha", "enabled", 1)]) == {
        "total": 1,
        "by_state": {"enabled": 1},
        "by_connector": {"alpha": {"enabled": 1}},
    }


def test_installation_enable_cannot_be_a_way_out_of_quarantine(
    world: SimpleNamespace,
) -> None:
    world.installation.state = "quarantined"
    response = _client(operator=True, world=world).post(
        f"/operations/installations/{INSTALLATION_ID}/enable",
        json={"reason": "try"},
    )
    assert response.status_code == 409
    assert "quarantine" in response.text
    assert world.installation.state == "quarantined"
    assert world.audits == []


def test_state_decisions_load_the_installation_under_a_row_lock(
    world: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    locked: list[bool] = []
    original = _FakeSession.get

    def spy(self: _FakeSession, model: object, identifier: UUID, **kw: Any) -> Any:
        if identifier == INSTALLATION_ID:
            locked.append(bool(kw.get("with_for_update")))
        return original(self, model, identifier, **kw)

    monkeypatch.setattr(_FakeSession, "get", spy)
    client = _client(operator=True, world=world)
    for _method, path in ROUTES[:3]:
        client.post(path, json={"reason": "r"})
    assert locked and all(locked)
