"""The `integration:manage` caller (D12a): confined, never an operator.

Driven without a database. The session is a small fake and the audit writer is
captured; the module's own lifecycle functions run unmodified where they decide
(`set_binding_enabled`), and `put_config_revision` is recorded because what is
under test is WHAT the assembly hands it.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import dotmac_integration as integration
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from dotmac_integrator import manage
from dotmac_integrator.assembly import create_app
from dotmac_integrator.product_auth import ProductAuthenticator
from dotmac_integrator.settings import (
    ManageGrant,
    ProductQueryCaller,
    config_key_is_egress,
)
from tests.support import build_settings

_REAL_DISCOVER = integration.discover
KEY = "manage-key-with-enough-entropy"
QUERY_KEY = "query-key-with-enough-entropy"
INSTALLATION = uuid4()
OTHER_INSTALLATION = uuid4()
BINDING = uuid4()
OTHER_BINDING = uuid4()
CONNECTOR = "example-connector"
GRANT = ManageGrant(
    installation_id=INSTALLATION,
    connector_key=CONNECTOR,
    binding_ids=(BINDING,),
    config_keys=("from_address", "display_name"),
)
HEADERS = {"X-Api-Key": KEY}
BASE = f"/product/v1/manage/installations/{INSTALLATION}"


def _manage_caller(*grants: ManageGrant) -> ProductQueryCaller:
    return ProductQueryCaller(
        application="academy",
        api_key_ref="file:///run/secrets/manage",
        scopes=("integration:manage",),
        manage_grants=grants,
    )


def _query_caller() -> ProductQueryCaller:
    return ProductQueryCaller(
        application="reader",
        api_key_ref="file:///run/secrets/query",
        scopes=("integration:query",),
        binding_ids=(uuid4(),),
    )


# ── Settings shape ──────────────────────────────────────────────────────────


def test_manage_scope_must_stand_alone() -> None:
    with pytest.raises(ValidationError, match="only scope"):
        ProductQueryCaller(
            application="academy",
            api_key_ref="file:///x",
            scopes=("integration:manage", "integration:query"),
        )


def test_grants_are_refused_on_a_caller_without_the_manage_scope() -> None:
    with pytest.raises(ValidationError, match="valid only with"):
        ProductQueryCaller(
            application="a",
            api_key_ref="file:///x",
            scopes=("integration:query",),
            binding_ids=(uuid4(),),
            manage_grants=(GRANT,),
        )


@pytest.mark.parametrize(
    "key", ["host", "smtp_host", "serverUrl", "username", "tls_mode", "password"]
)
def test_a_grant_cannot_allowlist_a_destination_key(key: str) -> None:
    assert config_key_is_egress(key)
    with pytest.raises(ValidationError, match="destination"):
        ManageGrant(
            installation_id=INSTALLATION, connector_key=CONNECTOR, config_keys=(key,)
        )


@pytest.mark.parametrize("key", ["from_address", "display_name", "reply_to"])
def test_sender_labels_are_not_egress_keys(key: str) -> None:
    assert not config_key_is_egress(key)


def test_an_unknown_grant_field_is_a_refused_boot() -> None:
    with pytest.raises(ValidationError):
        ManageGrant.model_validate(
            {
                "installation_id": str(INSTALLATION),
                "connector_key": CONNECTOR,
                "data_set": "x",
            }
        )


def test_the_manage_flag_needs_a_manage_caller() -> None:
    from dotmac_integrator.settings import validate_settings

    problems = validate_settings(build_settings(product_manage_enabled=True))
    assert any("PRODUCT_MANAGE_ENABLED" in p for p in problems)


# ── Authentication ──────────────────────────────────────────────────────────


def test_a_manage_key_does_not_authenticate_for_other_scopes_and_vice_versa() -> None:
    auth = ProductAuthenticator(
        (_manage_caller(GRANT), _query_caller()),
        secret_lookup=lambda ref: KEY if ref.endswith("manage") else QUERY_KEY,
    )
    principal = auth.authenticate(KEY, required_scope="integration:manage")
    assert principal.manage_grants == (GRANT,)
    with pytest.raises(Exception, match="authentication failed"):
        auth.authenticate(KEY, required_scope="integration:query")
    with pytest.raises(Exception, match="authentication failed"):
        auth.authenticate(QUERY_KEY, required_scope="integration:manage")


# ── The routes ──────────────────────────────────────────────────────────────


class _FakeSession:
    def __init__(self, world: SimpleNamespace) -> None:
        self.w = world

    def __enter__(self) -> _FakeSession:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def get(self, model: object, identifier: UUID) -> Any:
        if model is integration.ConnectorConfigRevision:
            return self.w.revision
        return self.w.rows.get(identifier)

    def execute(self, _stmt: object) -> Any:
        rows = self.w.counts
        return SimpleNamespace(
            all=lambda: rows,
            scalars=lambda: SimpleNamespace(all=lambda: self.w.bindings),
        )

    def flush(self) -> None:
        return None

    def commit(self) -> None:
        self.w.commits += 1

    def rollback(self) -> None:
        return None


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> Iterator[SimpleNamespace]:
    installation = SimpleNamespace(
        id=INSTALLATION,
        connector_key=CONNECTOR,
        name="n",
        state="enabled",
        state_reason=None,
        spi_range=">=1.3,<2.0",
        current_config_revision_id=uuid4(),
        updated_by=None,
    )
    binding = SimpleNamespace(
        id=BINDING,
        installation_id=INSTALLATION,
        capability_id="demo.capability",
        state="enabled",
        enabled_at=None,
        updated_by=None,
    )
    foreign = SimpleNamespace(
        id=OTHER_BINDING,
        installation_id=INSTALLATION,
        capability_id="demo.other",
        state="enabled",
        enabled_at=None,
        updated_by=None,
    )
    revision = SimpleNamespace(
        id=installation.current_config_revision_id,
        config_json={"from_address": "a@example.test", "host": "relay.example.test"},
        secret_refs={"credential": "file:///run/secrets/x"},
        network_targets_json=None,
        schema_version="1",
    )
    manifest = SimpleNamespace(
        spi_range=integration.SpiRange.parse(">=1.3,<2.0"),
        capability_ids=frozenset({"demo.capability", "demo.other"}),
        connector_key=CONNECTOR,
        version="1",
    )
    w = SimpleNamespace(
        installation=installation,
        binding=binding,
        revision=revision,
        rows={INSTALLATION: installation, BINDING: binding, OTHER_BINDING: foreign},
        bindings=[binding],
        counts=[("pending", 2)],
        audits=[],
        puts=[],
        commits=0,
        activated=True,
        registry=SimpleNamespace(get=lambda _k: manifest),
    )

    def put(db: Any, inst: Any, **kw: Any) -> Any:
        w.puts.append(kw)
        inst.state = "draft"
        return SimpleNamespace(id=uuid4(), revision=2), True

    monkeypatch.setattr(manage, "Session", lambda _e: _FakeSession(w))
    monkeypatch.setattr(
        manage, "write_platform_audit_event", lambda _db, **kw: w.audits.append(kw)
    )
    monkeypatch.setattr(manage, "_operator_has_activated", lambda _db, _b: w.activated)
    monkeypatch.setattr(integration, "put_config_revision", put)
    yield w


def _client(
    world: SimpleNamespace | None, *grants: ManageGrant, **kw: Any
) -> TestClient:
    integration.discover = _REAL_DISCOVER
    app = create_app(
        build_settings(
            product_manage_enabled=True,
            product_query_callers=(_manage_caller(*grants),),
            **kw,
        ),
    )
    app.state.product_query_authenticator = ProductAuthenticator(
        app.state.settings.product_query_callers, secret_lookup=lambda _ref: KEY
    )
    if world is not None:
        integration.discover = lambda: world.registry  # type: ignore[assignment,misc]
    return TestClient(app)


@pytest.fixture(autouse=True)
def _restore_discover() -> Iterator[None]:
    original = integration.discover
    yield
    integration.discover = original


def test_the_routes_are_absent_while_the_flag_is_off() -> None:
    app = create_app(build_settings())
    assert not [r for r in app.routes if "/product/v1/manage" in str(r.path)]  # type: ignore[attr-defined]


def test_no_key_is_401_and_a_query_key_is_401() -> None:
    client = _client(None, GRANT)
    assert client.get(BASE).status_code == 401
    assert client.get(BASE, headers={"X-Api-Key": "wrong"}).status_code == 401


def test_an_empty_grant_list_refuses_everything(world: SimpleNamespace) -> None:
    client = _client(world)
    body = {"reason": "r"}
    for method, path, kw in (
        ("GET", BASE, {}),
        ("PUT", f"{BASE}/config", {"json": {**body, "config": {"from_address": "x"}}}),
        ("POST", f"{BASE}/bindings/{BINDING}/disable", {"json": body}),
        ("POST", f"{BASE}/bindings/{BINDING}/enable", {"json": body}),
        (
            "POST",
            f"{BASE}/bindings/{BINDING}/test-send",
            {"json": {**body, "to_address": "a@example.test"}},
        ),
    ):
        assert client.request(method, path, headers=HEADERS, **kw).status_code == 403
    assert world.audits == [] and world.puts == []


def test_an_installation_outside_the_allowlist_is_403(world: SimpleNamespace) -> None:
    response = _client(world, GRANT).get(
        f"/product/v1/manage/installations/{OTHER_INSTALLATION}", headers=HEADERS
    )
    assert response.status_code == 403


def test_a_connector_outside_the_grant_is_403(world: SimpleNamespace) -> None:
    world.installation.connector_key = "some-other-connector"
    assert _client(world, GRANT).get(BASE, headers=HEADERS).status_code == 403


def test_read_returns_state_names_and_counts_only(world: SimpleNamespace) -> None:
    response = _client(world, GRANT).get(BASE, headers=HEADERS)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["installation"]["state"] == "enabled"
    assert body["delivery_counts"] == {"pending": 2}
    assert body["secrets"] == {"credential": "unresolved"}
    assert body["config"] == {"from_address": "a@example.test"}  # host not shown
    assert "file://" not in response.text and "relay.example" not in response.text


def test_set_config_carries_everything_it_was_not_given(world: SimpleNamespace) -> None:
    response = _client(world, GRANT).put(
        f"{BASE}/config",
        headers=HEADERS,
        json={
            "reason": "rename sender",
            "asserted_actor": "admin-7",
            "config": {"display_name": "Academy"},
        },
    )
    assert response.status_code == 200, response.text
    put = world.puts[0]
    assert put["config"] == {
        "from_address": "a@example.test",
        "host": "relay.example.test",  # carried over, never editable
        "display_name": "Academy",
    }
    assert put["secret_refs"] == {"credential": "file:///run/secrets/x"}
    assert put["network_targets"] is None
    assert response.json()["installation_state"] == "draft"
    audit = world.audits[0]
    assert audit["action"] == "integrator.manage.config_set"
    assert audit["actor_admin_id"] is None
    assert audit["details"]["principal"] == "academy"
    assert audit["details"]["principal_authenticated"] is True
    assert audit["details"]["asserted_actor"] == "admin-7"
    assert audit["details"]["asserted_actor_authenticated"] is False


@pytest.mark.parametrize(
    "key", ["host", "smtp_host", "username", "tls_mode", "password", "network_targets"]
)
def test_a_destination_change_is_refused_403(world: SimpleNamespace, key: str) -> None:
    response = _client(world, GRANT).put(
        f"{BASE}/config",
        headers=HEADERS,
        json={"reason": "r", "config": {key: "attacker.example.test"}},
    )
    assert response.status_code == 403
    assert "operator-only" in response.text
    assert world.puts == [] and world.audits == []


def test_a_key_outside_the_allowlist_is_403(world: SimpleNamespace) -> None:
    response = _client(world, GRANT).put(
        f"{BASE}/config",
        headers=HEADERS,
        json={"reason": "r", "config": {"footer": "x"}},
    )
    assert response.status_code == 403
    assert world.puts == []


def test_config_is_refused_while_quarantined(world: SimpleNamespace) -> None:
    world.installation.state = "quarantined"
    response = _client(world, GRANT).put(
        f"{BASE}/config",
        headers=HEADERS,
        json={"reason": "r", "config": {"display_name": "x"}},
    )
    assert response.status_code == 409
    assert world.puts == []


def test_disable_own_binding_works_and_is_attributed(world: SimpleNamespace) -> None:
    response = _client(world, GRANT).post(
        f"{BASE}/bindings/{BINDING}/disable",
        headers=HEADERS,
        json={"reason": "pause", "asserted_actor": "admin-7"},
    )
    assert response.status_code == 200, response.text
    assert world.binding.state == "disabled"
    assert world.audits[0]["action"] == "integrator.manage.binding_disabled"
    assert world.audits[0]["details"]["asserted_actor_authenticated"] is False


def test_another_binding_is_403(world: SimpleNamespace) -> None:
    for verb in ("disable", "enable"):
        response = _client(world, GRANT).post(
            f"{BASE}/bindings/{OTHER_BINDING}/{verb}",
            headers=HEADERS,
            json={"reason": "r"},
        )
        assert response.status_code == 403


def test_enable_works_after_an_operator_activation(world: SimpleNamespace) -> None:
    world.binding.state = "disabled"
    response = _client(world, GRANT).post(
        f"{BASE}/bindings/{BINDING}/enable", headers=HEADERS, json={"reason": "resume"}
    )
    assert response.status_code == 200, response.text
    assert world.binding.state == "enabled"


def test_enable_is_refused_if_never_activated(world: SimpleNamespace) -> None:
    world.binding.state = "disabled"
    world.activated = False
    response = _client(world, GRANT).post(
        f"{BASE}/bindings/{BINDING}/enable", headers=HEADERS, json={"reason": "r"}
    )
    assert response.status_code == 409
    assert "never activated" in response.text
    assert world.binding.state == "disabled"


def test_enable_is_refused_if_quarantined(world: SimpleNamespace) -> None:
    world.binding.state = "disabled"
    world.installation.state = "quarantined"
    response = _client(world, GRANT).post(
        f"{BASE}/bindings/{BINDING}/enable", headers=HEADERS, json={"reason": "r"}
    )
    assert response.status_code == 409
    assert world.binding.state == "disabled"


def test_enable_is_refused_while_the_installation_is_not_enabled(
    world: SimpleNamespace,
) -> None:
    world.binding.state = "disabled"
    world.installation.state = "draft"
    response = _client(world, GRANT).post(
        f"{BASE}/bindings/{BINDING}/enable", headers=HEADERS, json={"reason": "r"}
    )
    assert response.status_code == 409


@pytest.mark.parametrize(
    ("method", "suffix"),
    [
        ("POST", "/quarantine/release"),
        ("POST", "/quarantine"),
        ("POST", "/enable"),
        ("POST", "/activate"),
        ("POST", "/network-targets"),
        ("POST", "/operators"),
        ("PUT", "/secrets/credential"),
        ("DELETE", ""),
    ],
)
def test_every_operator_only_operation_is_403(
    world: SimpleNamespace, method: str, suffix: str
) -> None:
    response = _client(world, GRANT).request(
        method, f"{BASE}{suffix}", headers=HEADERS, json={"reason": "r"}
    )
    # `/enable` on the installation itself is not a manage route either.
    assert response.status_code in {403, 405}, (suffix, response.status_code)
    assert world.audits == []


def test_the_manage_key_is_not_an_operator(world: SimpleNamespace) -> None:
    client = _client(world, GRANT)
    for path in (
        f"/operations/installations/{INSTALLATION}/enable",
        f"/operations/bindings/{BINDING}/enable",
        "/operations/connectors",
    ):
        method = "GET" if path.endswith("connectors") else "POST"
        response = client.request(method, path, headers=HEADERS, json={"reason": "r"})
        assert response.status_code == 401, path


def test_test_send_is_unwired_by_default_and_validates_the_address(
    world: SimpleNamespace,
) -> None:
    client = _client(world, GRANT)
    path = f"{BASE}/bindings/{BINDING}/test-send"
    ok = {"reason": "r", "to_address": "person@example.test"}
    assert client.post(path, headers=HEADERS, json=ok).status_code == 503
    for bad in (
        "not-an-address",
        "a@b@c",
        "a b@example.test",
        "x@example.test,y@example.test",
    ):
        response = client.post(
            path, headers=HEADERS, json={"reason": "r", "to_address": bad}
        )
        assert response.status_code == 422, bad


def test_test_send_calls_the_injected_sender_once(world: SimpleNamespace) -> None:
    calls: list[dict[str, Any]] = []

    def sender(engine: Any, **kw: Any) -> dict[str, Any]:
        calls.append(kw)
        return {"queued": True}

    app = create_app(
        build_settings(
            product_manage_enabled=True,
            product_query_callers=(_manage_caller(GRANT),),
        ),
        manage_test_sender=sender,
    )
    app.state.product_query_authenticator = ProductAuthenticator(
        app.state.settings.product_query_callers, secret_lookup=lambda _r: KEY
    )
    integration.discover = lambda: world.registry  # type: ignore[assignment,misc]
    response = TestClient(app).post(
        f"{BASE}/bindings/{BINDING}/test-send",
        headers=HEADERS,
        json={"reason": "check", "to_address": "person@example.test"},
    )
    assert response.status_code == 200, response.text
    assert len(calls) == 1 and calls[0]["to_address"] == "person@example.test"
    assert world.audits[0]["action"] == "integrator.manage.test_send"
    assert world.audits[0]["details"]["to_domain"] == "example.test"
    assert "person@" not in str(world.audits[0])
