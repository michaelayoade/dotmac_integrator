"""The enablement gate and the audit trail, against a real migrated database.

`tests/unit` proves each decision in isolation with no database. This proves the
composition: a real operator authenticates against the kernel's platform
identity tables in THIS deployment's own database, drives the enablement gate,
and leaves an audit row that names them.

Three things can only be proved here:

1. the operator identity tables the guard depends on are actually created by
   the composed kernel lineage — the guard is a compile-time import and a
   runtime query, and only one of those is checked by a unit test;
2. the ONLINE platform role can read them and write the audit ledger, because a
   guard that 500s on a permission error is an outage, not a guard;
3. enablement is refused for missing material BEFORE the connector is consulted,
   and the refusal is evidenced with an actor.

Requires a real database; skipped without one, so a contributor without
PostgreSQL still gets the rest of the suite. CI does not skip.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from uuid import uuid4

import dotmac_integration as integration
import pytest
from dotmac_kernel.config import settings as kernel_settings
from dotmac_kernel.models_platform import PlatformAdmin, PlatformSession
from dotmac_kernel.platform_auth import issue_platform_token
from dotmac_kernel.security import hash_password, hash_token
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from dotmac_integrator.assembly import create_app
from tests.support import build_settings

#: The kernel authenticates host-exact. `TestClient` sends `Host: testserver`,
#: so requests carry the configured platform root explicitly rather than the
#: suite mutating a kernel singleton. Read from the kernel rather than
#: hardcoded, so a developer whose environment sets PLATFORM_ROOT_DOMAIN does
#: not get a mysterious 401.
PLATFORM_HOST = kernel_settings.platform_root_domain

SECRET_ENV = "INTEGRATOR_SECRET_END_TO_END"
SECRET_REF = f"env://{SECRET_ENV}"


@pytest.fixture
def operator(migrated: str) -> tuple[str, str]:
    """A real platform admin with a live session. Returns `(token, admin_id)`."""
    engine = create_engine(migrated)
    with Session(engine) as db:
        admin = PlatformAdmin(
            email=f"operator-{uuid4().hex[:8]}@dotmac.test",
            password_hash=hash_password("a-password-nothing-reads"),
            is_active=True,
        )
        db.add(admin)
        db.flush()
        token, expires_at = issue_platform_token(admin.id)
        db.add(
            PlatformSession(
                admin_id=admin.id, token_hash=hash_token(token), expires_at=expires_at
            )
        )
        admin_id = str(admin.id)
        db.commit()
    engine.dispose()
    return token, admin_id


@pytest.fixture
def client(migrated: str) -> Iterator[TestClient]:
    app = create_app(build_settings(database_url=migrated))
    # Entered, so the lifespan runs and secret material is loaded exactly as it
    # would be at boot — the whole point is that resolution reads what startup
    # held, not what a request could fetch.
    with TestClient(app) as entered:
        yield entered


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Host": PLATFORM_HOST}


def _install(migrated: str, secret_refs: dict[str, str]) -> str:
    """An installation with one configuration revision. Rows, not routes.

    Written directly because there is no route that authors an installation:
    a draft pins the connector installed at that moment, so authoring belongs
    with the first connector distribution rather than before it.
    """
    engine = create_engine(migrated)
    with Session(engine) as db:
        installation = integration.ConnectorInstallation(
            connector_key="test.connector",
            connector_version="0.0.1",
            spi_range="1.0,<2.0",
            manifest_digest="0" * 64,
            name=f"end-to-end-{uuid4().hex[:8]}",
            environment="production",
            state="draft",
        )
        db.add(installation)
        db.flush()
        revision = integration.ConnectorConfigRevision(
            installation_id=installation.id,
            revision=1,
            schema_version="1",
            config_json={"endpoint": "https://provider.invalid"},
            secret_refs=secret_refs,
            config_digest=uuid4().hex + uuid4().hex,
            validation_status="valid",
        )
        db.add(revision)
        db.flush()
        installation.current_config_revision_id = revision.id
        identifier = str(installation.id)
        db.commit()
    engine.dispose()
    return identifier


# ── The guard, against the real identity tables ─────────────────────────────


def test_an_authenticated_operator_reaches_the_operations_surface(
    client: TestClient, operator: tuple[str, str]
) -> None:
    token, _ = operator
    response = client.get("/operations/connectors", headers=_headers(token))
    assert response.status_code == 200, response.text
    assert response.json()["count"] >= 1


def test_a_revoked_session_stops_working_immediately(
    client: TestClient, operator: tuple[str, str], migrated: str
) -> None:
    """Revocation is the reason sessions are rows rather than only signatures.

    A token whose session row is revoked must fail on the NEXT request, not at
    its expiry — that is the whole operational value of a session table, and it
    is the mechanism an incident actually reaches for.
    """
    token, _ = operator
    assert (
        client.get("/operations/connectors", headers=_headers(token)).status_code == 200
    )

    engine = create_engine(migrated)
    with Session(engine) as db:
        session = db.scalars(
            select(PlatformSession).where(
                PlatformSession.token_hash == hash_token(token)
            )
        ).one()
        session.revoked_at = session.expires_at
        db.commit()
    engine.dispose()

    assert (
        client.get("/operations/connectors", headers=_headers(token)).status_code == 401
    )


def test_the_online_platform_role_can_operate_the_identity_and_audit_tables(
    migrated: str,
) -> None:
    """A guard that 500s on a permission error is an outage, not a guard.

    The runtime role is `platform_api`, not the owner. It never creates a
    table — but it must read the identity tables the guard queries and INSERT
    into the audit ledger every operator action writes, or the first
    authenticated request in production fails on a grant.
    """
    engine = create_engine(migrated)
    required = [
        ("platform_admins", "SELECT"),
        ("platform_sessions", "SELECT"),
        ("platform_sessions", "INSERT"),
        ("platform_sessions", "UPDATE"),
        ("platform_audit_events", "INSERT"),
    ]
    with engine.connect() as conn:
        held = {
            (table, privilege): conn.execute(
                text(
                    "SELECT has_table_privilege(CAST(:r AS text), "
                    "CAST(:t AS text), CAST(:p AS text))"
                ),
                {"r": "platform_api", "t": f"public.{table}", "p": privilege},
            ).scalar_one()
            for table, privilege in required
        }
    engine.dispose()
    missing = sorted(key for key, granted in held.items() if not granted)
    assert not missing, f"platform_api lacks {missing}"


def test_the_tenant_role_holds_nothing_on_the_platform_identity_tables(
    migrated: str,
) -> None:
    """Sensitivity proof for the grant check above.

    A `has_table_privilege` sweep that returned True for everything would pass
    the previous test without proving anything. `app_user` is the control: on
    this plane the REVOKE is the isolation.
    """
    engine = create_engine(migrated)
    with engine.connect() as conn:
        granted = conn.execute(
            text(
                "SELECT has_table_privilege(CAST(:r AS text), "
                "CAST(:t AS text), 'SELECT')"
            ),
            {"r": "app_user", "t": "public.platform_admins"},
        ).scalar_one()
    engine.dispose()
    assert granted is False


# ── Provider-neutral authoring ──────────────────────────────────────────────


def test_an_operator_can_author_the_installed_connector_without_direct_rows(
    client: TestClient,
    operator: tuple[str, str],
    migrated: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Draft → bind → configure → validate → mint → activate, through HTTP.

    This is the first real connector flow and deliberately creates no module
    ORM row in the test.  The connector and capability identities occur only in
    this acceptance fixture; generic assembly source learns them from package
    metadata and operator input.

    ## The SPI 1.3 authoring shape, which is NOT the 1.2 one

    Under 1.2 an operator invented slot ALIASES — `signing_slots: ["signing"]`,
    `handshake_slot: "handshake"` — and keyed `secret_refs` by those aliases.
    1.3 makes the logical secret names part of the installed package contract,
    so the aliases are gone: `config` is EMPTY and `secret_refs` is keyed by the
    names the connector's own manifest DECLARES. The connector still ships its
    1.2 schema in `historical_manifests`, so a persisted a1 revision keeps
    validating; a NEW revision is written against the current manifest and the
    old shape is refused as `config_additionalProperties`.

    That refusal is how this test found the change, which is the argument for
    driving the whole flow over HTTP rather than asserting the pin moved.
    """
    token, admin_id = operator
    headers = _headers(token)
    # The DECLARED binding names, from the connector's own manifest. Written out
    # rather than imported: this assembly may not import a connector, and an
    # acceptance fixture that read the name from the package under test would
    # agree with it by construction and prove nothing about the contract.
    signing_slot = "webhook_signing_secret"
    handshake_slot = "webhook_verify_token"
    signing_name = "INTEGRATOR_SECRET_AUTHORING_SIGNING"
    handshake_name = "INTEGRATOR_SECRET_AUTHORING_HANDSHAKE"
    signing_ref = f"env://{signing_name}"
    handshake_ref = f"env://{handshake_name}"
    signing_material = "signing-material-never-persisted"
    handshake_material = "handshake-material-never-persisted"

    drafted = client.post(
        "/operations/installations",
        headers=headers,
        json={
            "connector_key": "meta_whatsapp",
            "name": f"authoring-{uuid4().hex[:8]}",
            "environment": "test",
            "reason": "prove the first installed connector authoring flow",
        },
    )
    assert drafted.status_code == 200, drafted.text
    installation_id = drafted.json()["id"]
    assert drafted.json()["state"] == "draft"

    bound = client.post(
        f"/operations/installations/{installation_id}/bindings",
        headers=headers,
        json={
            "capability_id": "messaging.receive.v1",
            "scope": {"deployment": "acceptance"},
            "reason": "bind the declared ingress contract",
        },
    )
    assert bound.status_code == 200, bound.text
    binding_id = bound.json()["id"]
    assert bound.json()["state"] == "disabled"

    configured = client.post(
        f"/operations/installations/{installation_id}/config-revisions",
        headers=headers,
        json={
            # EMPTY under SPI 1.3 — the connector's current schema is
            # `additionalProperties: false` with no properties, because the
            # logical names below are the package's contract rather than an
            # operator's choice.
            "config": {},
            "secret_refs": {
                signing_slot: signing_ref,
                handshake_slot: handshake_ref,
            },
            "schema_version": "1",
            "reason": "pin the ingress verification configuration",
        },
    )
    assert configured.status_code == 200, configured.text
    assert configured.json()["is_new"] is True
    assert configured.json()["validation_status"] == "pending"

    monkeypatch.setenv(signing_name, signing_material)
    monkeypatch.setenv(handshake_name, handshake_material)
    refreshed = client.post(
        "/operations/secrets/refresh",
        headers=headers,
        json={"reason": "materialise the two approved references"},
    )
    assert refreshed.status_code == 200, refreshed.text
    assert {signing_ref, handshake_ref} <= set(refreshed.json()["held"])

    enabled = client.post(
        f"/operations/installations/{installation_id}/enable",
        headers=headers,
        json={"reason": "connection validation succeeded"},
    )
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["state"] == "enabled"

    minted = client.post(
        f"/operations/bindings/{binding_id}/ingress-endpoint/mint",
        headers=headers,
        json={"reason": "publish the ingress address"},
    )
    assert minted.status_code == 200, minted.text
    endpoint_key = minted.json()["ingress_endpoint_key"]
    assert len(endpoint_key) == 48

    activated = client.post(
        f"/operations/bindings/{binding_id}/enable",
        headers=headers,
        json={"reason": "the provider subscription is ready"},
    )
    assert activated.status_code == 200, activated.text
    assert activated.json()["state"] == "enabled"

    engine = create_engine(migrated)
    with engine.connect() as conn:
        persisted = conn.execute(
            text(
                "SELECT config_json::text, secret_refs::text "
                "FROM mod_intg.connector_config_revisions "
                "WHERE installation_id = CAST(:id AS uuid)"
            ),
            {"id": installation_id},
        ).one()
        evidence = conn.execute(
            text(
                "SELECT action, actor_admin_id, details::text "
                "FROM platform_audit_events "
                "WHERE entity_id IN (:installation_id, :binding_id)"
            ),
            {"installation_id": installation_id, "binding_id": binding_id},
        ).all()
    engine.dispose()

    persisted_text = " ".join(str(value) for value in persisted)
    audit_text = " ".join(str(value) for row in evidence for value in row)
    assert signing_ref in persisted_text and handshake_ref in persisted_text
    assert signing_material not in persisted_text + audit_text
    assert handshake_material not in persisted_text + audit_text
    assert endpoint_key not in audit_text
    host_evidence = [row for row in evidence if str(row[0]).startswith("integrator.")]
    assert all(str(row[1]) == admin_id for row in host_evidence)
    assert all('"reason"' in str(row[2]) for row in host_evidence)
    actions = {str(row[0]) for row in evidence}
    assert {
        "integrator.installation.drafted",
        "integrator.binding.configured",
        "integrator.installation.configured",
        "integrator.installation.enabled",
        "integrator.ingress_endpoint.minted",
        "integrator.binding.enabled",
        "integration.ingress_endpoint.minted",
    } <= actions


def test_the_pre_1_3_configuration_shape_is_refused(
    client: TestClient, operator: tuple[str, str]
) -> None:
    """Sensitivity proof for the change above (ADR-0018).

    The test before this one was rewritten to the SPI 1.3 authoring shape. A
    rewrite that only asserts the NEW shape works would pass just as happily if
    the module had quietly kept accepting the old one — and then nobody would
    know that an operator following the previous runbook writes a revision the
    connector cannot use.

    So the retired shape is driven deliberately and must be REFUSED, by the
    module's own capability-schema validation, with the conflict naming the
    capability. This is also the migration note in executable form: operator
    slot aliases are gone, and `secret_refs` is keyed by the connector's
    declared binding names.
    """
    token, _admin_id = operator
    headers = _headers(token)

    drafted = client.post(
        "/operations/installations",
        headers=headers,
        json={
            "connector_key": "meta_whatsapp",
            "name": f"legacy-shape-{uuid4().hex[:8]}",
            "environment": "test",
            "reason": "prove the retired configuration shape is refused",
        },
    )
    assert drafted.status_code == 200, drafted.text
    installation_id = drafted.json()["id"]

    bound = client.post(
        f"/operations/installations/{installation_id}/bindings",
        headers=headers,
        json={
            "capability_id": "messaging.receive.v1",
            "scope": {"deployment": "acceptance"},
            "reason": "bind the declared ingress contract",
        },
    )
    assert bound.status_code == 200, bound.text

    refused = client.post(
        f"/operations/installations/{installation_id}/config-revisions",
        headers=headers,
        json={
            "config": {
                "signing_slots": ["signing"],
                "handshake_slot": "handshake",
            },
            "secret_refs": {
                "signing": "env://INTEGRATOR_SECRET_AUTHORING_SIGNING",
                "handshake": "env://INTEGRATOR_SECRET_AUTHORING_HANDSHAKE",
            },
            "schema_version": "1",
            "reason": "the shape a pre-1.3 runbook would produce",
        },
    )
    assert refused.status_code == 409, refused.text
    assert "messaging.receive.v1" in refused.json()["detail"]


# ── The enablement gate ─────────────────────────────────────────────────────


def test_enablement_is_refused_when_referenced_material_is_not_held(
    client: TestClient, operator: tuple[str, str], migrated: str
) -> None:
    """The gate the held-secret resolver exists to be.

    The environment variable behind `SECRET_REF` is deliberately unset, so
    startup held nothing for it. The refusal must name the REFERENCE and must
    arrive before the connector is consulted — a missing credential surfacing as
    a provider authentication failure reads like the provider is down.
    """
    token, admin_id = operator
    installation_id = _install(migrated, {"api_key": SECRET_REF})

    response = client.post(
        f"/operations/installations/{installation_id}/enable",
        headers=_headers(token),
        json={"reason": "first enablement after provisioning"},
    )
    assert response.status_code == 409, response.text
    detail = response.json()["detail"]
    assert SECRET_REF in detail
    assert "refresh" in detail

    engine = create_engine(migrated)
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT actor_admin_id, details FROM platform_audit_events "
                "WHERE action = :a AND entity_id = :e"
            ),
            {"a": "integrator.installation.enable_refused", "e": installation_id},
        ).all()
    engine.dispose()

    assert len(rows) == 1, "a refused enablement left no evidence"
    actor, details = rows[0]
    assert str(actor) == admin_id, "the audit row cannot say who"
    assert details["reason"] == "first enablement after provisioning"
    assert details["refusal"] == "material_not_held"


def test_the_gate_opens_once_the_material_is_held(
    client: TestClient,
    operator: tuple[str, str],
    migrated: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other direction, which is what makes the refusal above meaningful.

    With the material present and an explicit refresh performed, the material
    check passes and the request reaches the connector lookup — which fails,
    because no installed connector declares the deliberately fake key on this
    fixture. That is the correct next refusal and it proves the gate was crossed
    rather than absent.

    The refresh is explicit on purpose: the variable was set after boot, and
    ADR-0009 makes rotation an operator act rather than a timer.
    """
    token, _ = operator
    installation_id = _install(migrated, {"api_key": SECRET_REF})
    monkeypatch.setenv(SECRET_ENV, "material-long-enough-to-redact")

    refreshed = client.post(
        "/operations/secrets/refresh",
        headers=_headers(token),
        json={"reason": "provisioned the credential"},
    )
    assert refreshed.status_code == 200, refreshed.text
    assert SECRET_REF in refreshed.json()["held"]

    response = client.post(
        f"/operations/installations/{installation_id}/enable",
        headers=_headers(token),
        json={"reason": "enable after provisioning the credential"},
    )
    assert response.status_code == 409, response.text
    detail: str = response.json()["detail"]
    assert "no installed connector declares key" in detail
    assert SECRET_REF not in detail
    assert "material-long-enough-to-redact" not in detail


def test_the_secret_report_never_names_a_value(
    client: TestClient,
    operator: tuple[str, str],
    migrated: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, _ = operator
    _install(migrated, {"api_key": SECRET_REF})
    monkeypatch.setenv(SECRET_ENV, "material-long-enough-to-redact")
    client.post(
        "/operations/secrets/refresh",
        headers=_headers(token),
        json={"reason": "provisioned"},
    )

    body: dict[str, Any] = client.get(
        "/operations/secrets", headers=_headers(token)
    ).json()
    serialised = str(body)
    assert SECRET_REF in serialised, "the reference is a pointer and is reportable"
    assert "material-long-enough-to-redact" not in serialised
