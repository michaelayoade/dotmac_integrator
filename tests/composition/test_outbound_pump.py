"""The outbound pump against a real database and a FAKE delivery connector.

No real mail connector exists yet (it is built separately in the Starter), so a
tiny in-test DELIVERY plugin counts its invocations. What is proved:

* the same dispatch key twice gives ONE invoke;
* a process killed after the connector was called gives AMBIGUOUS and no resend,
  and the module's blanket lease release WOULD have resent it (sensitivity);
* a connector-reported ambiguity is terminal, and requeue needs the explicit
  acknowledgement;
* a delivered payload is redacted after the retention period and not before.

Requires PostgreSQL; skipped without one (CI does not skip).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import dotmac_integration as integration
import pytest
from dotmac_integration.retry import Outcome, OutcomeStatus
from dotmac_integration.spi import (
    CapabilityDeclaration,
    ConnectorManifest,
    ConnectorMode,
    DispatchRequest,
    EgressDeclaration,
    SpiRange,
)
from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
from dotmac_kernel.models_platform import PlatformAdmin
from dotmac_kernel.modules import ModuleRegistry
from dotmac_kernel.security import hash_password
from fastapi import HTTPException
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from dotmac_integrator import operations, outbound, requeue_ambiguous
from dotmac_integrator.manifest import module as assembly_module
from dotmac_integrator.product_auth import ProductPrincipal
from dotmac_integrator.settings import get_settings
from tests.support import build_settings

CAPABILITY = "fake.delivery.v1"
CONNECTOR = "fake_delivery"


class _Contract:
    result_schema = None

    def require_command(self, payload: object) -> None:
        if not isinstance(payload, dict) or "to" not in payload:
            raise integration.CapabilityPayloadRejected("payload needs a recipient")

    def require_result(self, result: object) -> None:  # pragma: no cover
        return None


CAPABILITIES = SimpleNamespace(get=lambda _capability_id: _Contract())


class _Plugin:
    """DELIVERY connector that records every call and behaves as told."""

    modes = frozenset({ConnectorMode.DELIVERY})
    historical_manifests: tuple[ConnectorManifest, ...] = ()
    manifest = ConnectorManifest(
        connector_key=CONNECTOR,
        version="0.0.1",
        spi_range=SpiRange.parse(">=1.3,<2.0"),
        capabilities=(
            CapabilityDeclaration(
                capability_id=CAPABILITY, modes=frozenset({ConnectorMode.DELIVERY})
            ),
        ),
        secret_bindings=(),
        egress=EgressDeclaration(hosts=()),
    )

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.behaviour: Callable[[DispatchRequest], Outcome] = lambda _r: Outcome(
            status=OutcomeStatus.SUCCEEDED
        )

    def handler_for(self, capability_id: str) -> Callable[[DispatchRequest], Outcome]:
        def handle(request: DispatchRequest) -> Outcome:
            self.calls.append(request.idempotency_key)
            return self.behaviour(request)

        return handle

    def validate_connection(self, *, config: Any, secrets: Any) -> list[Any]:
        return []


class _Crash(BaseException):
    """Stands in for kill -9: not an Exception, so nothing catches it."""


@pytest.fixture
def world(migrated: str) -> Any:
    manifests = ModuleRegistry((integration.module, assembly_module)).startup_order()
    install_audit_actions(AuditActionRegistry.from_manifests(manifests))
    engine = create_engine(migrated)
    with engine.begin() as conn:
        # The database is shared by the module's tests; rows a previous test
        # left queued would be driven by this test's pump.
        conn.execute(text("DELETE FROM mod_intg.delivery_attempts"))
    plugin = _Plugin()
    registry = integration.ConnectorRegistry(plugins=(plugin,))  # type: ignore[arg-type]
    with Session(engine) as db:
        installation = integration.create_draft(
            db, registry=registry, connector_key=CONNECTOR, name=f"n-{uuid4().hex[:6]}"
        )
        integration.put_config_revision(
            db, installation, registry=registry, config={}, secret_refs={}
        )
        binding = integration.add_binding(
            db, installation, registry=registry, capability_id=CAPABILITY
        )
        integration.enable(db, installation, registry=registry)
        integration.set_binding_enabled(
            db, installation, binding, registry=registry, enabled=True
        )
        db.commit()
        binding_id = binding.id
    principal = ProductPrincipal(
        "academy", frozenset({"integration:dispatch"}), frozenset({binding_id})
    )
    yield SimpleNamespace(
        engine=engine,
        plugin=plugin,
        registry=registry,
        binding_id=binding_id,
        principal=principal,
    )
    engine.dispose()


def _body(binding_id: UUID, key: str, **payload: object) -> outbound.DispatchBody:
    return outbound.DispatchBody(
        dispatch_id=key,
        capability_binding_id=binding_id,
        event_type="mail.send",
        payload=payload or {"to": "person@example.test"},
    )


def _submit(w: Any, key: str, **payload: object) -> dict[str, Any]:
    return outbound.submit_dispatch(
        w.engine,
        w.principal,
        _body(w.binding_id, key, **payload),
        wait_seconds=0,
        capabilities=CAPABILITIES,
    )


def _pump(w: Any) -> dict[str, int]:
    return outbound.deliver_due_outbound(
        w.engine, 10, registry=w.registry, capabilities=CAPABILITIES, resolver=dict
    )


def _state(engine: Engine, key: str) -> str:
    with Session(engine) as db:
        return str(
            db.execute(
                text(
                    "SELECT state FROM mod_intg.delivery_attempts "
                    "WHERE idempotency_key = :k"
                ),
                {"k": key},
            ).scalar_one()
        )


def test_the_same_key_twice_gives_one_invoke(world: Any) -> None:
    first = _submit(world, "dispatch-1")
    assert first["state"] == "pending" and first["accepted_now"] is True
    assert _pump(world)["settled"] == 1
    second = _submit(world, "dispatch-1")
    assert second["accepted_now"] is False
    assert second["state"] == "delivered" and second["terminal"] is True
    _pump(world)  # nothing is due: the row is terminal
    assert world.plugin.calls == ["dispatch-1"]


def test_the_same_key_with_different_content_is_refused(world: Any) -> None:
    _submit(world, "dispatch-2")
    with pytest.raises(HTTPException) as refused:
        _submit(world, "dispatch-2", to="someone-else@example.test")
    assert refused.value.status_code == 409


def test_a_binding_other_than_the_callers_is_refused(world: Any) -> None:
    with pytest.raises(HTTPException) as refused:
        outbound.submit_dispatch(
            world.engine,
            world.principal,
            _body(uuid4(), "dispatch-3"),
            wait_seconds=0,
            capabilities=CAPABILITIES,
        )
    assert refused.value.status_code == 403


def test_a_payload_the_contract_rejects_is_not_queued(world: Any) -> None:
    with pytest.raises(HTTPException) as refused:
        outbound.submit_dispatch(
            world.engine,
            world.principal,
            outbound.DispatchBody(
                dispatch_id="dispatch-4",
                capability_binding_id=world.binding_id,
                event_type="mail.send",
                payload={"no_recipient": True},
            ),
            wait_seconds=0,
            capabilities=CAPABILITIES,
        )
    assert refused.value.status_code == 422


def _expire_lease(engine: Engine, key: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE mod_intg.delivery_attempts SET leased_until = :t "
                "WHERE idempotency_key = :k"
            ),
            {"t": datetime.now(UTC) - timedelta(minutes=5), "k": key},
        )


def test_a_crash_after_invoke_is_ambiguous_and_never_resent(world: Any) -> None:
    _submit(world, "dispatch-5")

    def die(_request: DispatchRequest) -> Outcome:
        raise _Crash

    world.plugin.behaviour = die
    with pytest.raises(_Crash):
        _pump(world)
    assert world.plugin.calls == ["dispatch-5"]
    assert _state(world.engine, "dispatch-5") == "in_flight"

    _expire_lease(world.engine, "dispatch-5")
    operations.sweep_expired_leases(world.engine, outbound_ambiguity=True)
    assert _state(world.engine, "dispatch-5") == "reconciliation_required"

    world.plugin.behaviour = lambda _r: Outcome(status=OutcomeStatus.SUCCEEDED)
    for _ in range(3):
        _pump(world)
        operations.sweep_expired_leases(world.engine, outbound_ambiguity=True)
    assert world.plugin.calls == ["dispatch-5"], "an ambiguous send was resent"
    view = _submit(world, "dispatch-5")
    assert view["state"] == "ambiguous" and view["terminal"] is True


def test_sensitivity_the_blanket_release_alone_would_resend(world: Any) -> None:
    """Proves the test above bites: without the outbound handling, the module's
    own lease release makes the stranded row retryable and it is sent again."""
    _submit(world, "dispatch-6")

    def die(_request: DispatchRequest) -> Outcome:
        raise _Crash

    world.plugin.behaviour = die
    with pytest.raises(_Crash):
        _pump(world)
    _expire_lease(world.engine, "dispatch-6")
    operations.sweep_expired_leases(world.engine, outbound_ambiguity=False)
    assert _state(world.engine, "dispatch-6") == "retryable"


def test_a_reported_ambiguity_is_terminal_and_replay_route_refuses(
    world: Any,
) -> None:
    world.plugin.behaviour = lambda _r: Outcome(
        status=OutcomeStatus.RECONCILIATION_REQUIRED, error_code="outcome_unknown"
    )
    _submit(world, "dispatch-7")
    _pump(world)
    _pump(world)
    assert world.plugin.calls == ["dispatch-7"]
    assert _state(world.engine, "dispatch-7") == "reconciliation_required"
    with Session(world.engine) as db:
        delivery_id = db.execute(
            text(
                "SELECT id FROM mod_intg.delivery_attempts "
                "WHERE idempotency_key = 'dispatch-7'"
            )
        ).scalar_one()
    actor = SimpleNamespace(admin_id=uuid4(), label="op", mechanism="platform_admin")
    with pytest.raises(HTTPException) as refused:
        operations.replay_delivery(world.engine, str(delivery_id), actor, "retry")  # type: ignore[arg-type]
    assert refused.value.status_code == 409
    assert _state(world.engine, "dispatch-7") == "reconciliation_required"


def test_requeue_needs_the_explicit_acknowledgement(
    world: Any, migrated: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.plugin.behaviour = lambda _r: Outcome(
        status=OutcomeStatus.RECONCILIATION_REQUIRED, error_code="outcome_unknown"
    )
    _submit(world, "dispatch-8")
    _pump(world)
    with Session(world.engine) as db:
        delivery_id = db.execute(
            text(
                "SELECT id FROM mod_intg.delivery_attempts "
                "WHERE idempotency_key = 'dispatch-8'"
            )
        ).scalar_one()
        admin = PlatformAdmin(
            email=f"op-{uuid4().hex[:6]}@example.test",
            password_hash=hash_password("not-used-anywhere"),
            is_active=True,
        )
        db.add(admin)
        db.commit()
        email = admin.email
    monkeypatch.setenv("DATABASE_URL", migrated)
    get_settings.cache_clear()
    base = [
        "--delivery-id",
        str(delivery_id),
        "--operator-email",
        email,
        "--reason",
        "checked with the provider",
    ]
    assert requeue_ambiguous.main(base) == 2
    assert _state(world.engine, "dispatch-8") == "reconciliation_required"
    assert requeue_ambiguous.main([*base, "--accept-possible-duplicate"]) == 0
    assert _state(world.engine, "dispatch-8") == "pending"
    get_settings.cache_clear()


def test_a_delivered_payload_is_redacted_after_retention_and_not_before(
    world: Any,
) -> None:
    _submit(world, "dispatch-9")
    _pump(world)
    settings = build_settings(
        outbound_payload_retention_days=7,
        outbound_replay_evidence_retention_days=30,
        outbound_legal_policy_owner="data-protection-owner",
    )
    assert outbound.redact_expired_payloads(world.engine, settings) == 0
    with world.engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE mod_intg.delivery_attempts SET created_at = :t "
                "WHERE idempotency_key = 'dispatch-9'"
            ),
            {"t": datetime.now(UTC) - timedelta(days=8)},
        )
    assert outbound.redact_expired_payloads(world.engine, settings) == 1
    with Session(world.engine) as db:
        payload = db.execute(
            text(
                "SELECT payload_json::text FROM mod_intg.delivery_attempts "
                "WHERE idempotency_key = 'dispatch-9'"
            )
        ).scalar_one()
    assert "person@example.test" not in payload
    assert integration.REDACTION_MARKER in payload
