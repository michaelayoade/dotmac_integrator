"""`_latest_state_event` against real audit rows: the rule that stops the manage
caller undoing an operator is only as good as this query."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import dotmac_integration as integration
from dotmac_kernel.audit import write_platform_audit_event
from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
from dotmac_kernel.modules import ModuleRegistry
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from dotmac_integrator import manage
from dotmac_integrator.manifest import module as assembly_module


def test_the_latest_state_event_wins_and_names_its_principal(migrated: str) -> None:
    manifests = ModuleRegistry((integration.module, assembly_module)).startup_order()
    install_audit_actions(AuditActionRegistry.from_manifests(manifests))
    engine = create_engine(migrated)
    binding, installation = uuid4(), uuid4()
    base = datetime.now(UTC) - timedelta(hours=1)

    def write(
        action: str, entity: str, entity_id: object, principal: object, n: int
    ) -> None:
        with Session(engine) as db:
            event = write_platform_audit_event(
                db,
                actor_admin_id=None,
                action=action,
                entity_type=entity,
                entity_id=str(entity_id),
                details={"principal": principal},
            )
            db.flush()
            db.execute(
                text("UPDATE platform_audit_events SET created_at=:t WHERE id=:i"),
                {"t": base + timedelta(minutes=n), "i": event.id},
            )
            db.commit()

    with Session(engine) as db:
        assert manage._latest_state_event(db, binding, installation) is None
    write("integrator.binding.enabled", "capability_binding", binding, None, 1)
    write(
        "integrator.manage.binding_disabled",
        "capability_binding",
        binding,
        "academy",
        2,
    )
    with Session(engine) as db:
        assert manage._latest_state_event(db, binding, installation) == (
            "integrator.manage.binding_disabled",
            "academy",
        )
    # An operator action AFTER the product's own disable takes it over.
    write("integrator.binding.enabled", "capability_binding", binding, None, 3)
    with Session(engine) as db:
        latest = manage._latest_state_event(db, binding, installation)
    assert latest is not None and latest[0] == "integrator.binding.enabled"
    # Another binding's or installation's events are not this one's.
    write(
        "integrator.manage.binding_disabled",
        "capability_binding",
        uuid4(),
        "academy",
        4,
    )
    with Session(engine) as db:
        latest = manage._latest_state_event(db, binding, installation)
    assert latest is not None and latest[0] == "integrator.binding.enabled"
    # An installation-level quarantine release is newer still.
    write(
        "integrator.installation.enabled",
        "connector_installation",
        installation,
        None,
        5,
    )
    with Session(engine) as db:
        latest = manage._latest_state_event(db, binding, installation)
    assert latest is not None and latest[0] == "integrator.installation.enabled"
    engine.dispose()
