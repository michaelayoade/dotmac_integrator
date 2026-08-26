"""Revisioned mirror evidence against the actually migrated PostgreSQL stack."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import dotmac_integration as integration
from dotmac_kernel.models_platform import PlatformAuditEvent
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from dotmac_integrator import delivery, shadow_evidence
from dotmac_integrator.assembly import create_app
from tests.support import build_settings

REVISION = "image-sha256:shadow-composition-v1"


def _receipt(migrated: str, *, suffix: str) -> UUID:
    engine = create_engine(migrated)
    with Session(engine) as db:
        installation = integration.ConnectorInstallation(
            connector_key=f"test.shadow.{suffix}",
            connector_version="0.0.1",
            spi_range=">=1.0,<2.0",
            manifest_digest="0" * 64,
            name=f"shadow-evidence-{suffix}-{uuid4().hex[:8]}",
            environment="test",
            state="enabled",
        )
        db.add(installation)
        db.flush()
        binding = integration.CapabilityBinding(
            installation_id=installation.id,
            capability_id="messaging.receive.v1",
            state="enabled",
        )
        db.add(binding)
        db.flush()
        receipt = integration.InboxReceipt(
            installation_id=installation.id,
            capability_binding_id=binding.id,
            provider_event_id=f"event-{uuid4()}",
            event_type="message.received",
            payload_digest="1" * 64,
            payload_json={"messages": []},
            state="verified",
        )
        db.add(receipt)
        db.commit()
        receipt_id = receipt.id
    engine.dispose()
    return receipt_id


def test_terminal_shadow_evidence_is_append_only_and_never_settles_a_receipt(
    migrated: str,
) -> None:
    # Installs the composed audit vocabulary exactly as the runtime does.
    app = create_app(
        build_settings(database_url=migrated, product_port_shadow_revision=REVISION)
    )
    app.state.engine.dispose()
    receipt_id = _receipt(migrated, suffix="terminal")
    engine = create_engine(migrated)

    assert receipt_id in delivery.due_shadow_receipt_ids(
        engine,
        10,
        comparison_revision=REVISION,
        retry_after_seconds=300,
    )

    shadow_evidence.record_shadow_observation(
        engine,
        receipt_id=receipt_id,
        comparison_revision=REVISION,
        verdict=shadow_evidence.SafeShadowVerdict(
            verdict="agrees", blocking_reasons=(), disagreeing_fields=()
        ),
    )

    with Session(engine) as db:
        receipt = db.get(integration.InboxReceipt, receipt_id)
        assert receipt is not None
        assert receipt.state == "verified"
        assert receipt.attempt_count == 0
        assert receipt.leased_until is None
        assert receipt.next_attempt_at is None
        evidence = db.scalars(
            select(PlatformAuditEvent).where(
                PlatformAuditEvent.action == shadow_evidence.SHADOW_EVIDENCE_ACTION,
                PlatformAuditEvent.entity_id == str(receipt_id),
            )
        ).one()
        assert evidence.actor_admin_id is None
        assert evidence.details == {
            "comparison_revision": REVISION,
            "verdict": "agrees",
            "blocking_reasons": [],
            "disagreeing_fields": [],
        }

    assert receipt_id not in delivery.due_shadow_receipt_ids(
        engine,
        10,
        comparison_revision=REVISION,
        retry_after_seconds=300,
    )
    assert receipt_id in delivery.due_shadow_receipt_ids(
        engine,
        10,
        comparison_revision="image-sha256:shadow-composition-v2",
        retry_after_seconds=300,
    )

    report = shadow_evidence.shadow_report(engine, REVISION)
    assert report.unique_receipts == 1
    assert report.sample_has_no_blockers is True
    assert str(receipt_id) not in repr(report.as_dict())
    engine.dispose()


def test_a_transient_verdict_reenters_only_after_the_sampling_interval(
    migrated: str,
) -> None:
    app = create_app(
        build_settings(database_url=migrated, product_port_shadow_revision=REVISION)
    )
    app.state.engine.dispose()
    receipt_id = _receipt(migrated, suffix="transient")
    engine = create_engine(migrated)
    shadow_evidence.record_shadow_observation(
        engine,
        receipt_id=receipt_id,
        comparison_revision=REVISION,
        verdict=shadow_evidence.SafeShadowVerdict(
            verdict="no_counterpart",
            blocking_reasons=("no_counterpart_observation",),
            disagreeing_fields=(),
        ),
    )

    assert receipt_id not in delivery.due_shadow_receipt_ids(
        engine,
        10,
        comparison_revision=REVISION,
        retry_after_seconds=3600,
        now=datetime.now(UTC),
    )
    assert receipt_id in delivery.due_shadow_receipt_ids(
        engine,
        10,
        comparison_revision=REVISION,
        retry_after_seconds=3600,
        now=datetime.now(UTC) + timedelta(hours=2),
    )
    engine.dispose()
