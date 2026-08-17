"""Revisioned mirror evidence against the actually migrated PostgreSQL stack."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import dotmac_integration as integration
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from dotmac_integrator import delivery, operations

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


def _record(
    migrated: str, receipt_id: UUID, verdict: integration.SafeShadowVerdict
) -> None:
    engine = create_engine(migrated)
    with Session(engine) as db:
        integration.record_shadow_observation(
            db,
            receipt_id=receipt_id,
            comparison_revision=REVISION,
            verdict=verdict,
        )
        db.commit()
    engine.dispose()


def test_terminal_shadow_evidence_is_append_only_and_never_settles_a_receipt(
    migrated: str,
) -> None:
    receipt_id = _receipt(migrated, suffix="terminal")
    engine = create_engine(migrated)

    assert receipt_id in delivery.due_shadow_receipt_ids(
        engine,
        10,
        comparison_revision=REVISION,
        retry_after_seconds=300,
    )

    _record(
        migrated,
        receipt_id,
        integration.SafeShadowVerdict(
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
            select(integration.ShadowComparisonEvidence).where(
                integration.ShadowComparisonEvidence.receipt_id == receipt_id,
                integration.ShadowComparisonEvidence.comparison_revision == REVISION,
            )
        ).one()
        assert evidence.verdict == "agrees"
        assert evidence.blocking_reasons == []
        assert evidence.disagreeing_fields == []

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

    report = operations.shadow_report(engine, REVISION)
    assert report["unique_receipts"] == 1
    assert report["sample_has_no_blockers"] is True
    assert str(receipt_id) not in repr(report)
    engine.dispose()


def test_a_transient_verdict_reenters_only_after_the_sampling_interval(
    migrated: str,
) -> None:
    receipt_id = _receipt(migrated, suffix="transient")
    _record(
        migrated,
        receipt_id,
        integration.SafeShadowVerdict(
            verdict="no_counterpart",
            blocking_reasons=("no_counterpart_observation",),
            disagreeing_fields=(),
        ),
    )
    engine = create_engine(migrated)

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
