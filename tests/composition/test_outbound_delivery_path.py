"""One real command traverses the composed outbox and delivery engine.

The route/authentication and three-phase ordering have focused unit canaries.
This proof supplies what mocks cannot: the released module migrations create a
usable outbox, enqueue deduplicates in PostgreSQL, the assembly's due selector
finds the row, and settle persists typed provider evidence.
"""

from __future__ import annotations

from uuid import uuid4

import dotmac_integration as integration
from dotmac_integration.conformance import (
    fake_manifest,
    fake_plugin,
    fake_registry,
)
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from dotmac_integrator import command_port, outbound

CAPABILITY_ID = "conformance.delivery.v1"


def test_a_product_command_is_deduplicated_dispatched_and_settled(
    migrated: str,
) -> None:
    engine = create_engine(migrated)
    manifest = fake_manifest(capabilities=(CAPABILITY_ID,))
    plugin = fake_plugin(
        manifest_=manifest,
        outcome=integration.Outcome(
            status=integration.OutcomeStatus.SUCCEEDED,
            provider_reference="remote-object-1",
            provider_status_code=202,
        ),
    )
    registry = fake_registry(plugins=(plugin,))
    idempotency_key = f"source:message:{uuid4()}"
    payload: dict[str, object] = {
        "recipient": "opaque-recipient-1",
        "text": "hello",
    }

    try:
        with Session(engine) as db:
            installation = integration.ConnectorInstallation(
                connector_key=manifest.connector_key,
                connector_version=manifest.version,
                spi_range=str(manifest.spi_range),
                manifest_digest=manifest.digest,
                name=f"outbound-live-{uuid4().hex[:8]}",
                environment="test",
                state="enabled",
            )
            db.add(installation)
            db.flush()
            binding = integration.CapabilityBinding(
                installation_id=installation.id,
                capability_id=CAPABILITY_ID,
                state="enabled",
                policy_json={"default": True},
            )
            db.add(binding)
            db.commit()

        first = command_port.enqueue(
            engine,
            capability_id=CAPABILITY_ID,
            event_type="send_text",
            idempotency_key=idempotency_key,
            payload=payload,
        )
        replay = command_port.enqueue(
            engine,
            capability_id=CAPABILITY_ID,
            event_type="send_text",
            idempotency_key=idempotency_key,
            payload=payload,
        )

        assert first["is_new"] is True
        assert replay["is_new"] is False
        assert replay["delivery_id"] == first["delivery_id"]

        report = outbound.dispatch_due_deliveries(
            engine,
            limit=10,
            registry=registry,
            resolve_secrets=lambda _refs: {},
        )
        assert report == {
            "candidates": 1,
            "settled": 1,
            "contended": 0,
            "missing": 0,
            "lost": 0,
            "unavailable": 0,
        }
        assert len(plugin.seen) == 1
        assert plugin.seen[0].payload == payload
        assert plugin.seen[0].idempotency_key == idempotency_key

        with Session(engine) as db:
            rows = db.scalars(
                select(integration.DeliveryAttempt).where(
                    integration.DeliveryAttempt.idempotency_key == idempotency_key
                )
            ).all()
            assert len(rows) == 1
            delivery = rows[0]
            assert delivery.state == "delivered"
            assert delivery.attempt_count == 1
            assert delivery.provider_reference == "remote-object-1"
            assert delivery.provider_status_code == 202
            assert delivery.payload_json == payload
            assert delivery.delivered_at is not None
    finally:
        engine.dispose()
