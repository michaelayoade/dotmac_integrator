"""The module's conditional receipt claim against this real composition.

The fast pump tests prove call ordering. This proves the database decision they
drive: two online-role sessions may select the same candidate, but exactly one
conditional UPDATE wins and increments the attempt. It deliberately uses the
assembly's migrated PostgreSQL schema because the statement contains
``make_interval`` and SQLite cannot be evidence for it.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier
from uuid import UUID, uuid4

import dotmac_integration as integration
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

CAPABILITY_ID = "messaging.receive.v1"


def _registry() -> integration.CapabilityRegistry:
    return integration.CapabilityRegistry.from_declarations(
        (
            integration.CapabilityContract(
                capability_id=CAPABILITY_ID,
                owner=integration.CapabilityOwner(
                    application="sub",
                    module="team_inbox",
                ),
                summary="Record one verified inbound messaging observation.",
            ),
        )
    )


def _receipt(migrated: str) -> UUID:
    engine = create_engine(migrated)
    registry = _registry()
    with Session(engine) as db:
        installation = integration.ConnectorInstallation(
            connector_key="test.connector",
            connector_version="0.0.1",
            spi_range=">=1.0,<2.0",
            manifest_digest="0" * 64,
            name=f"claim-race-{uuid4().hex[:8]}",
            environment="test",
            state="enabled",
        )
        db.add(installation)
        db.flush()
        binding = integration.CapabilityBinding(
            installation_id=installation.id,
            capability_id=CAPABILITY_ID,
            state="enabled",
            scope_json={"kind": "inbox", "ref": "support"},
        )
        db.add(binding)
        db.flush()
        integration.establish_destination(
            db,
            capability_binding_id=binding.id,
            scope=integration.LocalScope(kind="inbox", ref="support"),
            registry=registry,
            established_by="test:receipt-claim-race",
            reason="prove the composed conditional claim",
        )
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


def test_two_online_workers_produce_one_claim_and_one_normal_loser(
    migrated: str,
) -> None:
    receipt_id = _receipt(migrated)
    engine = create_engine(migrated, pool_size=2, max_overflow=0)
    registry = _registry()
    ready = Barrier(2)
    now = datetime(2026, 8, 17, 5, 0, tzinfo=UTC)

    def online_session() -> Session:
        session = Session(engine)
        session.execute(text("SET LOCAL ROLE platform_api"))
        return session

    def claim() -> integration.ReceiptClaim | None:
        store = integration.ReceiptClaims(online_session, registry=registry)
        ready.wait(timeout=10)
        return store.claim(receipt_id=receipt_id, now=now)

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = (workers.submit(claim), workers.submit(claim))
        claims = tuple(future.result(timeout=20) for future in futures)

    winners = tuple(item for item in claims if item is not None)
    assert len(winners) == 1
    assert winners[0].receipt_id == receipt_id
    assert winners[0].attempt == 1

    with Session(engine) as db:
        row = db.scalars(
            select(integration.InboxReceipt).where(
                integration.InboxReceipt.id == receipt_id
            )
        ).one()
        assert row.state == "processing"
        assert row.attempt_count == 1
        assert row.destination_application == "sub"
        assert row.destination_contract_version == 1
        assert row.leased_until is not None
    engine.dispose()
