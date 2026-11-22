"""Requeue ONE ambiguous outbound delivery, only with an explicit acknowledgement.

    python -m dotmac_integrator.requeue_ambiguous \\
        --delivery-id <uuid> --operator-email <email> --reason "<why>" \\
        --accept-possible-duplicate

An ambiguous delivery (`reconciliation_required`) may already have reached the
provider. Putting it back on the queue can therefore send the same message
twice. Without `--accept-possible-duplicate` this prints the delivery's state
and changes NOTHING (exit 2): that is the dry run. With it, the module's own
`replay_delivery` returns the row to the queue and an `integrator.*` audit row
records the operator and the reason.

Runs with the ONLINE `DATABASE_URL` read from the environment, like the API; it
needs no owner credential. Only a state of `reconciliation_required` is
accepted: anything else belongs to the normal replay route or is not repairable.
"""

from __future__ import annotations

import argparse
import sys
from uuid import UUID

import dotmac_integration as integration
from dotmac_kernel.audit import write_platform_audit_event
from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
from dotmac_kernel.models_platform import PlatformAdmin
from dotmac_kernel.modules import ModuleRegistry
from sqlalchemy import select
from sqlalchemy.orm import Session

from dotmac_integrator.assembly import build_engine
from dotmac_integrator.manifest import module as assembly_module
from dotmac_integrator.settings import get_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="requeue_ambiguous")
    parser.add_argument("--delivery-id", required=True)
    parser.add_argument("--operator-email", required=True)
    parser.add_argument("--reason", required=True)
    # BooleanOptionalAction rather than `action="store_true"`: the audit-vocabulary
    # scan reads every `action=` string literal in this package.
    parser.add_argument(
        "--accept-possible-duplicate",
        action=argparse.BooleanOptionalAction,
        default=False,
    )
    args = parser.parse_args(argv)

    reason = args.reason.strip()
    if not reason:
        print("refused: a reason is required")
        return 2
    try:
        delivery_id = UUID(args.delivery_id)
    except ValueError:
        print("refused: --delivery-id is not a UUID")
        return 2

    manifests = ModuleRegistry((integration.module, assembly_module)).startup_order()
    install_audit_actions(AuditActionRegistry.from_manifests(manifests))
    engine = build_engine(get_settings())
    try:
        with Session(engine) as db:
            admin = db.execute(
                select(PlatformAdmin).where(
                    PlatformAdmin.email == args.operator_email,
                    PlatformAdmin.is_active.is_(True),
                )
            ).scalar_one_or_none()
            if admin is None:
                print("refused: no active operator with that email")
                return 2
            delivery = db.get(integration.DeliveryAttempt, delivery_id)
            if delivery is None:
                print("refused: no such delivery")
                return 2
            if delivery.state != "reconciliation_required":
                print(f"refused: delivery is {delivery.state!r}, not ambiguous")
                return 2
            if not args.accept_possible_duplicate:
                print(
                    "dry run: delivery is ambiguous (it may already have been "
                    "sent). Nothing changed. Re-run with "
                    "--accept-possible-duplicate to requeue it."
                )
                return 2
            integration.replay_delivery(
                db, delivery, actor_admin_id=admin.id, reason=reason
            )
            write_platform_audit_event(
                db,
                actor_admin_id=admin.id,
                action="integrator.delivery.requeued_after_ambiguity",
                entity_type="delivery_attempt",
                entity_id=str(delivery.id),
                details={"reason": reason, "accepted_possible_duplicate": True},
            )
            db.commit()
    finally:
        engine.dispose()
    print("requeued; possible duplicate acknowledged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
