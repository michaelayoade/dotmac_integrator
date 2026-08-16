"""Receipt → product delivery: the pump, and the port the deployment supplies.

Recording that a provider event arrived is not delivering it. Without this the
control plane can acknowledge a customer's message to the provider and then
land it nowhere — the acknowledgement is a promise the inbox alone cannot keep.

`dotmac_integration.receipt_delivery` owns the whole mechanism: `ReceiptClaims`
is a conditional UPDATE where ``rowcount == 1`` IS the claim, and
`deliver_receipt` sequences claim → call → settle with no session held across
the network. **Neither is reimplemented here, and that is the point of this
file being short.** What this assembly adds is a loop, a candidate query, and
the two collaborators the module correctly refuses to construct: a session
factory and a client that speaks the product's protocol.

## The selector is a HINT; the claim is the decision

:func:`due_receipt_ids` is a plain SELECT with no locking, and two workers will
routinely be handed the same id. That is fine and it is the design: the
conditional UPDATE inside `ReceiptClaims.claim` evaluates the real predicate —
not terminal, not held by a live lease, and due — inside the database, so the
loser sees zero rows and gets `None`. A selector that tried to be authoritative
would be a SECOND opinion about claimability, and the two would drift; worse, it
would tempt someone to add `FOR UPDATE SKIP LOCKED` and hold that lock across
the product call, which is exactly the transaction-around-the-network the
module's three phases exist to prevent.

So the selector is deliberately loose and deliberately cheap, and
`DeliveryReport.claimed is False` is a NORMAL outcome rather than an error.

## No product client ships here

`ProductPortClient` is a PORT, and this deployment installs one at startup the
same way it installs secret material (ADR-0009): once, in memory, never fetched
while handling anything. With none installed the pump does not run and says so
in a log line — it does not fall back to "deliver nowhere and mark it done",
which would be the inbox lying at a different layer.

The client itself belongs with the checked-in contract of the application it
speaks to, not here: authoring it in the transport would make this assembly the
sole author of a wire contract two systems must agree on (ADR-0024).
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

import dotmac_integration as integration
import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from dotmac_integrator import telemetry

logger = logging.getLogger(__name__)

__all__ = [
    "ProductPortNotInstalled",
    "deliver_due_receipts",
    "due_receipt_ids",
    "install_product_port",
    "product_port",
    "product_port_installed",
]


class ProductPortNotInstalled(RuntimeError):
    """No client was installed for the application receipts land in.

    Raised rather than treated as "nothing to do". A deployment that receives
    provider events and delivers them nowhere is not idle — it is silently
    accumulating a backlog behind a control plane that answered 200 to the
    provider, and the provider will not send those events again.
    """


#: Installed ONCE, at startup, and held. The same shape as `install_secrets`
#: and for the same reason (ADR-0009): a delivery must not be delayed or failed
#: by a lookup, and a client constructed per call would rebuild a connection
#: pool for every receipt.
_PORT: Any | None = None
_REGISTRY: Any | None = None


def install_product_port(client: Any, *, registry: Any) -> None:
    """Install the client and the capability registry this deployment routes by.

    Both, together, because they are useless apart: `ReceiptClaims.claim`
    resolves the destination through the registry inside the claim transaction,
    and the client is what that destination is then contacted with. Installing
    one without the other yields a pump that claims receipts it cannot deliver
    and burns an attempt on each.
    """
    global _PORT, _REGISTRY
    # Checked by SHAPE. `ProductPortClient` is a plain `Protocol` and not
    # `runtime_checkable`, so `isinstance` is unavailable — and checking here
    # rather than trusting the annotation is what turns "the port was wired up
    # wrong" from an `AttributeError` on the first real receipt, mid-claim and
    # after an attempt has been burned, into a refusal at startup.
    if not callable(getattr(client, "deliver", None)):
        raise ProductPortNotInstalled(
            "the installed product port does not satisfy "
            "`dotmac_integration.ProductPortClient`: it has no callable "
            "`deliver(request) -> ProductOutcome`"
        )
    integration.install_capability_registry(registry)
    _PORT = client
    _REGISTRY = registry


def product_port_installed() -> bool:
    return _PORT is not None and _REGISTRY is not None


def product_port() -> tuple[Any, Any]:
    if _PORT is None or _REGISTRY is None:
        raise ProductPortNotInstalled(
            "no product port is installed; call install_product_port(...) at "
            "startup with a client for the application these receipts land in"
        )
    return _PORT, _REGISTRY


#: States a receipt can still be delivered from. `retryable` is present and
#: `processing` is absent: a receipt already held by a live lease is not a
#: candidate, and one whose lease expired is recovered by the LEASE predicate
#: in the claim rather than by a state check here.
_DELIVERABLE_STATES = ("verified", "retryable")


def due_receipt_ids(engine: Engine, limit: int) -> tuple[UUID, ...]:
    """Receipts that MIGHT be claimable. A hint, never an answer.

    No locking, no `SKIP LOCKED`, no `FOR UPDATE`. Two workers seeing the same
    id is the expected case and costs one losing conditional UPDATE — cheaper
    than a lock held while the product is contacted, which is what the
    alternative quietly becomes.

    Ordered oldest-first so a backlog drains in arrival order rather than
    starving whatever has been waiting longest.
    """
    receipt = integration.InboxReceipt
    now = sa.func.now()
    with Session(engine) as db:
        rows = db.execute(
            sa.select(receipt.id)
            .where(
                receipt.state.in_(_DELIVERABLE_STATES),
                sa.or_(receipt.leased_until.is_(None), receipt.leased_until < now),
                sa.or_(
                    receipt.next_attempt_at.is_(None), receipt.next_attempt_at <= now
                ),
            )
            .order_by(receipt.received_at)
            .limit(limit)
        ).all()
    return tuple(row[0] for row in rows)


def deliver_due_receipts(engine: Engine, limit: int) -> dict[str, int]:
    """One pass. Claim, call, settle — per receipt, through the module.

    Each receipt is delivered independently: one product refusal must not stop
    the batch, because the receipts behind it are unrelated observations and the
    module has already decided what a refusal means (`retry.next_state`).

    `LostClaim` is caught HERE and counted rather than allowed to kill the pump.
    It means this worker's lease expired mid-call and another worker legitimately
    took the receipt over, so the correct action is to move on — but it is
    counted because a rising rate means the lease is shorter than the product's
    real latency, which is invisible otherwise and eventually duplicates work.
    """
    gateway, registry = product_port()
    store = integration.ReceiptClaims(
        # A CALLABLE, not a session: the claim and the settle are separate
        # transactions by design, and sharing one session would reduce that to
        # the caller remembering to commit in the right places.
        lambda: Session(engine),
        registry=registry,
    )

    counted = {"claimed": 0, "unclaimed": 0, "lost": 0}
    for receipt_id in due_receipt_ids(engine, limit):
        try:
            report = integration.deliver_receipt(
                receipt_id=receipt_id, store=store, gateway=gateway
            )
        except integration.LostClaim:
            counted["lost"] += 1
            telemetry.counters.record_lost_claim()
            continue
        if not report.claimed:
            # The normal case when several workers sweep one queue, and the
            # reason the selector is allowed to be a hint.
            counted["unclaimed"] += 1
            continue
        counted["claimed"] += 1
        if report.outcome is not None:
            telemetry.counters.record_product_acceptance(
                report.outcome.acceptance.value
            )
    return counted
