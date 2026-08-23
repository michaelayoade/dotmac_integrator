"""One recorded `dotmac_sub` descriptor, and the digest Sub computed for it.

`ProductPortDescriptorReconciler._read` already recomputes the digest and
refuses a descriptor whose published facts it does not cover. That check is
real, but it only ever runs against a LIVE Sub: every other test in this
repository builds a synthetic document and computes the expected digest with
the same function under test, which proves self-consistency and nothing about
the product.

So a canonicalisation drift — a reordered key, a changed separator, a field
added on one side — would pass CI here and fail at reconcile time against a
deployed Sub, reported as "the product descriptor digest does not cover its
published facts". That message accuses the product of publishing a wrong digest
when the truth may be that this repository changed how it canonicalises.

The fixture below is the missing half: a document in Sub's exact published
shape with the digest Sub's own algorithm produces for it. If either side
changes canonicalisation, this fails in CI, in the repository that changed.

PROVENANCE — transcribed from `dotmac_sub` `origin/dev` `379a6ea68`:

* `app/services/integrations/product_port_descriptor.py` — the `published`
  dict, its field order-independent digest (`json.dumps(sort_keys=True,
  separators=(",", ":"), default=str)` then SHA-256), and the constants
  `DESCRIPTOR_SCHEMA_VERSION`, `APPLICATION`, `OWNER_MODULE`,
  `CAPABILITY_SUMMARY`, `CONTRACT_VERSION`, `DESTINATION_SCOPE`.
* `app/services/integrations/connectors/integrator_http.py` —
  `INTEGRATOR_RECEIVE_CAPABILITY = "messaging.receive.v1"`.

The ids and timestamps are fixed rather than generated: a golden digest is only
golden if the document that produced it cannot vary between runs.
"""

from __future__ import annotations

from uuid import UUID

import pytest
from dotmac_integration import (
    LocalScope,
    ProductPortDescriptorSnapshot,
    product_port_descriptor_digest,
)

#: The binding id the recorded descriptor names.
RECORDED_BINDING = UUID("6f1f2a1e-6b8a-4f3f-9a7c-1c2d3e4f5a6b")

_DELIVERY_PATH = f"/api/v1/integration/observations/{RECORDED_BINDING}"

#: Sub's `source_revision` for the recorded binding — itself a digest, over the
#: binding and installation state that decided `activation_state`.
RECORDED_SOURCE_REVISION = (
    "989d1f0b6de3bedab73db87aa8b2ae5f85f9bd90ad2a4587cfe821d41f53bbc0"
)

#: What Sub's `descriptor_digest(published)` returns for the descriptor below.
#: Recorded, not computed here — computing it with the function under test is
#: exactly the tautology this file exists to avoid.
RECORDED_SUB_DESCRIPTOR_DIGEST = (
    "e16e062bf4fa3de5aa8068b8b55158dfb26fb23bb78fdafd48c9f683e4e924da"
)


def _recorded_descriptor(**overrides: object) -> ProductPortDescriptorSnapshot:
    fields: dict[str, object] = {
        "schema_version": "dotmac.io/product-port-descriptor/v1",
        "application": "sub",
        "owner_module": "communications.team_inbox_integrator_envelope",
        "capability_id": "messaging.receive.v1",
        "capability_summary": (
            "Inbound provider message and delivery-state observations"
        ),
        "contract_version": 1,
        "destination_binding_id": RECORDED_BINDING,
        "delivery_path": _DELIVERY_PATH,
        "mirror_path": f"{_DELIVERY_PATH}/mirror",
        "destination_scope": LocalScope(kind="inbox", ref="support"),
        "activation_state": "configured_disabled",
        "source_revision": RECORDED_SOURCE_REVISION,
        "descriptor_digest": RECORDED_SUB_DESCRIPTOR_DIGEST,
    }
    fields.update(overrides)
    return ProductPortDescriptorSnapshot(**fields)  # type: ignore[arg-type]


def test_this_repositorys_digest_equals_the_one_sub_published() -> None:
    """The parity that `_read` assumes, proven without a running Sub."""

    descriptor = _recorded_descriptor()

    assert product_port_descriptor_digest(descriptor) == RECORDED_SUB_DESCRIPTOR_DIGEST


def test_the_recorded_descriptor_is_the_pre_activation_one() -> None:
    """Gate 2b reconciles a `configured_disabled` port; that is the shape to pin.

    Recording an `enabled` descriptor would make the fixture describe a state
    the cutover has not reached, and quietly move the parity proof off the only
    activation state mirror mode actually reads.
    """

    assert _recorded_descriptor().activation_state == "configured_disabled"


@pytest.mark.parametrize(
    "field, value",
    [
        ("application", "erp"),
        ("owner_module", "communications.something_else"),
        ("capability_id", "messaging.receive.v2"),
        ("capability_summary", "Something else entirely"),
        ("contract_version", 2),
        ("delivery_path", "/api/v1/integration/observations/elsewhere"),
        ("mirror_path", "/api/v1/integration/observations/elsewhere/mirror"),
        ("activation_state", "enabled"),
        ("source_revision", "f" * 64),
        ("schema_version", "dotmac.io/product-port-descriptor/v2"),
    ],
)
def test_every_covered_field_moves_the_digest(field: str, value: object) -> None:
    """Sensitivity: a golden digest that ignores a field is not covering it.

    Without this, the parity test above would still pass if the digest silently
    stopped including, say, `activation_state` — and a descriptor could then flip
    to `enabled` without changing its digest, which is precisely the drift the
    operator-approved pin exists to catch.
    """

    changed = _recorded_descriptor(**{field: value})

    assert product_port_descriptor_digest(changed) != RECORDED_SUB_DESCRIPTOR_DIGEST


def test_the_destination_scope_is_covered_too() -> None:
    """`destination_scope` is nested, so it needs its own sensitivity case."""

    changed = _recorded_descriptor(
        destination_scope=LocalScope(kind="queue", ref="fiber")
    )

    assert product_port_descriptor_digest(changed) != RECORDED_SUB_DESCRIPTOR_DIGEST


def test_the_published_digest_field_is_not_part_of_the_material() -> None:
    """A digest cannot cover itself; changing it must not change the result.

    This is what makes `_read`'s first comparison meaningful: it holds Sub's
    claim beside a value computed from everything EXCEPT that claim.
    """

    changed = _recorded_descriptor(descriptor_digest="0" * 64)

    assert product_port_descriptor_digest(changed) == RECORDED_SUB_DESCRIPTOR_DIGEST
