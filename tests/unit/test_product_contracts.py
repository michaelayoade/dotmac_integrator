from __future__ import annotations

import copy
import json

import dotmac_integration as integration
import pytest

from dotmac_integrator import product_contracts
from dotmac_integrator.product_port import HttpAnswer


class RecordingTransport:
    def __init__(self, document: dict[str, object]) -> None:
        self.document = document
        self.headers: dict[str, str] = {}

    def get(self, url: str, *, headers: dict[str, str], timeout: float) -> HttpAnswer:
        assert url == "https://erp.example/internal/query-contracts"
        assert timeout == 3.0
        self.headers = headers
        return HttpAnswer(status=200, body=json.dumps(self.document).encode())


def _schema(required: str) -> dict[str, object]:
    return {
        "type": "object",
        "properties": {required: {"type": "string"}},
        "required": [required],
        "additionalProperties": False,
    }


def _document() -> dict[str, object]:
    rows: list[dict[str, object]] = []
    for capability_id in (
        "fleet.tracking.device.read.v1",
        "fleet.tracking.position.history.v1",
        "fleet.tracking.position.latest.v1",
        "integration.provider.health.v1",
    ):
        contract = integration.CapabilityContract(
            capability_id=capability_id,
            owner=integration.CapabilityOwner(application="dotmac_erp", module="fleet"),
            summary=f"ERP-owned {capability_id}",
            command_schema=_schema("provider_device_ref"),
            observation_schema=_schema("status"),
        )
        rows.append(
            {
                "owner_module": "fleet",
                "capability_id": capability_id,
                "capability_summary": contract.summary,
                "contract_version": 1,
                "capability_contract": integration.capability_contract_document(
                    contract
                ),
            }
        )
    document: dict[str, object] = {
        "schema_version": product_contracts.SCHEMA_VERSION,
        "application": "dotmac_erp",
        "source_revision": "a" * 64,
        "contracts": rows,
    }
    document["descriptor_digest"] = product_contracts.descriptor_digest(document)
    return document


def _reconciler(
    document: dict[str, object],
) -> product_contracts.ProductContractRegistryReconciler:
    return product_contracts.ProductContractRegistryReconciler(
        descriptor_url="https://erp.example/internal/query-contracts",
        expected_digest=str(document["descriptor_digest"]),
        api_key_ref="file:///run/secrets/product-contracts/erp",
        timeout_seconds=3.0,
        transport=RecordingTransport(document),
    )


def test_authenticated_exact_pinned_bundle_builds_four_contracts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _document()
    transport = RecordingTransport(document)
    monkeypatch.setattr(
        product_contracts,
        "resolve_secrets",
        lambda refs: {product_contracts.SECRET_NAME: "held-machine-key"},
    )
    reconciler = product_contracts.ProductContractRegistryReconciler(
        descriptor_url="https://erp.example/internal/query-contracts",
        expected_digest=str(document["descriptor_digest"]),
        api_key_ref="file:///run/secrets/product-contracts/erp",
        timeout_seconds=3.0,
        transport=transport,
    )

    registry = reconciler.reconcile()

    assert registry.declared_ids == {
        "fleet.tracking.device.read.v1",
        "fleet.tracking.position.history.v1",
        "fleet.tracking.position.latest.v1",
        "integration.provider.health.v1",
    }
    assert transport.headers == {
        "Accept": "application/json",
        "X-Api-Key": "held-machine-key",
    }


@pytest.mark.parametrize("mutation", ["extra", "reorder", "version", "count"])
def test_bundle_refuses_shape_order_version_and_count_drift(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    document = copy.deepcopy(_document())
    rows = document["contracts"]
    assert isinstance(rows, list)
    if mutation == "extra":
        document["provider"] = "traccar"
    elif mutation == "reorder":
        rows.reverse()
    elif mutation == "version":
        assert isinstance(rows[0], dict)
        rows[0]["contract_version"] = 2
    else:
        rows.pop()
    document["descriptor_digest"] = product_contracts.descriptor_digest(document)
    monkeypatch.setattr(
        product_contracts,
        "resolve_secrets",
        lambda refs: {product_contracts.SECRET_NAME: "held-machine-key"},
    )

    with pytest.raises(product_contracts.ProductContractRegistryError):
        _reconciler(document).reconcile()


def test_operator_pin_is_independent_of_published_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _document()
    monkeypatch.setattr(
        product_contracts,
        "resolve_secrets",
        lambda refs: {product_contracts.SECRET_NAME: "held-machine-key"},
    )
    reconciler = product_contracts.ProductContractRegistryReconciler(
        descriptor_url="https://erp.example/internal/query-contracts",
        expected_digest="f" * 64,
        api_key_ref="file:///run/secrets/product-contracts/erp",
        timeout_seconds=3.0,
        transport=RecordingTransport(document),
    )

    with pytest.raises(
        product_contracts.ProductContractRegistryError, match="operator"
    ):
        reconciler.reconcile()
