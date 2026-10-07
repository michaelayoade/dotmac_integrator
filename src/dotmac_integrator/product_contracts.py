"""Authenticated product-owned capability declarations for synchronous work."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from typing import Any, Final
from urllib.parse import urlsplit

import dotmac_integration as integration

from dotmac_integrator.product_port import HttpAnswer, Transport, UrllibTransport
from dotmac_integrator.secret_resolver import resolve_secrets

SCHEMA_VERSION: Final = "dotmac.io/integration-query-capability-registry/v1"
SECRET_NAME: Final = "api_key"
_FIELDS: Final = frozenset(
    {
        "schema_version",
        "application",
        "source_revision",
        "contracts",
        "descriptor_digest",
    }
)
_CONTRACT_FIELDS: Final = frozenset(
    {
        "owner_module",
        "capability_id",
        "capability_summary",
        "contract_version",
        "capability_contract",
    }
)


class ProductContractRegistryError(ValueError):
    """An authenticated product declaration cannot be trusted."""


def descriptor_digest(document: Mapping[str, object]) -> str:
    """Canonical digest of every published fact except the digest itself."""
    material = {
        key: value for key, value in document.items() if key != "descriptor_digest"
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class ProductContractRegistryReconciler:
    """Fetch one exact-pinned product registry and parse it through a18."""

    def __init__(
        self,
        *,
        descriptor_url: str,
        expected_digest: str,
        api_key_ref: str,
        timeout_seconds: float,
        transport: Transport | None = None,
    ) -> None:
        parsed = urlsplit(descriptor_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ProductContractRegistryError(
                "PRODUCT_CONTRACT_REGISTRY_URL must be an http(s) URL without "
                "credentials, query, or fragment"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
            raise ProductContractRegistryError(
                "PRODUCT_CONTRACT_REGISTRY_EXPECTED_DIGEST must be 64 lowercase hex"
            )
        self._url = descriptor_url
        self._expected_digest = expected_digest
        self._api_key_ref = api_key_ref
        self._timeout = timeout_seconds
        self._transport: Transport = transport or UrllibTransport()

    def reconcile(self) -> integration.CapabilityRegistry:
        key = resolve_secrets({SECRET_NAME: self._api_key_ref})[SECRET_NAME]
        try:
            answer: HttpAnswer = self._transport.get(
                self._url,
                headers={"Accept": "application/json", "X-Api-Key": key},
                timeout=self._timeout,
            )
        finally:
            del key
        if answer.status != 200:
            raise ProductContractRegistryError(
                f"the product capability registry endpoint answered {answer.status}"
            )
        try:
            document: Any = json.loads(answer.body)
        except ValueError as exc:
            raise ProductContractRegistryError(
                "the product capability registry endpoint did not return JSON"
            ) from exc
        return self._parse(document)

    def _parse(self, document: object) -> integration.CapabilityRegistry:
        if not isinstance(document, dict) or set(document) != _FIELDS:
            raise ProductContractRegistryError(
                "the product capability registry does not have the exact field set"
            )
        application = document["application"]
        source_revision = document["source_revision"]
        claimed_digest = document["descriptor_digest"]
        if (
            document["schema_version"] != SCHEMA_VERSION
            or not isinstance(application, str)
            or not re.fullmatch(r"[a-z0-9_.-]+", application)
            or not isinstance(source_revision, str)
            or not re.fullmatch(r"[0-9a-f]{64}", source_revision)
            or not isinstance(claimed_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", claimed_digest)
        ):
            raise ProductContractRegistryError(
                "the product capability registry contains an invalid typed field"
            )
        computed = descriptor_digest(document)
        if not hmac.compare_digest(claimed_digest, computed):
            raise ProductContractRegistryError(
                "the product capability registry digest does not cover its "
                "published facts"
            )
        if not hmac.compare_digest(computed, self._expected_digest):
            raise ProductContractRegistryError(
                "the product capability registry differs from the operator-approved pin"
            )
        rows = document["contracts"]
        if not isinstance(rows, list) or len(rows) != 4:
            raise ProductContractRegistryError(
                "the product capability registry must contain exactly four contracts"
            )
        contracts: list[integration.CapabilityContract] = []
        identifiers: list[str] = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != _CONTRACT_FIELDS:
                raise ProductContractRegistryError(
                    "a product capability contract does not have the exact field set"
                )
            owner = row["owner_module"]
            capability_id = row["capability_id"]
            summary = row["capability_summary"]
            version = row["contract_version"]
            contract_document = row["capability_contract"]
            if (
                not isinstance(owner, str)
                or not owner
                or not isinstance(capability_id, str)
                or not capability_id
                or not isinstance(summary, str)
                or not summary
                or not isinstance(version, int)
                or isinstance(version, bool)
                or version < 1
                or not isinstance(contract_document, Mapping)
            ):
                raise ProductContractRegistryError(
                    "a product capability contract contains an invalid typed field"
                )
            identifiers.append(capability_id)
            try:
                contract = integration.capability_contract_from_document(
                    contract_document,
                    capability_id=capability_id,
                    application=application,
                    owner_module=owner,
                    summary=summary,
                )
            except (TypeError, ValueError, KeyError) as exc:
                raise ProductContractRegistryError(
                    "a product capability contract is invalid"
                ) from exc
            version_match = re.search(r"\.v([1-9][0-9]*)$", capability_id)
            if version_match is None or version != int(version_match.group(1)):
                raise ProductContractRegistryError(
                    "a product capability contract version disagrees with its "
                    "declaration"
                )
            contracts.append(contract)
        if identifiers != sorted(identifiers) or len(set(identifiers)) != len(
            identifiers
        ):
            raise ProductContractRegistryError(
                "product capability contracts must have unique capability ids "
                "in sorted order"
            )
        return integration.CapabilityRegistry.from_declarations(contracts)


def build_from_settings(
    settings: Any, *, held_references: tuple[str, ...]
) -> integration.CapabilityRegistry:
    """Build the exact-pinned registry after its credential has been held."""
    reference = settings.product_contract_registry_api_key_ref.strip()
    if reference not in held_references:
        raise ProductContractRegistryError(
            f"no material is held for {reference}, the product registry credential"
        )
    return ProductContractRegistryReconciler(
        descriptor_url=settings.product_contract_registry_url.strip(),
        expected_digest=settings.product_contract_registry_expected_digest.strip(),
        api_key_ref=reference,
        timeout_seconds=settings.product_contract_registry_timeout_seconds,
    ).reconcile()
