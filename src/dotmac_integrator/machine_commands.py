"""Held-key authentication for the machine provisioning command surface.

This is assembly-owned authentication, not provisioning authority.  It proves
who signed a canonical, time-bounded command and signs the transport receipt
returned by this deployment.  Replay/collision and every execution transition
remain in ``dotmac_integration``'s durable command ledger.

Key material enters through :func:`install_crypto_from_held` at startup and on
the explicit secret refresh.  Request guards use only parsed in-memory keys;
this module imports no store, filesystem, network client, ORM or subprocess.
"""

import base64
import binascii
import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Generic, Literal, Self, TypeVar
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import Body, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from dotmac_integrator.secret_resolver import resolve_secrets
from dotmac_integrator.settings import (
    Settings,
    command_public_key_references,
)

__all__ = [
    "ApplyCommand",
    "ApplyCommandEnvelope",
    "ApprovedCommandTemplate",
    "ApprovalGrant",
    "AuthenticatedCommand",
    "CancelCommand",
    "CancelCommandEnvelope",
    "CapabilityOperationPin",
    "CommandIssuerDeploymentInstances",
    "CommandAuthenticationRefused",
    "CommandIssuerAssignment",
    "CommandIssuerAssignments",
    "MachineCommandGuard",
    "ObserveCommand",
    "ObserveCommandEnvelope",
    "PlanCommand",
    "PlanCommandEnvelope",
    "PrerequisiteEvidenceBinding",
    "PrerequisiteReceiptPin",
    "ProvisioningStep",
    "ReceiptPayload",
    "SignedReceipt",
    "body_digest",
    "canonical_body_bytes",
    "canonical_command_bytes",
    "command_template_digest",
    "crypto_material_validators",
    "install_crypto",
    "install_crypto_from_held",
    "refresh_crypto_from_held",
    "require_apply_command",
    "require_cancel_command",
    "require_observe_command",
    "require_plan_command",
    "sign_receipt",
    "validate_crypto_material",
    "verify_apply_command",
    "verify_receipt",
]

CommandDigest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Reference = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,319}$")]
Code = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.:-]{0,158}[a-z0-9]$")]
SchemaReference = Annotated[
    str,
    Field(pattern=r"^schema:[a-z0-9](?:[a-z0-9._/-]{0,218}[a-z0-9])?@v[1-9][0-9]*$"),
]
CommandIdentifier = Annotated[str, Field(min_length=1, max_length=240)]
CapabilityInstanceRef = Annotated[
    str,
    Field(
        min_length=1,
        max_length=200,
        pattern=r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$",
    ),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CommandIssuerDeploymentInstances(_StrictModel):
    """Exact capability instances one issuer may address in one deployment."""

    deployment_ref: Reference
    capability_instance_refs: tuple[CapabilityInstanceRef, ...] = Field(min_length=1)

    @field_validator("capability_instance_refs")
    @classmethod
    def require_canonical_instances(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("issuer capability instance assignments must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("issuer capability instance assignments must be sorted")
        return value


class CommandIssuerAssignment(_StrictModel):
    """One held service identity and its exact deployment/instance pairs."""

    key_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")]
    account_ref: Reference
    deployment_instances: tuple[CommandIssuerDeploymentInstances, ...] = Field(
        min_length=1
    )

    @field_validator("deployment_instances")
    @classmethod
    def require_canonical_deployments(
        cls, value: tuple[CommandIssuerDeploymentInstances, ...]
    ) -> tuple[CommandIssuerDeploymentInstances, ...]:
        deployment_refs = tuple(item.deployment_ref for item in value)
        if len(set(deployment_refs)) != len(deployment_refs):
            raise ValueError("issuer deployment assignments must be unique")
        if deployment_refs != tuple(sorted(deployment_refs)):
            raise ValueError("issuer deployment assignments must be sorted")
        return value


class CommandIssuerAssignments(_StrictModel):
    contract_version: Literal["integrator.command-issuer-assignments.v2"]
    assignments: tuple[CommandIssuerAssignment, ...] = Field(min_length=1)

    @field_validator("assignments")
    @classmethod
    def require_canonical_issuers(
        cls, value: tuple[CommandIssuerAssignment, ...]
    ) -> tuple[CommandIssuerAssignment, ...]:
        key_ids = tuple(item.key_id for item in value)
        if len(set(key_ids)) != len(key_ids):
            raise ValueError("issuer assignment key ids must be unique")
        if key_ids != tuple(sorted(key_ids)):
            raise ValueError("issuer assignments must be sorted by key_id")
        return value


class ProvisioningStep(_StrictModel):
    step_key: Code
    endpoint_code: Code
    depends_on: tuple[str, ...] = ()
    input: dict[str, object] = Field(default_factory=dict)

    @field_validator("input")
    @classmethod
    def require_finite_json_numbers(cls, value: dict[str, object]) -> dict[str, object]:
        _require_finite_numbers(value)
        return value


def _require_finite_numbers(value: object) -> None:
    if isinstance(value, Mapping):
        for nested in value.values():
            _require_finite_numbers(nested)
        return
    if isinstance(value, list | tuple):
        for nested in value:
            _require_finite_numbers(nested)
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("structured input contains a non-finite number")


class CapabilityOperationPin(_StrictModel):
    """Exact a69 owner-operation schema identity approved for this command."""

    operation_code: Code
    input_schema_ref: Reference
    input_schema_digest: CommandDigest
    output_schema_ref: Reference
    output_schema_digest: CommandDigest


class PrerequisiteEvidenceBinding(_StrictModel):
    """Approved value-free mapping from upstream public evidence to step input.

    Both schema identities are a69-held APPLY operation pins.  Concrete values
    never enter the command template: the module resolves them from its locked
    upstream receipt chain immediately before invoking a copied step request.
    """

    source_capability_binding_id: UUID
    source_step_key: Code
    source_schema_ref: SchemaReference
    source_schema_digest: CommandDigest
    source_pointer: Annotated[str, Field(max_length=1024)]
    target_step_key: Code
    target_schema_ref: SchemaReference
    target_schema_digest: CommandDigest
    target_pointer: Annotated[str, Field(max_length=1024)]
    required: Annotated[bool, Field(strict=True)]

    @field_validator("source_pointer", "target_pointer")
    @classmethod
    def require_canonical_json_pointer(cls, value: str) -> str:
        if not value.startswith("/") or re.search(r"~(?![01])", value):
            raise ValueError(
                "evidence locations must be non-root RFC 6901 JSON pointers"
            )
        return value


def _evidence_binding_sort_key(
    binding: PrerequisiteEvidenceBinding,
) -> tuple[str, str, str, str, str]:
    return (
        str(binding.source_capability_binding_id),
        binding.source_step_key,
        binding.source_pointer,
        binding.target_step_key,
        binding.target_pointer,
    )


def _require_canonical_evidence_bindings(
    value: tuple[PrerequisiteEvidenceBinding, ...],
) -> tuple[PrerequisiteEvidenceBinding, ...]:
    keys = tuple(_evidence_binding_sort_key(binding) for binding in value)
    if len(set(keys)) != len(keys):
        raise ValueError("prerequisite evidence bindings must be unique")
    if keys != tuple(sorted(keys)):
        raise ValueError(
            "prerequisite evidence bindings must use canonical evidence-binding order"
        )
    target_locations = tuple(
        (binding.target_step_key, binding.target_pointer) for binding in value
    )
    if len(set(target_locations)) != len(target_locations):
        raise ValueError("evidence-binding target input locations must be unique")
    return value


def _require_canonical_operations(
    value: tuple[CapabilityOperationPin, ...],
) -> tuple[CapabilityOperationPin, ...]:
    operation_codes = tuple(operation.operation_code for operation in value)
    if len(set(operation_codes)) != len(operation_codes):
        raise ValueError("capability operation pins must be unique")
    if operation_codes != tuple(sorted(operation_codes)):
        raise ValueError("capability operation pins must be sorted by operation_code")
    return value


class ApprovalGrant(_StrictModel):
    grant_ref: Reference
    approval_request_id: UUID
    approval_request_binding_hash: CommandDigest
    saved_plan_id: UUID
    approved_plan_hash: CommandDigest
    approved_command_template_digest: CommandDigest
    plan_command_id: CommandIdentifier
    plan_validation_receipt_id: UUID
    plan_validation_receipt_digest: CommandDigest
    plan_validation_request_body_digest: CommandDigest
    module_plan_receipt_hash: CommandDigest
    digest: CommandDigest
    expires_at: datetime
    verified_at: datetime

    @field_validator("expires_at", "verified_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("approval times must include a timezone")
        return value


class PlanCommand(_StrictModel):
    deployment_ref: Reference
    capability_id: Code
    capability_instance_ref: CapabilityInstanceRef
    capability_binding_id: UUID
    plan_hash: CommandDigest
    config_digest: CommandDigest
    steps: tuple[ProvisioningStep, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def require_one_versioned_capability_action(self) -> Self:
        if any(step.endpoint_code != self.capability_id for step in self.steps):
            raise ValueError(
                "every step endpoint_code must equal the versioned capability_id"
            )
        return self


class ApprovedCommandTemplate(_StrictModel):
    """Static approved material; deliberately excludes plan hash and receipts."""

    deployment_ref: Reference
    desired_state_revision: Annotated[int, Field(ge=1)]
    desired_state_version_id: UUID
    desired_state_hash: CommandDigest
    saved_plan_id: UUID
    profile_version_id: UUID
    profile_code: Code
    profile_version: Annotated[int, Field(ge=1)]
    profile_schema_version: Annotated[int, Field(ge=1)]
    profile_content_hash: CommandDigest
    command_schema_version: Literal["integrator.provisioning-command.v1"]
    capability_id: Code
    capability_instance_ref: CapabilityInstanceRef
    capability_owner_code: Code
    capability_code: Code
    capability_schema_version: Annotated[int, Field(ge=1)]
    capability_contract_attestation_id: UUID
    capability_contract_digest: CommandDigest
    capability_operations: tuple[CapabilityOperationPin, ...] = Field(min_length=1)
    capability_binding_id: UUID
    binding_ref: UUID
    installation_id: UUID
    installation_ref: Reference
    connector_key: Code
    connector_version: Reference
    connector_manifest_digest: CommandDigest
    connector_configuration_revision_id: UUID
    configuration_snapshot_ref: Reference
    configuration_schema_version: Annotated[int, Field(ge=1)]
    configuration_hash: CommandDigest
    artifact_digest: CommandDigest
    component_artifact_digest: CommandDigest | None
    config_digest: CommandDigest
    execution_policy_digest: CommandDigest
    steps: tuple[ProvisioningStep, ...] = Field(min_length=1)
    prerequisite_capability_binding_ids: tuple[UUID, ...]
    prerequisite_evidence_bindings: tuple[PrerequisiteEvidenceBinding, ...]

    @field_validator("capability_operations")
    @classmethod
    def require_canonical_operations(
        cls, value: tuple[CapabilityOperationPin, ...]
    ) -> tuple[CapabilityOperationPin, ...]:
        return _require_canonical_operations(value)

    @field_validator("prerequisite_capability_binding_ids")
    @classmethod
    def require_canonical_binding_order(
        cls, value: tuple[UUID, ...]
    ) -> tuple[UUID, ...]:
        identifiers = tuple(str(identifier) for identifier in value)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("prerequisite capability binding ids must be unique")
        if identifiers != tuple(sorted(identifiers)):
            raise ValueError(
                "prerequisite capability binding ids must use canonical UUID order"
            )
        return value

    @field_validator("prerequisite_evidence_bindings")
    @classmethod
    def require_canonical_evidence_bindings(
        cls, value: tuple[PrerequisiteEvidenceBinding, ...]
    ) -> tuple[PrerequisiteEvidenceBinding, ...]:
        return _require_canonical_evidence_bindings(value)

    @model_validator(mode="after")
    def require_exact_static_identities(self) -> Self:
        if self.binding_ref != self.capability_binding_id:
            raise ValueError("binding_ref must equal capability_binding_id")
        expected_capability_id = (
            f"{self.capability_code}.v{self.capability_schema_version}"
        )
        if self.capability_id != expected_capability_id:
            raise ValueError(
                "capability_id must be capability_code plus its schema version"
            )
        if any(step.endpoint_code != self.capability_id for step in self.steps):
            raise ValueError(
                "every step endpoint_code must equal the versioned capability_id"
            )
        prerequisite_ids = set(self.prerequisite_capability_binding_ids)
        target_steps = {step.step_key for step in self.steps}
        apply_operation = next(
            (
                operation
                for operation in self.capability_operations
                if operation.operation_code == "apply"
            ),
            None,
        )
        if apply_operation is None:
            raise ValueError("capability operation pins must include apply")
        for binding in self.prerequisite_evidence_bindings:
            if binding.source_capability_binding_id not in prerequisite_ids:
                raise ValueError(
                    "evidence source must be an approved prerequisite "
                    "capability binding"
                )
            if binding.target_step_key not in target_steps:
                raise ValueError("evidence target step must exist in command steps")
            if (
                binding.target_schema_ref != apply_operation.input_schema_ref
                or binding.target_schema_digest != apply_operation.input_schema_digest
            ):
                raise ValueError(
                    "evidence target schema must equal the capability apply "
                    "input schema"
                )
        return self


class PrerequisiteReceiptPin(_StrictModel):
    """Immutable upstream success evidence for one cross-binding DAG edge."""

    operation_id: UUID
    capability_binding_id: UUID
    terminal_receipt_sequence: Annotated[int, Field(ge=1)]
    terminal_receipt_digest: CommandDigest
    required_terminal_status: Literal["succeeded"]


class ApplyCommand(PlanCommand):
    desired_state_revision: Annotated[int, Field(ge=1)]
    desired_state_version_id: UUID
    desired_state_hash: CommandDigest
    saved_plan_id: UUID
    approval_request_id: UUID
    approval_request_binding_hash: CommandDigest
    plan_command_id: CommandIdentifier
    plan_validation_receipt_id: UUID
    plan_validation_receipt_digest: CommandDigest
    plan_validation_request_body_digest: CommandDigest
    module_plan_receipt_hash: CommandDigest
    profile_version_id: UUID
    profile_code: Code
    profile_version: Annotated[int, Field(ge=1)]
    profile_schema_version: Annotated[int, Field(ge=1)]
    profile_content_hash: CommandDigest
    command_schema_version: Literal["integrator.provisioning-command.v1"]
    capability_owner_code: Code
    capability_code: Code
    capability_schema_version: Annotated[int, Field(ge=1)]
    capability_contract_attestation_id: UUID
    capability_contract_digest: CommandDigest
    capability_operations: tuple[CapabilityOperationPin, ...] = Field(min_length=1)
    binding_ref: UUID
    installation_id: UUID
    installation_ref: Reference
    connector_key: Code
    connector_version: Reference
    connector_manifest_digest: CommandDigest
    connector_configuration_revision_id: UUID
    configuration_snapshot_ref: Reference
    configuration_schema_version: Annotated[int, Field(ge=1)]
    configuration_hash: CommandDigest
    artifact_digest: CommandDigest
    component_artifact_digest: CommandDigest | None
    execution_policy_digest: CommandDigest
    expected_plan_hash: CommandDigest
    approved_command_template_digest: CommandDigest
    prerequisite_capability_binding_ids: tuple[UUID, ...]
    prerequisite_evidence_bindings: tuple[PrerequisiteEvidenceBinding, ...]
    prerequisite_receipt_pins: tuple[PrerequisiteReceiptPin, ...]
    approval: ApprovalGrant

    @field_validator("prerequisite_capability_binding_ids")
    @classmethod
    def require_canonical_binding_order(
        cls, value: tuple[UUID, ...]
    ) -> tuple[UUID, ...]:
        return ApprovedCommandTemplate.require_canonical_binding_order(value)

    @field_validator("capability_operations")
    @classmethod
    def require_canonical_operations(
        cls, value: tuple[CapabilityOperationPin, ...]
    ) -> tuple[CapabilityOperationPin, ...]:
        return _require_canonical_operations(value)

    @field_validator("prerequisite_evidence_bindings")
    @classmethod
    def require_canonical_evidence_bindings(
        cls, value: tuple[PrerequisiteEvidenceBinding, ...]
    ) -> tuple[PrerequisiteEvidenceBinding, ...]:
        return _require_canonical_evidence_bindings(value)

    @field_validator("prerequisite_receipt_pins")
    @classmethod
    def require_canonical_prerequisite_order(
        cls, value: tuple[PrerequisiteReceiptPin, ...]
    ) -> tuple[PrerequisiteReceiptPin, ...]:
        operation_ids = tuple(str(pin.operation_id) for pin in value)
        if len(set(operation_ids)) != len(operation_ids):
            raise ValueError("prerequisite operation_id values must be unique")
        if operation_ids != tuple(sorted(operation_ids)):
            raise ValueError("prerequisite pins must use canonical operation_id order")
        return value

    @model_validator(mode="after")
    def require_approved_template_and_exact_dynamic_pins(self) -> Self:
        if self.binding_ref != self.capability_binding_id:
            raise ValueError("binding_ref must equal capability_binding_id")
        expected_capability_id = (
            f"{self.capability_code}.v{self.capability_schema_version}"
        )
        if self.capability_id != expected_capability_id:
            raise ValueError(
                "capability_id must be capability_code plus its schema version"
            )
        if self.approval_request_id != self.approval.approval_request_id:
            raise ValueError("approval grant does not match approval_request_id")
        if (
            self.approval_request_binding_hash
            != self.approval.approval_request_binding_hash
        ):
            raise ValueError(
                "approval grant does not match approval_request_binding_hash"
            )
        if self.saved_plan_id != self.approval.saved_plan_id:
            raise ValueError("approval grant does not match saved_plan_id")
        if self.plan_hash != self.expected_plan_hash:
            raise ValueError("plan_hash must equal expected_plan_hash")
        if self.plan_hash != self.approval.approved_plan_hash:
            raise ValueError("approval grant does not approve plan_hash")
        plan_evidence = (
            (self.plan_command_id, self.approval.plan_command_id, "plan_command_id"),
            (
                self.plan_validation_receipt_id,
                self.approval.plan_validation_receipt_id,
                "plan_validation_receipt_id",
            ),
            (
                self.plan_validation_receipt_digest,
                self.approval.plan_validation_receipt_digest,
                "plan_validation_receipt_digest",
            ),
            (
                self.plan_validation_request_body_digest,
                self.approval.plan_validation_request_body_digest,
                "plan_validation_request_body_digest",
            ),
            (
                self.module_plan_receipt_hash,
                self.approval.module_plan_receipt_hash,
                "module_plan_receipt_hash",
            ),
        )
        for command_value, grant_value, field_name in plan_evidence:
            if command_value != grant_value:
                raise ValueError(f"approval grant does not match {field_name}")
        static_bindings = self.prerequisite_capability_binding_ids
        dynamic_bindings = tuple(
            pin.capability_binding_id for pin in self.prerequisite_receipt_pins
        )
        wrong_count = len(dynamic_bindings) != len(static_bindings)
        wrong_bindings = set(dynamic_bindings) != set(static_bindings)
        if wrong_count or wrong_bindings:
            raise ValueError(
                "receipt-pin capability bindings must exactly match the approved "
                "prerequisite capability bindings"
            )
        expected = command_template_digest(self)
        if self.approved_command_template_digest != expected:
            raise ValueError("approved command template digest does not match body")
        if self.approval.approved_command_template_digest != expected:
            raise ValueError("approval grant does not approve this command template")
        return self


class ObserveCommand(_StrictModel):
    deployment_ref: Reference
    capability_instance_ref: CapabilityInstanceRef
    operation_id: UUID
    step_key: Code
    provider_operation_ref: Reference
    plan_hash: CommandDigest
    approval_digest: CommandDigest
    artifact_digest: CommandDigest
    config_digest: CommandDigest


class CancelCommand(ObserveCommand):
    reason: Annotated[str, Field(min_length=1, max_length=500)]


class _Envelope(_StrictModel):
    contract_version: Literal["integrator.provisioning-command.v1"]
    key_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")]
    audience: Annotated[str, Field(min_length=1, max_length=240)]
    issued_at: datetime
    expires_at: datetime
    command_id: Annotated[str, Field(min_length=1, max_length=240)]
    nonce: Annotated[str, Field(min_length=8, max_length=240)]
    body_sha256: CommandDigest
    signature: Annotated[str, Field(min_length=8, max_length=512)]

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("command envelope times must include a timezone")
        return value


class PlanCommandEnvelope(_Envelope):
    body: PlanCommand


class ApplyCommandEnvelope(_Envelope):
    body: ApplyCommand


class ObserveCommandEnvelope(_Envelope):
    body: ObserveCommand


class CancelCommandEnvelope(_Envelope):
    body: CancelCommand


CommandEnvelope = (
    PlanCommandEnvelope
    | ApplyCommandEnvelope
    | ObserveCommandEnvelope
    | CancelCommandEnvelope
)


BodyT = TypeVar("BodyT", bound=_StrictModel)


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedCommand(Generic[BodyT]):
    contract_version: str
    key_id: str
    issuer_account_ref: str
    audience: str
    issued_at: datetime
    expires_at: datetime
    command_id: str
    nonce: str
    body_sha256: str
    body: BodyT


class ReceiptPayload(_StrictModel):
    receipt_contract_version: Literal["integrator.provisioning-receipt.v1"]
    command_contract_version: str
    operation: Literal["plan", "apply", "observe", "cancel"]
    command_id: str
    nonce: str
    issuer_account_ref: Reference
    deployment_ref: Reference
    capability_instance_ref: CapabilityInstanceRef
    request_body_sha256: CommandDigest
    plan_hash: CommandDigest
    approval_digest: CommandDigest | None
    artifact_digest: CommandDigest | None
    config_digest: CommandDigest
    outcome: str
    operation_id: UUID | None = None
    replayed: bool | None = None
    latest_module_receipt_sequence: Annotated[int, Field(ge=1)] | None = None
    latest_module_receipt_hash: CommandDigest | None = None
    module_plan_receipt_hash: CommandDigest | None = None
    occurred_at: datetime
    evidence: dict[str, object] = Field(default_factory=dict)


class SignedReceipt(_StrictModel):
    key_id: str
    receipt_sha256: CommandDigest
    signature: str
    receipt: ReceiptPayload


class CommandAuthenticationRefused(RuntimeError):
    """A command or receipt signature cannot be trusted."""


@dataclass(frozen=True, slots=True, repr=False)
class _CryptoState:
    audience: str
    public_keys: Mapping[str, Ed25519PublicKey]
    issuer_assignments: Mapping[str, CommandIssuerAssignment]
    clock_skew: timedelta
    max_lifetime: timedelta
    receipt_key_id: str
    receipt_private_key: Ed25519PrivateKey


_state: _CryptoState | None = None
_installed_settings: Settings | None = None
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def body_digest(body: _StrictModel) -> str:
    return "sha256:" + hashlib.sha256(canonical_body_bytes(body)).hexdigest()


def canonical_body_bytes(body: _StrictModel) -> bytes:
    """Pure v1 body canonicalizer; mirrored by the checked golden fixture."""
    return _canonical(body.model_dump(mode="json", exclude_none=False))


def command_template_digest(
    value: ApprovedCommandTemplate | ApplyCommand,
) -> str:
    """Hash only immutable pre-approval fields, never dispatch-time receipts."""
    if isinstance(value, ApplyCommand):
        template = ApprovedCommandTemplate(
            deployment_ref=value.deployment_ref,
            desired_state_revision=value.desired_state_revision,
            desired_state_version_id=value.desired_state_version_id,
            desired_state_hash=value.desired_state_hash,
            saved_plan_id=value.saved_plan_id,
            profile_version_id=value.profile_version_id,
            profile_code=value.profile_code,
            profile_version=value.profile_version,
            profile_schema_version=value.profile_schema_version,
            profile_content_hash=value.profile_content_hash,
            command_schema_version=value.command_schema_version,
            capability_id=value.capability_id,
            capability_instance_ref=value.capability_instance_ref,
            capability_owner_code=value.capability_owner_code,
            capability_code=value.capability_code,
            capability_schema_version=value.capability_schema_version,
            capability_contract_attestation_id=(
                value.capability_contract_attestation_id
            ),
            capability_contract_digest=value.capability_contract_digest,
            capability_operations=value.capability_operations,
            capability_binding_id=value.capability_binding_id,
            binding_ref=value.binding_ref,
            installation_id=value.installation_id,
            installation_ref=value.installation_ref,
            connector_key=value.connector_key,
            connector_version=value.connector_version,
            connector_manifest_digest=value.connector_manifest_digest,
            connector_configuration_revision_id=(
                value.connector_configuration_revision_id
            ),
            configuration_snapshot_ref=value.configuration_snapshot_ref,
            configuration_schema_version=value.configuration_schema_version,
            configuration_hash=value.configuration_hash,
            artifact_digest=value.artifact_digest,
            component_artifact_digest=value.component_artifact_digest,
            config_digest=value.config_digest,
            execution_policy_digest=value.execution_policy_digest,
            steps=value.steps,
            prerequisite_capability_binding_ids=(
                value.prerequisite_capability_binding_ids
            ),
            prerequisite_evidence_bindings=value.prerequisite_evidence_bindings,
        )
    else:
        template = value
    return body_digest(template)


def canonical_command_bytes(envelope: CommandEnvelope) -> bytes:
    """The exact signed header; body bytes are bound by ``body_sha256``."""
    material = envelope.model_dump(
        mode="json", exclude={"signature", "body"}, exclude_none=False
    )
    return _canonical(material)


def _decode_raw_key(material: str) -> bytes:
    try:
        decoded = base64.b64decode(material, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Ed25519 material is not canonical base64") from exc
    if len(decoded) != 32:
        raise ValueError("Ed25519 material must encode exactly 32 raw bytes")
    return decoded


def _public_key(material: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_decode_raw_key(material))


def _private_key(material: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_decode_raw_key(material))


def crypto_material_validators(
    settings: Settings,
) -> dict[str, Any]:
    """Validators run while loading, so a bad rotation preserves old keys."""
    if not settings.command_surface_enabled:
        return {}
    validators: dict[str, Any] = {
        reference: _public_key
        for reference in command_public_key_references(
            settings.command_public_key_refs
        ).values()
    }
    validators[settings.command_issuer_assignments_ref] = _issuer_assignments
    validators[settings.receipt_signing_private_key_ref] = _private_key
    return validators


def _issuer_assignments(material: str) -> CommandIssuerAssignments:
    try:
        value = json.loads(material)
        return CommandIssuerAssignments.model_validate(value)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("invalid command issuer assignment document") from exc


def _validated_crypto_state(
    settings: Settings, material: Mapping[str, str]
) -> _CryptoState | None:
    if not settings.command_surface_enabled:
        return None
    references = command_public_key_references(settings.command_public_key_refs)
    public_keys: dict[str, Ed25519PublicKey] = {}
    for key_id, reference in references.items():
        value = material.get(reference)
        if value is None:
            raise ValueError(f"command public key reference {reference!r} is not held")
        public_keys[key_id] = _public_key(value)
    assignment_ref = settings.command_issuer_assignments_ref
    assignment_value = material.get(assignment_ref)
    if assignment_value is None:
        raise ValueError(
            f"command issuer assignment reference {assignment_ref!r} is not held"
        )
    assignments_document = _issuer_assignments(assignment_value)
    issuer_assignments = {
        item.key_id: item for item in assignments_document.assignments
    }
    if set(issuer_assignments) != set(public_keys):
        raise ValueError(
            "command issuer assignment key ids must exactly match held public keys"
        )
    receipt_ref = settings.receipt_signing_private_key_ref
    receipt_value = material.get(receipt_ref)
    if receipt_value is None:
        raise ValueError(f"receipt signing key reference {receipt_ref!r} is not held")
    receipt_key = _private_key(receipt_value)
    receipt_public = receipt_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    issuer_public = {
        key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        for key in public_keys.values()
    }
    if receipt_public in issuer_public:
        raise ValueError(
            "the Integrator receipt-signing key must be distinct from every "
            "command issuer key"
        )
    return _CryptoState(
        audience=settings.command_audience,
        public_keys=public_keys,
        issuer_assignments=issuer_assignments,
        clock_skew=timedelta(seconds=settings.command_clock_skew_seconds),
        max_lifetime=timedelta(seconds=settings.command_max_lifetime_seconds),
        receipt_key_id=settings.receipt_signing_key_id,
        receipt_private_key=receipt_key,
    )


def validate_crypto_material(settings: Settings, material: Mapping[str, str]) -> None:
    """Validate relationships across the complete set before a held-set swap."""
    _validated_crypto_state(settings, material)


def install_crypto(settings: Settings, material: Mapping[str, str]) -> None:
    """Parse and atomically install one complete held-key working set."""
    global _installed_settings, _state
    state = _validated_crypto_state(settings, material)
    _installed_settings = settings
    _state = state


def install_crypto_from_held(settings: Settings) -> None:
    if not settings.command_surface_enabled:
        install_crypto(settings, {})
        return
    references = command_public_key_references(settings.command_public_key_refs)
    logical = {f"command:{key_id}": ref for key_id, ref in references.items()}
    logical["command:issuer-assignments"] = settings.command_issuer_assignments_ref
    logical["receipt:signing"] = settings.receipt_signing_private_key_ref
    resolved = resolve_secrets(logical)
    material = {
        reference: resolved[f"command:{key_id}"]
        for key_id, reference in references.items()
    }
    material[settings.command_issuer_assignments_ref] = resolved[
        "command:issuer-assignments"
    ]
    material[settings.receipt_signing_private_key_ref] = resolved["receipt:signing"]
    install_crypto(settings, material)


def refresh_crypto_from_held() -> None:
    if _installed_settings is None:
        return
    install_crypto_from_held(_installed_settings)


def _decode_signature(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (ValueError, binascii.Error, UnicodeEncodeError) as exc:
        raise CommandAuthenticationRefused("invalid command authentication") from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise CommandAuthenticationRefused("invalid command authentication")
    return decoded


def _verify(
    envelope: CommandEnvelope, *, now: datetime | None = None
) -> AuthenticatedCommand[Any]:
    state = _state
    if state is None:
        raise CommandAuthenticationRefused("machine command keys are not installed")
    moment = now or datetime.now(UTC)
    issued_at = envelope.issued_at.astimezone(UTC)
    expires_at = envelope.expires_at.astimezone(UTC)
    if envelope.audience != state.audience:
        raise CommandAuthenticationRefused("invalid command authentication")
    if issued_at > moment + state.clock_skew:
        raise CommandAuthenticationRefused("command is not yet valid")
    if expires_at <= moment:
        raise CommandAuthenticationRefused("command has expired")
    if expires_at <= issued_at or expires_at - issued_at > state.max_lifetime:
        raise CommandAuthenticationRefused("command validity interval is invalid")
    if envelope.nonce != envelope.command_id:
        raise CommandAuthenticationRefused(
            "command nonce must equal command_id; the module command ledger "
            "is the sole replay owner"
        )
    assignment = state.issuer_assignments.get(envelope.key_id)
    if assignment is None:
        raise CommandAuthenticationRefused(
            "command issuer is not assigned to deployment capability instance"
        )
    assigned_instances = next(
        (
            item.capability_instance_refs
            for item in assignment.deployment_instances
            if item.deployment_ref == envelope.body.deployment_ref
        ),
        (),
    )
    if envelope.body.capability_instance_ref not in assigned_instances:
        raise CommandAuthenticationRefused(
            "command issuer is not assigned to deployment capability instance"
        )
    if body_digest(envelope.body) != envelope.body_sha256:
        raise CommandAuthenticationRefused("command body hash does not match")
    public_key = state.public_keys.get(envelope.key_id)
    if public_key is None:
        raise CommandAuthenticationRefused("invalid command authentication")
    try:
        public_key.verify(
            _decode_signature(envelope.signature), canonical_command_bytes(envelope)
        )
    except InvalidSignature as exc:
        raise CommandAuthenticationRefused("invalid command authentication") from exc
    return AuthenticatedCommand(
        contract_version=envelope.contract_version,
        key_id=envelope.key_id,
        issuer_account_ref=assignment.account_ref,
        audience=envelope.audience,
        issued_at=issued_at,
        expires_at=expires_at,
        command_id=envelope.command_id,
        nonce=envelope.nonce,
        body_sha256=envelope.body_sha256,
        body=envelope.body,
    )


def verify_apply_command(
    envelope: ApplyCommandEnvelope, *, now: datetime | None = None
) -> AuthenticatedCommand[ApplyCommand]:
    return _verify(envelope, now=now)


class MachineCommandGuard:
    """Marker base used by the route-classification boot audit."""

    def _http_verify(self, envelope: CommandEnvelope) -> AuthenticatedCommand[Any]:
        try:
            return _verify(envelope)
        except CommandAuthenticationRefused as exc:
            raise HTTPException(
                status_code=401,
                detail=str(exc),
                headers={"WWW-Authenticate": "Signature"},
            ) from exc


class _PlanGuard(MachineCommandGuard):
    def __call__(
        self, envelope: Annotated[PlanCommandEnvelope, Body()]
    ) -> AuthenticatedCommand[PlanCommand]:
        return self._http_verify(envelope)


class _ApplyGuard(MachineCommandGuard):
    def __call__(
        self, envelope: Annotated[ApplyCommandEnvelope, Body()]
    ) -> AuthenticatedCommand[ApplyCommand]:
        return self._http_verify(envelope)


class _ObserveGuard(MachineCommandGuard):
    def __call__(
        self, envelope: Annotated[ObserveCommandEnvelope, Body()]
    ) -> AuthenticatedCommand[ObserveCommand]:
        return self._http_verify(envelope)


class _CancelGuard(MachineCommandGuard):
    def __call__(
        self, envelope: Annotated[CancelCommandEnvelope, Body()]
    ) -> AuthenticatedCommand[CancelCommand]:
        return self._http_verify(envelope)


require_plan_command = _PlanGuard()
require_apply_command = _ApplyGuard()
require_observe_command = _ObserveGuard()
require_cancel_command = _CancelGuard()


def _receipt_signature_bytes(key_id: str, digest: str) -> bytes:
    return _canonical({"key_id": key_id, "receipt_sha256": digest})


def sign_receipt(receipt: ReceiptPayload) -> SignedReceipt:
    state = _state
    if state is None:
        raise RuntimeError("receipt signer is not installed")
    digest = (
        "sha256:"
        + hashlib.sha256(
            _canonical(receipt.model_dump(mode="json", exclude_none=False))
        ).hexdigest()
    )
    signature = (
        base64.urlsafe_b64encode(
            state.receipt_private_key.sign(
                _receipt_signature_bytes(state.receipt_key_id, digest)
            )
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    return SignedReceipt(
        key_id=state.receipt_key_id,
        receipt_sha256=digest,
        signature=signature,
        receipt=receipt,
    )


def verify_receipt(
    value: SignedReceipt | Mapping[str, object], public_key: Ed25519PublicKey
) -> None:
    receipt = (
        value
        if isinstance(value, SignedReceipt)
        else SignedReceipt.model_validate(value)
    )
    digest = (
        "sha256:"
        + hashlib.sha256(
            _canonical(receipt.receipt.model_dump(mode="json", exclude_none=False))
        ).hexdigest()
    )
    if (
        not _DIGEST_RE.fullmatch(receipt.receipt_sha256)
        or digest != receipt.receipt_sha256
    ):
        raise CommandAuthenticationRefused("receipt body hash does not match")
    try:
        public_key.verify(
            _decode_signature(receipt.signature),
            _receipt_signature_bytes(receipt.key_id, receipt.receipt_sha256),
        )
    except InvalidSignature as exc:
        raise CommandAuthenticationRefused("invalid receipt signature") from exc
