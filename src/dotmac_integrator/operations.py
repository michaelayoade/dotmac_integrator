"""Operational controls: session, fetch, delegate, serialise.

The routes in `assembly.py` hold no session and issue no query — same split the
Starter enforces between `router.py` and `service.py`, for the same reason. This
file is the assembly's service layer, and it is thin by construction: every
function here loads what the module's operation needs, calls it, and converts
the result to JSON.

**No decision is made in this file.** `release_expired_leases`, `health_report`,
`replay_delivery`, `replay_receipt` and `enable` all belong to
`dotmac_integration`. What is added is a transaction boundary, a serialisation,
and the two things a module composed by an unknown assembly cannot supply
itself: the materialised secrets its enablement gate needs, and the identity of
the person who asked.

## Actor and reason are threaded, not optional

`dotmac_integration.record_operation` takes `actor_admin_id` with a default of
`None`, so an unauthenticated repair writes an audit row with a null actor and
succeeds. That default is correct for a module that must not presume its host's
identity model, and wrong for this deployment — so every operator-triggered
function here takes an `OperatorIdentity` positionally and passes both
representations through. An audit row that cannot say who and why is not
evidence.

The one caller that legitimately passes no actor is the worker's timed lease
sweep: a schedule is not a person. It is a separate function
(`sweep_expired_leases`) rather than a default argument, so the distinction is
visible in the call site instead of hidden in a signature.

## The transaction owner exercises its authority

`lifecycle.enable` writes the connector's own failure text into
`installation.state_reason` and FLUSHES before raising. If a connector echoes
the credential it just failed to authenticate with, that credential lands in a
row and in every backup. Nothing in the module can prevent it — but this
assembly owns the transaction, and it declines to commit one.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, NoReturn, Protocol, cast
from uuid import UUID

import dotmac_integration as integration
from dotmac_kernel.audit import write_platform_audit_event
from fastapi import HTTPException
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from dotmac_integrator import machine_commands, secret_loading, telemetry
from dotmac_integrator.machine_commands import (
    ApplyCommand,
    AuthenticatedCommand,
    CancelCommand,
    ObserveCommand,
    PlanCommand,
    ReceiptPayload,
    SignedReceipt,
)
from dotmac_integrator.operator_auth import OperatorIdentity
from dotmac_integrator.secret_resolver import (
    missing_references,
    redact,
    resolve_secrets,
)

#: Audit actions this ASSEMBLY writes, under its own prefix.
#:
#: `integration.*` is the module's vocabulary and it declares three of them on
#: its manifest; writing a fourth from here would make this deployment a second
#: author of someone else's registry (hard rule 12). These are operations the
#: assembly genuinely owns — enablement is gated on material only a deployment
#: can materialise, and a secret refresh has no module-side existence at all.
#:
#: `tests/architecture/test_audit_actions_are_declared.py` asserts in both
#: directions: nothing is written that is not declared here, and nothing is
#: declared here without a writer.
INTEGRATOR_AUDIT_ACTION_PREFIX = "integrator"
INTEGRATOR_AUDIT_ACTIONS: tuple[str, ...] = (
    "integrator.installation.enabled",
    "integrator.installation.enable_refused",
    "integrator.secrets.refreshed",
)

# Every published module name required by the command gateway.  Keep this as a
# complete boot gate rather than discovering one missing phase halfway through
# a signed request: a deployment pinned to the preceding module release must
# refuse enablement, not mount a surface it cannot finish.
PROVISIONING_MODULE_SYMBOLS: tuple[str, ...] = (
    "CAPABILITY_INSTANCE_REF_PATTERN",
    "require_capability_instance_ref",
    "ProvisionStep",
    "VerifiedApprovalGrant",
    "ProvisioningCommand",
    "ProvisioningCapabilityOperationPin",
    "PrerequisiteReceiptPin",
    "PrerequisiteEvidenceBinding",
    "ExpectedProvisioningPin",
    "CommandIdentityCollision",
    "ProvisioningRefused",
    "prepare_provisioning_plan",
    "invoke_prepared_plan",
    "settle_provisioning_plan",
    "accept_provisioning_command",
    "prepare_next_apply",
    "invoke_prepared_provisioning",
    "settle_provisioning",
    "prepare_next_observation",
    "invoke_prepared_observation",
    "settle_observation",
    "prepare_cancellation",
    "invoke_prepared_cancellation",
    "settle_cancellation",
    "read_provisioning_receipts",
    "ProvisioningPlanReceiptView",
    "read_provisioning_plan_receipt",
)


@dataclass(frozen=True, slots=True, repr=False)
class ProvisioningOutcome:
    """Safe transport projection returned by a module-backed façade."""

    state: str
    operation_id: UUID | None = None
    replayed: bool | None = None
    evidence: dict[str, object] = field(default_factory=dict)
    capability_instance_ref: str | None = None
    plan_hash: str | None = None
    approval_digest: str | None = None
    artifact_digest: str | None = None
    config_digest: str | None = None
    latest_module_receipt_sequence: int | None = None
    latest_module_receipt_hash: str | None = None
    module_plan_receipt_hash: str | None = None


class ProvisioningPlanReceiptProjection(Protocol):
    command_id: str
    command_fingerprint: str
    capability_instance_ref: str
    request_body_digest: str
    result_digest: str
    receipt_hash: str


class ProvisioningReceiptProjection(Protocol):
    sequence: int
    receipt_kind: str
    step_key: str | None
    provider_operation_ref: str | None
    previous_receipt_hash: str | None
    receipt_hash: str
    plan_hash: str
    capability_instance_ref: str
    connector_key: str
    connector_version: str
    manifest_digest: str
    artifact_digest: str
    config_digest: str
    approval_digest: str
    evidence: Mapping[str, object]


class ProvisioningGateway(Protocol):
    """Assembly seam over dotmac-integration's four public façades.

    The concrete implementation below remains a direct adapter to top-level
    published symbols; it owns no provisioning decision.
    """

    def plan(
        self, engine: Engine, command_id: str, body: PlanCommand
    ) -> ProvisioningOutcome: ...

    def apply(
        self, engine: Engine, command_id: str, body: ApplyCommand
    ) -> ProvisioningOutcome: ...

    def observe(
        self, engine: Engine, command_id: str, body: ObserveCommand
    ) -> ProvisioningOutcome: ...

    def cancel(
        self, engine: Engine, command_id: str, body: CancelCommand
    ) -> ProvisioningOutcome: ...


def require_provisioning_module_surface() -> None:
    """Refuse boot unless the composed module publishes the whole a6 seam."""
    missing = tuple(
        name
        for name in PROVISIONING_MODULE_SYMBOLS
        if getattr(integration, name, None) is None
    )
    if not missing:
        return
    version = getattr(integration, "__version__", "unknown")
    qualified = ", ".join(f"dotmac_integration.{name}" for name in missing)
    raise RuntimeError(
        f"dotmac-integration {version} does not publish the complete "
        f"provisioning command surface: {qualified}"
    )


def _module_symbol(name: str) -> Any:
    symbol = getattr(integration, name, None)
    if symbol is None:
        version = getattr(integration, "__version__", "unknown")
        raise RuntimeError(
            f"dotmac-integration {version} does not publish required symbol "
            f"dotmac_integration.{name}",
        )
    return symbol


class ModuleProvisioningGateway:
    """Direct adapter to the module's public provisioning transaction façades."""

    def plan(
        self, engine: Engine, command_id: str, body: PlanCommand
    ) -> ProvisioningOutcome:
        registry = integration.discover()
        step_type = _module_symbol("ProvisionStep")
        prepare = _module_symbol("prepare_provisioning_plan")
        invoke = _module_symbol("invoke_prepared_plan")
        settle = _module_symbol("settle_provisioning_plan")
        read_plan_receipt = _module_symbol("read_provisioning_plan_receipt")
        request_body_digest = machine_commands.body_digest(body)
        steps = tuple(
            step_type(
                step_key=step.step_key,
                endpoint_code=step.endpoint_code,
                depends_on=step.depends_on,
                input=step.input,
            )
            for step in body.steps
        )
        try:
            with Session(engine) as db:
                prepared = prepare(
                    db,
                    command_id=command_id,
                    deployment_ref=body.deployment_ref,
                    capability_id=body.capability_id,
                    capability_instance_ref=body.capability_instance_ref,
                    binding_id=body.capability_binding_id,
                    config_digest=body.config_digest,
                    plan_hash=body.plan_hash,
                    request_body_digest=request_body_digest,
                    steps=steps,
                    registry=registry,
                )
                db.commit()
            replayed = prepared is None
            if prepared is not None:
                result = invoke(
                    prepared, registry=registry, resolve_secrets=resolve_secrets
                )
                with Session(engine) as db:
                    settle(db, prepared=prepared, result=result)
                    db.commit()
            with Session(engine) as db:
                plan_receipt = cast(
                    ProvisioningPlanReceiptProjection,
                    read_plan_receipt(db, command_id=command_id),
                )
        except Exception as exc:
            _raise_provisioning_refusal(exc)
        if plan_receipt.command_id != command_id:
            raise RuntimeError("module PLAN receipt command identity differs")
        if plan_receipt.request_body_digest != request_body_digest:
            raise RuntimeError("module PLAN receipt request body digest differs")
        if plan_receipt.capability_instance_ref != body.capability_instance_ref:
            raise RuntimeError("module PLAN receipt capability instance differs")
        return ProvisioningOutcome(
            state="planned",
            replayed=replayed,
            capability_instance_ref=str(plan_receipt.capability_instance_ref),
            plan_hash=body.plan_hash,
            config_digest=body.config_digest,
            module_plan_receipt_hash=str(plan_receipt.receipt_hash),
            evidence={
                "step_count": len(body.steps),
                "module_plan_receipt": {
                    "command_id": str(plan_receipt.command_id),
                    "command_fingerprint": str(plan_receipt.command_fingerprint),
                    "capability_instance_ref": str(
                        plan_receipt.capability_instance_ref
                    ),
                    "request_body_digest": str(plan_receipt.request_body_digest),
                    "result_digest": str(plan_receipt.result_digest),
                    "receipt_hash": str(plan_receipt.receipt_hash),
                },
            },
        )

    def apply(
        self, engine: Engine, command_id: str, body: ApplyCommand
    ) -> ProvisioningOutcome:
        step_type = _module_symbol("ProvisionStep")
        operation_pin_type = _module_symbol("ProvisioningCapabilityOperationPin")
        approval_type = _module_symbol("VerifiedApprovalGrant")
        prerequisite_type = _module_symbol("PrerequisiteReceiptPin")
        evidence_binding_type = _module_symbol("PrerequisiteEvidenceBinding")
        command_type = _module_symbol("ProvisioningCommand")
        accept = _module_symbol("accept_provisioning_command")
        prepare = _module_symbol("prepare_next_apply")
        invoke = _module_symbol("invoke_prepared_provisioning")
        settle = _module_symbol("settle_provisioning")
        read_receipts = _module_symbol("read_provisioning_receipts")
        registry = integration.discover()
        command = command_type(
            command_id=command_id,
            deployment_ref=body.deployment_ref,
            desired_state_revision=body.desired_state_revision,
            desired_state_version_id=body.desired_state_version_id,
            desired_state_hash=body.desired_state_hash,
            saved_plan_id=body.saved_plan_id,
            approval_request_id=body.approval_request_id,
            approval_request_binding_hash=body.approval_request_binding_hash,
            plan_command_id=body.plan_command_id,
            plan_validation_receipt_id=body.plan_validation_receipt_id,
            plan_validation_receipt_digest=body.plan_validation_receipt_digest,
            plan_validation_request_body_digest=(
                body.plan_validation_request_body_digest
            ),
            module_plan_receipt_hash=body.module_plan_receipt_hash,
            profile_version_id=body.profile_version_id,
            profile_code=body.profile_code,
            profile_version=body.profile_version,
            profile_schema_version=body.profile_schema_version,
            profile_content_hash=body.profile_content_hash,
            command_schema_version=body.command_schema_version,
            capability_id=body.capability_id,
            capability_instance_ref=body.capability_instance_ref,
            capability_owner_code=body.capability_owner_code,
            capability_code=body.capability_code,
            capability_schema_version=body.capability_schema_version,
            capability_contract_attestation_id=(
                body.capability_contract_attestation_id
            ),
            capability_contract_digest=body.capability_contract_digest,
            capability_operations=tuple(
                operation_pin_type(**operation.model_dump(mode="python"))
                for operation in body.capability_operations
            ),
            capability_binding_id=body.capability_binding_id,
            binding_ref=body.binding_ref,
            installation_id=body.installation_id,
            installation_ref=body.installation_ref,
            connector_key=body.connector_key,
            connector_version=body.connector_version,
            connector_manifest_digest=body.connector_manifest_digest,
            connector_configuration_revision_id=(
                body.connector_configuration_revision_id
            ),
            configuration_snapshot_ref=body.configuration_snapshot_ref,
            configuration_schema_version=body.configuration_schema_version,
            configuration_hash=body.configuration_hash,
            plan_hash=body.plan_hash,
            expected_plan_hash=body.expected_plan_hash,
            artifact_digest=body.artifact_digest,
            component_artifact_digest=body.component_artifact_digest,
            config_digest=body.config_digest,
            execution_policy_digest=body.execution_policy_digest,
            prerequisite_capability_binding_ids=(
                body.prerequisite_capability_binding_ids
            ),
            prerequisite_evidence_bindings=tuple(
                evidence_binding_type(**binding.model_dump(mode="python"))
                for binding in body.prerequisite_evidence_bindings
            ),
            prerequisite_receipt_pins=tuple(
                prerequisite_type(
                    operation_id=pin.operation_id,
                    capability_binding_id=pin.capability_binding_id,
                    terminal_receipt_sequence=pin.terminal_receipt_sequence,
                    terminal_receipt_digest=pin.terminal_receipt_digest,
                    required_terminal_status=pin.required_terminal_status,
                )
                for pin in body.prerequisite_receipt_pins
            ),
            approval=approval_type(
                grant_ref=body.approval.grant_ref,
                approval_request_id=body.approval.approval_request_id,
                approval_request_binding_hash=(
                    body.approval.approval_request_binding_hash
                ),
                saved_plan_id=body.approval.saved_plan_id,
                approved_plan_hash=body.approval.approved_plan_hash,
                approved_command_template_digest=(
                    body.approval.approved_command_template_digest
                ),
                plan_command_id=body.approval.plan_command_id,
                plan_validation_receipt_id=(body.approval.plan_validation_receipt_id),
                plan_validation_receipt_digest=(
                    body.approval.plan_validation_receipt_digest
                ),
                plan_validation_request_body_digest=(
                    body.approval.plan_validation_request_body_digest
                ),
                module_plan_receipt_hash=body.approval.module_plan_receipt_hash,
                digest=body.approval.digest,
                expires_at=body.approval.expires_at,
                verified_at=body.approval.verified_at,
            ),
            steps=tuple(
                step_type(
                    step_key=step.step_key,
                    endpoint_code=step.endpoint_code,
                    depends_on=step.depends_on,
                    input=step.input,
                )
                for step in body.steps
            ),
        )
        try:
            with Session(engine) as db:
                accepted = accept(db, command, registry=registry)
                db.commit()
            replayed = not bool(accepted.is_new)
            with Session(engine) as db:
                prepared = prepare(
                    db,
                    operation_id=accepted.operation_id,
                    registry=registry,
                )
                db.commit()
            if prepared is None:
                receipts = _read_module_receipts(
                    engine, accepted.operation_id, read_receipts
                )
                return _operation_outcome(
                    state=str(accepted.state),
                    operation_id=accepted.operation_id,
                    replayed=replayed,
                    receipts=receipts,
                )
            result = invoke(
                prepared, registry=registry, resolve_secrets=resolve_secrets
            )
            with Session(engine) as db:
                operation = settle(db, prepared=prepared, result=result)
                receipts = tuple(read_receipts(db, operation_id=accepted.operation_id))
                state = str(operation.state)
                db.commit()
        except Exception as exc:
            _raise_provisioning_refusal(exc)
        return _operation_outcome(
            state=state,
            operation_id=accepted.operation_id,
            replayed=replayed,
            receipts=receipts,
        )

    def observe(
        self, engine: Engine, command_id: str, body: ObserveCommand
    ) -> ProvisioningOutcome:
        registry = integration.discover()
        expected_type = _module_symbol("ExpectedProvisioningPin")
        prepare = _module_symbol("prepare_next_observation")
        invoke = _module_symbol("invoke_prepared_observation")
        settle = _module_symbol("settle_observation")
        read_receipts = _module_symbol("read_provisioning_receipts")
        expected = expected_type(
            deployment_ref=body.deployment_ref,
            capability_instance_ref=body.capability_instance_ref,
            step_key=body.step_key,
            provider_operation_ref=body.provider_operation_ref,
            plan_hash=body.plan_hash,
            artifact_digest=body.artifact_digest,
            config_digest=body.config_digest,
            approval_digest=body.approval_digest,
        )
        try:
            with Session(engine) as db:
                prepared = prepare(
                    db,
                    command_id=command_id,
                    operation_id=body.operation_id,
                    expected=expected,
                    registry=registry,
                )
                db.commit()
            if prepared is None:
                receipts = _read_module_receipts(
                    engine, body.operation_id, read_receipts
                )
                return _verified_existing_outcome(body.operation_id, receipts)
            result = invoke(
                prepared, registry=registry, resolve_secrets=resolve_secrets
            )
            with Session(engine) as db:
                operation = settle(db, prepared=prepared, result=result)
                receipts = tuple(read_receipts(db, operation_id=body.operation_id))
                state = str(operation.state)
                db.commit()
        except Exception as exc:
            _raise_provisioning_refusal(exc)
        return _operation_outcome(
            state=state,
            operation_id=body.operation_id,
            replayed=False,
            receipts=receipts,
        )

    def cancel(
        self, engine: Engine, command_id: str, body: CancelCommand
    ) -> ProvisioningOutcome:
        registry = integration.discover()
        expected_type = _module_symbol("ExpectedProvisioningPin")
        prepare = _module_symbol("prepare_cancellation")
        invoke = _module_symbol("invoke_prepared_cancellation")
        settle = _module_symbol("settle_cancellation")
        read_receipts = _module_symbol("read_provisioning_receipts")
        expected = expected_type(
            deployment_ref=body.deployment_ref,
            capability_instance_ref=body.capability_instance_ref,
            step_key=body.step_key,
            provider_operation_ref=body.provider_operation_ref,
            plan_hash=body.plan_hash,
            artifact_digest=body.artifact_digest,
            config_digest=body.config_digest,
            approval_digest=body.approval_digest,
        )
        try:
            with Session(engine) as db:
                prepared = prepare(
                    db,
                    command_id=command_id,
                    operation_id=body.operation_id,
                    expected=expected,
                    reason=body.reason,
                    registry=registry,
                )
                db.commit()
            if prepared is None:
                receipts = _read_module_receipts(
                    engine, body.operation_id, read_receipts
                )
                return _verified_existing_outcome(body.operation_id, receipts)
            result = invoke(
                prepared, registry=registry, resolve_secrets=resolve_secrets
            )
            with Session(engine) as db:
                operation = settle(db, prepared=prepared, result=result)
                receipts = tuple(read_receipts(db, operation_id=body.operation_id))
                state = str(operation.state)
                db.commit()
        except Exception as exc:
            _raise_provisioning_refusal(exc)
        return _operation_outcome(
            state=state,
            operation_id=body.operation_id,
            replayed=False,
            receipts=receipts,
        )


def _raise_provisioning_refusal(exc: Exception) -> NoReturn:
    collision_type = _module_symbol("CommandIdentityCollision")
    refusal_type = _module_symbol("ProvisioningRefused")
    if isinstance(exc, collision_type):
        raise HTTPException(409, "command identity collision") from exc
    if isinstance(exc, refusal_type):
        raise HTTPException(409, redact(str(exc))) from exc
    raise exc


def _read_module_receipts(
    engine: Engine, operation_id: UUID, reader: Any
) -> tuple[ProvisioningReceiptProjection, ...]:
    with Session(engine) as db:
        return cast(
            tuple[ProvisioningReceiptProjection, ...],
            tuple(reader(db, operation_id=operation_id)),
        )


def _module_receipt_evidence(
    receipts: tuple[ProvisioningReceiptProjection, ...],
) -> dict[str, object]:
    return {
        "module_receipts": [
            {
                "sequence": receipt.sequence,
                "receipt_kind": receipt.receipt_kind,
                "step_key": receipt.step_key,
                "provider_operation_ref": receipt.provider_operation_ref,
                "previous_receipt_hash": receipt.previous_receipt_hash,
                "receipt_hash": receipt.receipt_hash,
                "plan_hash": receipt.plan_hash,
                "capability_instance_ref": receipt.capability_instance_ref,
                "connector_key": receipt.connector_key,
                "connector_version": receipt.connector_version,
                "manifest_digest": receipt.manifest_digest,
                "artifact_digest": receipt.artifact_digest,
                "config_digest": receipt.config_digest,
                "approval_digest": receipt.approval_digest,
                "evidence": dict(receipt.evidence),
            }
            for receipt in receipts
        ]
    }


def _operation_outcome(
    *,
    state: str,
    operation_id: UUID,
    replayed: bool | None,
    receipts: tuple[ProvisioningReceiptProjection, ...],
) -> ProvisioningOutcome:
    latest = receipts[-1] if receipts else None
    if latest is None:
        raise HTTPException(
            409,
            "the module returned no verified provisioning receipt for "
            "this operation",
        )
    return ProvisioningOutcome(
        state=state,
        operation_id=operation_id,
        replayed=replayed,
        evidence=_module_receipt_evidence(receipts),
        capability_instance_ref=str(latest.capability_instance_ref),
        plan_hash=str(latest.plan_hash),
        approval_digest=str(latest.approval_digest),
        artifact_digest=str(latest.artifact_digest),
        config_digest=str(latest.config_digest),
        latest_module_receipt_sequence=int(latest.sequence),
        latest_module_receipt_hash=str(latest.receipt_hash),
    )


def _verified_existing_outcome(
    operation_id: UUID, receipts: tuple[ProvisioningReceiptProjection, ...]
) -> ProvisioningOutcome:
    latest = receipts[-1] if receipts else None
    if latest is None:
        raise HTTPException(
            409,
            "the command is not actionable and no verified module receipt exists",
        )
    return _operation_outcome(
        state=str(latest.receipt_kind),
        operation_id=operation_id,
        replayed=None,
        receipts=receipts,
    )


def _require_signed_module_chain_projection(outcome: ProvisioningOutcome) -> None:
    """Refuse to sign a terminal pin detached from the projected module chain."""
    projected = outcome.evidence.get("module_receipts")
    if not isinstance(projected, list) or not projected:
        raise RuntimeError("module receipt projection is absent")
    previous_hash: str | None = None
    for index, item in enumerate(projected):
        if not isinstance(item, Mapping):
            raise RuntimeError("module receipt projection is malformed")
        sequence = item.get("sequence")
        receipt_hash = item.get("receipt_hash")
        predecessor = item.get("previous_receipt_hash")
        if sequence != index + 1 or predecessor != previous_hash:
            raise RuntimeError("module receipt projection is not continuous")
        if item.get("capability_instance_ref") != outcome.capability_instance_ref:
            raise RuntimeError("module receipt capability instance differs")
        if not isinstance(receipt_hash, str):
            raise RuntimeError("module receipt projection is malformed")
        previous_hash = receipt_hash
    latest = projected[-1]
    if (
        latest.get("sequence") != outcome.latest_module_receipt_sequence
        or latest.get("receipt_hash") != outcome.latest_module_receipt_hash
    ):
        raise RuntimeError("latest module receipt pin differs from projected chain")


def _require_signed_plan_receipt_projection(
    command: AuthenticatedCommand[PlanCommand], outcome: ProvisioningOutcome
) -> None:
    """Refuse to sign a PLAN receipt detached from the module-owned record."""
    projected = outcome.evidence.get("module_plan_receipt")
    if not isinstance(projected, Mapping):
        raise RuntimeError("module PLAN receipt projection is absent")
    if projected.get("command_id") != command.command_id:
        raise RuntimeError("module PLAN receipt command identity differs")
    if projected.get("request_body_digest") != command.body_sha256:
        raise RuntimeError("module PLAN receipt request body digest differs")
    if projected.get("capability_instance_ref") != command.body.capability_instance_ref:
        raise RuntimeError("module PLAN receipt capability instance differs")
    if projected.get("receipt_hash") != outcome.module_plan_receipt_hash:
        raise RuntimeError("module PLAN receipt hash differs from projection")


def _signed_provisioning_outcome(
    operation: Literal["plan", "apply", "observe", "cancel"],
    command: AuthenticatedCommand[Any],
    outcome: ProvisioningOutcome,
) -> SignedReceipt:
    body = command.body
    caller_plan_hash = body.plan_hash
    capability_instance_ref = outcome.capability_instance_ref
    if (
        capability_instance_ref is None
        or capability_instance_ref != body.capability_instance_ref
    ):
        raise RuntimeError("module capability instance differs from signed command")
    if isinstance(body, PlanCommand) and not isinstance(body, ApplyCommand):
        caller_approval_digest = None
        caller_artifact_digest = None
        if outcome.module_plan_receipt_hash is None:
            raise RuntimeError("PLAN receipt must come from verified module state")
        _require_signed_plan_receipt_projection(command, outcome)
    elif isinstance(body, ApplyCommand):
        caller_approval_digest = None
        caller_artifact_digest = None
        if any(
            value is None
            for value in (
                outcome.plan_hash,
                outcome.approval_digest,
                outcome.artifact_digest,
                outcome.config_digest,
                outcome.latest_module_receipt_sequence,
                outcome.latest_module_receipt_hash,
            )
        ):
            raise RuntimeError(
                "apply receipt pins must come from verified module state"
            )
        _require_signed_module_chain_projection(outcome)
    else:
        caller_approval_digest = body.approval_digest
        caller_artifact_digest = body.artifact_digest
        if any(
            value is None
            for value in (
                outcome.plan_hash,
                outcome.approval_digest,
                outcome.artifact_digest,
                outcome.config_digest,
                outcome.latest_module_receipt_sequence,
                outcome.latest_module_receipt_hash,
            )
        ):
            raise RuntimeError(
                "observe/cancel receipt pins must come from verified module state"
            )
        _require_signed_module_chain_projection(outcome)
    receipt = ReceiptPayload(
        receipt_contract_version="integrator.provisioning-receipt.v1",
        command_contract_version=command.contract_version,
        operation=operation,
        command_id=command.command_id,
        nonce=command.nonce,
        issuer_account_ref=command.issuer_account_ref,
        deployment_ref=body.deployment_ref,
        capability_instance_ref=capability_instance_ref,
        request_body_sha256=command.body_sha256,
        plan_hash=outcome.plan_hash or caller_plan_hash,
        approval_digest=outcome.approval_digest or caller_approval_digest,
        artifact_digest=outcome.artifact_digest or caller_artifact_digest,
        config_digest=outcome.config_digest or body.config_digest,
        outcome=outcome.state,
        operation_id=outcome.operation_id,
        replayed=outcome.replayed,
        latest_module_receipt_sequence=(outcome.latest_module_receipt_sequence),
        latest_module_receipt_hash=outcome.latest_module_receipt_hash,
        module_plan_receipt_hash=outcome.module_plan_receipt_hash,
        occurred_at=datetime.now(UTC),
        evidence=outcome.evidence,
    )
    return machine_commands.sign_receipt(receipt)


def plan_provisioning(
    engine: Engine,
    command: AuthenticatedCommand[PlanCommand],
    gateway: ProvisioningGateway,
) -> SignedReceipt:
    return _signed_provisioning_outcome(
        "plan", command, gateway.plan(engine, command.command_id, command.body)
    )


def apply_provisioning(
    engine: Engine,
    command: AuthenticatedCommand[ApplyCommand],
    gateway: ProvisioningGateway,
) -> SignedReceipt:
    return _signed_provisioning_outcome(
        "apply", command, gateway.apply(engine, command.command_id, command.body)
    )


def observe_provisioning(
    engine: Engine,
    command: AuthenticatedCommand[ObserveCommand],
    gateway: ProvisioningGateway,
) -> SignedReceipt:
    return _signed_provisioning_outcome(
        "observe", command, gateway.observe(engine, command.command_id, command.body)
    )


def cancel_provisioning(
    engine: Engine,
    command: AuthenticatedCommand[CancelCommand],
    gateway: ProvisioningGateway,
) -> SignedReceipt:
    return _signed_provisioning_outcome(
        "cancel", command, gateway.cancel(engine, command.command_id, command.body)
    )


def _record(
    db: Session,
    actor: OperatorIdentity,
    *,
    action: str,
    entity_type: str,
    entity_id: str | None,
    details: dict[str, object],
) -> None:
    """Write one assembly-owned platform audit event.

    Goes through the kernel's platform ledger directly rather than through
    `integration.record_operation`, which would prefix the action with
    `integration.` and put an undeclared code into the module's namespace.
    """
    if action not in INTEGRATOR_AUDIT_ACTIONS:  # pragma: no cover — see the test
        raise AssertionError(f"undeclared audit action {action!r}")
    write_platform_audit_event(
        db,
        actor_admin_id=actor.admin_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details={"actor": actor.label, "mechanism": actor.mechanism, **details},
    )


def _jsonable(value: Any) -> Any:
    """Serialise a module result without importing its private types.

    Deliberately structural rather than a per-type mapping: a mapping would need
    editing every time the module adds a field, and a stale mapping silently
    drops data from an operational report — the one place a reader assumes they
    are seeing everything.
    """
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {k: _jsonable(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_jsonable(v) for v in value]
    if isinstance(value, UUID):
        return str(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def _jsonable_mapping(value: Any) -> dict[str, Any]:
    """`_jsonable` for a value that must serialise to an object.

    A checked narrowing rather than a `cast`. The module's operations return
    dataclasses today, so this always holds — but `cast` would assert it and a
    future return type that serialises to a list would then reach the client as
    a JSON array from a handler typed as returning an object, which fails at the
    consumer instead of here.
    """
    serialised = _jsonable(value)
    if not isinstance(serialised, dict):
        raise TypeError(
            f"expected an object-shaped result, got {type(value).__name__} "
            f"serialising to {type(serialised).__name__}"
        )
    return serialised


def _repaired(row: Any) -> dict[str, Any]:
    """What a repair command returns to the operator.

    An EXPLICIT projection, not `_jsonable`. The module's repair commands
    return the ORM row, which is neither a dataclass nor a mapping — the
    structural serialiser falls through to `str()` on it, and
    `_jsonable_mapping` then raises `TypeError` from inside a handler that has
    already committed. Both replay routes did exactly that.

    Explicit is also the right answer on its own terms: `InboxReceipt` and
    `DeliveryAttempt` carry `payload_json`, and a repair acknowledgement is no
    place to echo a provider payload back over HTTP.
    """
    return {
        "id": str(row.id),
        "state": row.state,
        "attempt_count": row.attempt_count,
    }


def _uuid(raw: str, field: str) -> UUID:
    try:
        return UUID(raw)
    except ValueError as exc:
        # Counted by REASON, never by value. `raw` reaches the caller who sent
        # it — it must not reach a metric label, where it would be stored for a
        # year and rendered on every dashboard that groups by it.
        telemetry.counters.record_refusal("malformed_identifier")
        raise HTTPException(422, f"{field} is not a UUID: {raw!r}") from exc


def installed_connectors() -> dict[str, Any]:
    """What this deployment can actually dispatch to.

    Entry-point discovery, so the answer is the set of INSTALLED connector
    distributions — not a list this assembly maintains. A connector appears here
    by being installed, which is the only mechanism; there is no registration
    call and no name hardcoded anywhere in this repository.
    """
    registry = integration.discover()
    plugins = getattr(registry, "plugins", ())
    return {
        "spi_version": str(integration.CURRENT_SPI_VERSION),
        "entry_point_group": integration.ENTRY_POINT_GROUP,
        "count": len(plugins),
        "connectors": _jsonable(
            [getattr(p, "manifest", p) for p in plugins],
        ),
    }


def health_report(engine: Engine) -> dict[str, Any]:
    with Session(engine) as db:
        return _jsonable_mapping(integration.health_report(db))


# ── Secret material ─────────────────────────────────────────────────────────


def secret_status() -> dict[str, Any]:
    """Which references this process holds material for. NAMES ONLY.

    There is no accessor anywhere in this deployment that returns a held value,
    and this is the closest thing to one on purpose: an operator diagnosing a
    refused enablement needs to know whether the reference resolved, and never
    needs to see what it resolved to.
    """
    return secret_loading.last_report().as_dict()


def refresh_secret_material(
    engine: Engine, actor: OperatorIdentity, reason: str
) -> dict[str, Any]:
    """Re-read every stored reference. THE rotation operation (ADR-0009).

    Explicit rather than a TTL: a rotation takes effect when an operator says
    so. `dotmac_kernel.secret_sources` keeps the working set if the reload
    fails, so a mount that vanished mid-rotation leaves a working process
    working — and this function propagates the failure so the operator learns
    the rotation did not land.
    """
    report = secret_loading.refresh()
    payload = report.as_dict()
    with Session(engine) as db:
        _record(
            db,
            actor,
            action="integrator.secrets.refreshed",
            entity_type="secret_material",
            entity_id=None,
            details={
                "reason": reason,
                # References and counts. A held VALUE has no path to this row.
                "held_count": len(report.held),
                "unresolved": sorted(report.unresolved),
            },
        )
        db.commit()
    return payload


# ── Enablement — the gate the resolver exists for ───────────────────────────


def enable_installation(
    engine: Engine, installation_id: str, actor: OperatorIdentity, reason: str
) -> dict[str, Any]:
    """Enable an installation after materialising its referenced secrets.

    This is the whole reason the held-secret resolver comes first.
    `lifecycle.enable` refuses to enable anything without a LIVE
    `validate_connection`, and `validate_connection` takes VALUES — so until
    something could turn `{"api_key": "bao://…"}` into material, no connector in
    this fleet could be enabled at all.

    Order matters: material is checked BEFORE the connector is asked to
    validate. A missing credential produces a refusal naming the reference,
    rather than a provider-side authentication failure that reads like the
    provider is down.
    """
    identifier = _uuid(installation_id, "installation_id")
    with Session(engine) as db:
        installation = db.get(integration.ConnectorInstallation, identifier)
        if installation is None:
            raise HTTPException(404, f"no installation {installation_id}")

        revision = (
            db.get(
                integration.ConnectorConfigRevision,
                installation.current_config_revision_id,
            )
            if installation.current_config_revision_id is not None
            else None
        )
        if revision is None:
            raise HTTPException(
                409,
                "installation has no configuration revision; there is nothing "
                "to validate a connection against",
            )

        secret_refs: dict[str, str] = {
            str(name): str(reference)
            for name, reference in (revision.secret_refs or {}).items()
        }
        absent = missing_references(secret_refs)
        if absent:
            _record(
                db,
                actor,
                action="integrator.installation.enable_refused",
                entity_type="connector_installation",
                entity_id=str(installation.id),
                details={
                    "reason": reason,
                    "refusal": "material_not_held",
                    "missing": sorted(absent.values()),
                },
            )
            db.commit()
            raise HTTPException(
                409,
                "referenced secret material is not held: "
                f"{sorted(absent.values())}. Material loads at startup and on "
                "an explicit POST /operations/secrets/refresh (ADR-0009); "
                "enablement is refused rather than attempted without it",
            )

        # A FRESH `dict[str, object]`, not the resolver's `dict[str, str]`.
        # `lifecycle.enable` takes `dict[str, object] | None` and `dict` is
        # invariant, so handing it the resolver's mapping does not type — and a
        # `cast` would be the wrong repair, because the widened parameter says
        # the module may put a non-`str` into whatever it is given. Copying is
        # what makes that its business rather than a mutation of the assembly's
        # resolved set. Surfaced by the a1 -> a3 pin bump, which widened the
        # parameter; there is no behaviour change.
        secrets: dict[str, object] = dict(resolve_secrets(secret_refs))
        registry = integration.discover()
        try:
            integration.enable(
                db,
                installation,
                registry=registry,
                secrets=secrets,
                actor=actor.label,
            )
        except integration.LifecycleError as exc:
            detail = redact(str(exc))
            reported = installation.state_reason or ""
            if redact(reported) != reported:
                # The connector put held material into its own diagnostic, and
                # the module already flushed it onto the installation row. This
                # assembly owns the transaction, so the row does not land.
                db.rollback()
                raise HTTPException(
                    502,
                    "the connector's validation diagnostic contained secret "
                    "material; the failure was NOT recorded, because a "
                    "configuration row is immutable and reaches every backup. "
                    "Fix the connector: a diagnostic may name a credential, "
                    "never quote one",
                ) from exc
            _record(
                db,
                actor,
                action="integrator.installation.enable_refused",
                entity_type="connector_installation",
                entity_id=str(installation.id),
                details={
                    "reason": reason,
                    "refusal": "validation_failed",
                    "detail": detail,
                },
            )
            db.commit()
            raise HTTPException(409, detail) from exc
        except integration.InvalidManifestError as exc:
            # The connector distribution named by the installation is not
            # installed in this runtime. Evidenced like the other refusals: an
            # operator whose enablement failed because the deploy shipped
            # without the connector needs that in the trail, not only in a
            # response body they may not have kept.
            _record(
                db,
                actor,
                action="integrator.installation.enable_refused",
                entity_type="connector_installation",
                entity_id=str(installation.id),
                details={
                    "reason": reason,
                    "refusal": "connector_not_installed",
                    "connector_key": installation.connector_key,
                },
            )
            db.commit()
            raise HTTPException(409, str(exc)) from exc

        _record(
            db,
            actor,
            action="integrator.installation.enabled",
            entity_type="connector_installation",
            entity_id=str(installation.id),
            details={
                "reason": reason,
                "connector_key": installation.connector_key,
                "config_revision": str(revision.id),
                # References, so the trail records WHICH material authorised
                # this enablement without recording the material.
                "secret_references": sorted(secret_refs.values()),
            },
        )
        db.commit()
        return {
            "id": str(installation.id),
            "connector_key": installation.connector_key,
            "state": installation.state,
            "enabled_at": (
                installation.enabled_at.isoformat()
                if installation.enabled_at is not None
                else None
            ),
        }


# ── Repair ──────────────────────────────────────────────────────────────────


def release_expired_leases(
    engine: Engine, actor: OperatorIdentity, reason: str
) -> dict[str, Any]:
    """Sweep leases whose holder died, at an operator's request.

    Committed here because the module's operation is a mutation and the module
    does not own the transaction — `dotmac_kernel.db` holds that authority in the
    Starter, and in this deployment the assembly does.

    `reason` is carried in this assembly's own audit detail because the module's
    `leases.released` event records the count and the ids but has no `reason`
    field — a gap raised with the module rather than papered over here.
    """
    with Session(engine) as db:
        released = integration.release_expired_leases(db, actor_admin_id=actor.admin_id)
        db.commit()
    return {"released": released, "reason": reason, "actor": actor.label}


def sweep_expired_leases(engine: Engine) -> int:
    """The TIMED sweep. No actor, because a schedule is not a person.

    Separate from `release_expired_leases` rather than an optional argument:
    the difference between "the deployment reclaimed a dead worker's lease on
    its timer" and "someone reclaimed it" is exactly what a reader of the trail
    needs, and a default parameter hides which one happened.
    """
    with Session(engine) as db:
        released = integration.release_expired_leases(db)
        db.commit()
    return released


def replay_delivery(
    engine: Engine, delivery_id: str, actor: OperatorIdentity, reason: str
) -> dict[str, Any]:
    """Replay one delivery.

    `reason` is required by the module and passed through unaltered. An assembly
    that supplied a default here ("replayed via API") would put a fabricated
    justification into the audit record of a manual intervention, which is worse
    than having no record.
    """
    identifier = _uuid(delivery_id, "delivery_id")
    with Session(engine) as db:
        delivery = db.get(integration.DeliveryAttempt, identifier)
        if delivery is None:
            telemetry.counters.record_refusal("not_found")
            raise HTTPException(404, f"no delivery {delivery_id}")
        try:
            replayed = integration.replay_delivery(
                db, delivery, actor_admin_id=actor.admin_id, reason=reason
            )
        except integration.NotRepairable as exc:
            telemetry.counters.record_refusal("not_repairable")
            raise HTTPException(409, str(exc)) from exc
        db.commit()
        return _repaired(replayed)


def replay_receipt(
    engine: Engine, receipt_id: str, actor: OperatorIdentity, reason: str
) -> dict[str, Any]:
    identifier = _uuid(receipt_id, "receipt_id")
    with Session(engine) as db:
        receipt = db.get(integration.InboxReceipt, identifier)
        if receipt is None:
            telemetry.counters.record_refusal("not_found")
            raise HTTPException(404, f"no receipt {receipt_id}")
        try:
            replayed = integration.replay_receipt(
                db, receipt, actor_admin_id=actor.admin_id, reason=reason
            )
        except integration.NotRepairable as exc:
            telemetry.counters.record_refusal("not_repairable")
            raise HTTPException(409, str(exc)) from exc
        db.commit()
        return _repaired(replayed)
