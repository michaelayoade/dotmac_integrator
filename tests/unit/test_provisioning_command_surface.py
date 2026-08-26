from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from dotmac_integrator import operations
from dotmac_integrator.assembly import create_app
from dotmac_integrator.machine_commands import (
    ApplyCommand,
    ApplyCommandEnvelope,
    ApprovalGrant,
    ApprovedCommandTemplate,
    CancelCommand,
    CancelCommandEnvelope,
    CapabilityOperationPin,
    ObserveCommand,
    ObserveCommandEnvelope,
    PlanCommand,
    PlanCommandEnvelope,
    ProvisioningStep,
    body_digest,
    canonical_command_bytes,
    command_template_digest,
    install_crypto,
    verify_receipt,
)
from dotmac_integrator.operations import ProvisioningGateway, ProvisioningOutcome
from dotmac_integrator.settings import Settings
from tests.support import build_settings

NOW = datetime.now(UTC)
ASSIGNMENT_REF = "env://INTEGRATOR_SECRET_ISSUER_ASSIGNMENTS"
SAVED_PLAN_ID = UUID("11111111-1111-4111-8111-111111111111")
APPROVAL_REQUEST_ID = UUID("22222222-2222-4222-8222-222222222222")
PLAN_VALIDATION_RECEIPT_ID = UUID("77777777-7777-4777-8777-777777777777")


def _assignments() -> str:
    return json.dumps(
        {
            "contract_version": "integrator.command-issuer-assignments.v2",
            "assignments": [
                {
                    "key_id": "vendor-key",
                    "account_ref": "vendor-account-1",
                    "deployment_instances": [
                        {
                            "deployment_ref": "deployment-1",
                            "capability_instance_refs": [
                                "managed.service-primary",
                                "primary",
                            ],
                        }
                    ],
                }
            ],
        }
    )


def _capability_operations() -> tuple[CapabilityOperationPin, ...]:
    return tuple(
        CapabilityOperationPin(
            operation_code=operation_code,
            input_schema_ref=f"schema:provisioning/{operation_code}-request@v1",
            input_schema_digest="sha256:" + input_digit * 64,
            output_schema_ref=f"schema:provisioning/{operation_code}-result@v1",
            output_schema_digest="sha256:" + output_digit * 64,
        )
        for operation_code, input_digit, output_digit in (
            ("apply", "1", "2"),
            ("cancel", "3", "4"),
            ("observe", "5", "6"),
            ("plan", "7", "8"),
        )
    )


def _static_fields(binding_id: UUID) -> dict[str, object]:
    return {
        "deployment_ref": "deployment-1",
        "desired_state_revision": 7,
        "desired_state_version_id": UUID("55555555-5555-4555-8555-555555555555"),
        "desired_state_hash": "sha256:" + "a" * 64,
        "saved_plan_id": SAVED_PLAN_ID,
        "profile_version_id": UUID("66666666-6666-4666-8666-666666666666"),
        "profile_code": "managed.application",
        "profile_version": 3,
        "profile_schema_version": 1,
        "profile_content_hash": "sha256:" + "6" * 64,
        "command_schema_version": "integrator.provisioning-command.v1",
        "capability_id": "managed.service.provision.v1",
        "capability_instance_ref": "primary",
        "capability_owner_code": "vendor.managed-services",
        "capability_code": "managed.service.provision",
        "capability_schema_version": 1,
        "capability_contract_attestation_id": UUID(
            "88888888-8888-4888-8888-888888888888"
        ),
        "capability_contract_digest": "sha256:" + "5" * 64,
        "capability_operations": _capability_operations(),
        "capability_binding_id": binding_id,
        "binding_ref": binding_id,
        "installation_id": UUID("33333333-3333-4333-8333-333333333333"),
        "installation_ref": "managed-services-primary",
        "connector_key": "conformance.fake",
        "connector_version": "1.2.3",
        "connector_manifest_digest": "sha256:" + "8" * 64,
        "connector_configuration_revision_id": UUID(
            "44444444-4444-4444-8444-444444444444"
        ),
        "configuration_snapshot_ref": "configuration-snapshot-7",
        "configuration_schema_version": 1,
        "configuration_hash": "sha256:" + "4" * 64,
        "artifact_digest": "sha256:" + "b" * 64,
        "component_artifact_digest": "sha256:" + "7" * 64,
        "config_digest": "sha256:" + "c" * 64,
        "execution_policy_digest": (
            "sha256:c8b475b054fffe618dc26b02ca8f8fcc3" "ca4da13bc5670449343497bb475b536"
        ),
    }


def _approval_evidence_fields() -> dict[str, object]:
    return {
        "approval_request_id": APPROVAL_REQUEST_ID,
        "approval_request_binding_hash": "sha256:" + "0" * 64,
        "plan_command_id": "plan-command-0001",
        "plan_validation_receipt_id": PLAN_VALIDATION_RECEIPT_ID,
        "plan_validation_receipt_digest": "sha256:" + "1" * 64,
        "plan_validation_request_body_digest": "sha256:" + "2" * 64,
        "module_plan_receipt_hash": "sha256:" + "3" * 64,
    }


def _module_receipts() -> list[dict[str, object]]:
    return [
        {
            "sequence": 1,
            "capability_instance_ref": "primary",
            "previous_receipt_hash": None,
            "receipt_hash": "sha256:" + "0" * 64,
        },
        {
            "sequence": 2,
            "capability_instance_ref": "primary",
            "previous_receipt_hash": "sha256:" + "0" * 64,
            "receipt_hash": "sha256:" + "1" * 64,
        },
    ]


def _raw_private(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    ).decode("ascii")


def _raw_public(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode("ascii")


@dataclass
class RecordingGateway(ProvisioningGateway):
    seen: list[tuple[str, str, object]] = field(default_factory=list)

    def plan(
        self, engine: Engine, command_id: str, body: PlanCommand
    ) -> ProvisioningOutcome:
        self.seen.append(("plan", command_id, body))
        receipt_hash = "sha256:" + "9" * 64
        return ProvisioningOutcome(
            state="planned",
            capability_instance_ref=body.capability_instance_ref,
            plan_hash=body.plan_hash,
            config_digest=body.config_digest,
            module_plan_receipt_hash=receipt_hash,
            evidence={
                "module_plan_receipt": {
                    "command_id": command_id,
                    "command_fingerprint": "sha256:" + "8" * 64,
                    "capability_instance_ref": body.capability_instance_ref,
                    "request_body_digest": body_digest(body),
                    "result_digest": "sha256:" + "7" * 64,
                    "receipt_hash": receipt_hash,
                }
            },
        )

    def apply(
        self, engine: Engine, command_id: str, body: ApplyCommand
    ) -> ProvisioningOutcome:
        self.seen.append(("apply", command_id, body))
        return ProvisioningOutcome(
            state="pending",
            capability_instance_ref=body.capability_instance_ref,
            operation_id=UUID("f818c730-a0a2-4ace-a50d-91ead9c9f1ed"),
            replayed=False,
            plan_hash=body.plan_hash,
            approval_digest=body.approval.digest,
            artifact_digest=body.artifact_digest,
            config_digest=body.config_digest,
            evidence={"module_receipts": _module_receipts()},
            latest_module_receipt_sequence=2,
            latest_module_receipt_hash="sha256:" + "1" * 64,
        )

    def observe(
        self, engine: Engine, command_id: str, body: ObserveCommand
    ) -> ProvisioningOutcome:
        self.seen.append(("observe", command_id, body))
        return ProvisioningOutcome(
            state="observing", capability_instance_ref=body.capability_instance_ref
        )

    def cancel(
        self, engine: Engine, command_id: str, body: CancelCommand
    ) -> ProvisioningOutcome:
        self.seen.append(("cancel", command_id, body))
        return ProvisioningOutcome(
            state="cancelled", capability_instance_ref=body.capability_instance_ref
        )


def _settings() -> Settings:
    return build_settings(
        command_surface_enabled=True,
        command_audience="dotmac-integrator:test",
        command_public_key_refs="vendor-key=env://INTEGRATOR_SECRET_VENDOR_PUB",
        command_issuer_assignments_ref=ASSIGNMENT_REF,
        receipt_signing_key_id="integrator-receipt-1",
        receipt_signing_private_key_ref=("env://INTEGRATOR_SECRET_RECEIPT_PRIVATE"),
    )


def _sign(
    envelope: (
        PlanCommandEnvelope
        | ApplyCommandEnvelope
        | ObserveCommandEnvelope
        | CancelCommandEnvelope
    ),
    key: Ed25519PrivateKey,
) -> dict[str, object]:
    signature = (
        base64.urlsafe_b64encode(key.sign(canonical_command_bytes(envelope)))
        .rstrip(b"=")
        .decode("ascii")
    )
    return cast(
        dict[str, object],
        envelope.model_copy(update={"signature": signature}).model_dump(mode="json"),
    )


def _crypto() -> tuple[Ed25519PrivateKey, Ed25519PrivateKey]:
    command_key = Ed25519PrivateKey.generate()
    receipt_key = Ed25519PrivateKey.generate()
    install_crypto(
        _settings(),
        {
            "env://INTEGRATOR_SECRET_VENDOR_PUB": _raw_public(command_key),
            ASSIGNMENT_REF: _assignments(),
            "env://INTEGRATOR_SECRET_RECEIPT_PRIVATE": _raw_private(receipt_key),
        },
    )
    return command_key, receipt_key


def _step() -> ProvisioningStep:
    return ProvisioningStep(
        step_key="identity-client",
        endpoint_code="managed.service.provision.v1",
        depends_on=(),
        input={"desired_ref": "deployment-1"},
    )


def test_default_gateway_refuses_boot_without_the_complete_module_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        operations,
        "integration",
        SimpleNamespace(__version__="0.1.0a4"),
    )

    with pytest.raises(
        RuntimeError,
        match=r"dotmac_integration\.prepare_provisioning_plan",
    ):
        create_app(_settings())


def test_plan_route_is_a_typed_delegate_and_returns_a_signed_receipt() -> None:
    command_key, receipt_key = _crypto()
    plan = PlanCommand(
        deployment_ref="deployment-1",
        capability_id="managed.service.provision.v1",
        capability_instance_ref="primary",
        capability_binding_id=UUID("d9e93437-fb89-4db6-8a53-bf85beb26a33"),
        plan_hash="sha256:" + "a" * 64,
        config_digest="sha256:" + "c" * 64,
        steps=(_step(),),
    )
    envelope = PlanCommandEnvelope(
        contract_version="integrator.provisioning-command.v1",
        key_id="vendor-key",
        audience="dotmac-integrator:test",
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=2),
        command_id="plan-command-1",
        nonce="plan-command-1",
        body_sha256=body_digest(plan),
        signature="unsigned",
        body=plan,
    )
    gateway = RecordingGateway()
    app = create_app(_settings(), provisioning_gateway=gateway)
    response = TestClient(app).post(
        "/commands/provisioning/plan", json=_sign(envelope, command_key)
    )

    assert response.status_code == 200, response.text
    signed = response.json()
    assert signed["receipt"]["plan_hash"] == plan.plan_hash
    assert signed["receipt"]["artifact_digest"] is None
    assert signed["receipt"]["config_digest"] == plan.config_digest
    assert signed["receipt"]["issuer_account_ref"] == "vendor-account-1"
    assert signed["receipt"]["deployment_ref"] == "deployment-1"
    assert signed["receipt"]["capability_instance_ref"] == "primary"
    assert signed["receipt"]["module_plan_receipt_hash"] == ("sha256:" + "9" * 64)
    verify_receipt(signed, receipt_key.public_key())
    assert gateway.seen == [("plan", "plan-command-1", plan)]


def test_apply_passes_exact_approval_and_replay_identity_to_the_gateway() -> None:
    command_key, receipt_key = _crypto()
    plan_hash = "sha256:" + "a" * 64
    binding_id = UUID("d9e93437-fb89-4db6-8a53-bf85beb26a33")
    steps = (_step(),)
    template_digest = command_template_digest(
        ApprovedCommandTemplate.model_validate(
            {
                **_static_fields(binding_id),
                "prerequisite_capability_binding_ids": (),
                "prerequisite_evidence_bindings": (),
                "steps": steps,
            }
        )
    )
    approval = ApprovalGrant.model_validate(
        {
            "grant_ref": "approval-1",
            **_approval_evidence_fields(),
            "saved_plan_id": SAVED_PLAN_ID,
            "approved_plan_hash": plan_hash,
            "approved_command_template_digest": template_digest,
            "digest": "sha256:" + "d" * 64,
            "expires_at": NOW + timedelta(minutes=10),
            "verified_at": NOW,
        }
    )
    body = ApplyCommand.model_validate(
        {
            **_static_fields(binding_id),
            **_approval_evidence_fields(),
            "plan_hash": plan_hash,
            "expected_plan_hash": plan_hash,
            "approved_command_template_digest": template_digest,
            "prerequisite_capability_binding_ids": (),
            "prerequisite_evidence_bindings": (),
            "prerequisite_receipt_pins": (),
            "approval": approval,
            "steps": steps,
        }
    )
    envelope = ApplyCommandEnvelope(
        contract_version="integrator.provisioning-command.v1",
        key_id="vendor-key",
        audience="dotmac-integrator:test",
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=2),
        command_id="apply-command-1",
        nonce="apply-command-1",
        body_sha256=body_digest(body),
        signature="unsigned",
        body=body,
    )
    gateway = RecordingGateway()
    app = create_app(_settings(), provisioning_gateway=gateway)
    response = TestClient(app).post(
        "/commands/provisioning/apply", json=_sign(envelope, command_key)
    )

    assert response.status_code == 200, response.text
    signed = response.json()
    assert signed["receipt"]["approval_digest"] == approval.digest
    assert signed["receipt"]["operation_id"] == "f818c730-a0a2-4ace-a50d-91ead9c9f1ed"
    assert signed["receipt"]["replayed"] is False
    assert signed["receipt"]["latest_module_receipt_sequence"] == 2
    assert signed["receipt"]["latest_module_receipt_hash"] == ("sha256:" + "1" * 64)
    verify_receipt(signed, receipt_key.public_key())
    assert gateway.seen == [("apply", "apply-command-1", body)]


def test_invalid_signature_never_reaches_the_gateway() -> None:
    command_key, _ = _crypto()
    another_key = Ed25519PrivateKey.generate()
    plan = PlanCommand(
        deployment_ref="deployment-1",
        capability_id="managed.service.provision.v1",
        capability_instance_ref="primary",
        capability_binding_id=UUID("d9e93437-fb89-4db6-8a53-bf85beb26a33"),
        plan_hash="sha256:" + "a" * 64,
        config_digest="sha256:" + "c" * 64,
        steps=(_step(),),
    )
    envelope = PlanCommandEnvelope(
        contract_version="integrator.provisioning-command.v1",
        key_id="vendor-key",
        audience="dotmac-integrator:test",
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=2),
        command_id="plan-command-1",
        nonce="plan-command-1",
        body_sha256=body_digest(plan),
        signature="unsigned",
        body=plan,
    )
    gateway = RecordingGateway()
    app = create_app(_settings(), provisioning_gateway=gateway)
    response = TestClient(app).post(
        "/commands/provisioning/plan", json=_sign(envelope, another_key)
    )
    assert response.status_code == 401
    assert gateway.seen == []
    assert command_key is not another_key


def test_unassigned_plan_is_refused_before_the_gateway() -> None:
    command_key, _ = _crypto()
    plan = PlanCommand(
        deployment_ref="deployment-outside-assignment",
        capability_id="managed.service.provision.v1",
        capability_instance_ref="primary",
        capability_binding_id=UUID("d9e93437-fb89-4db6-8a53-bf85beb26a33"),
        plan_hash="sha256:" + "a" * 64,
        config_digest="sha256:" + "c" * 64,
        steps=(_step(),),
    )
    envelope = PlanCommandEnvelope(
        contract_version="integrator.provisioning-command.v1",
        key_id="vendor-key",
        audience="dotmac-integrator:test",
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=2),
        command_id="unassigned-plan-command-1",
        nonce="unassigned-plan-command-1",
        body_sha256=body_digest(plan),
        signature="unsigned",
        body=plan,
    )
    gateway = RecordingGateway()
    response = TestClient(create_app(_settings(), provisioning_gateway=gateway)).post(
        "/commands/provisioning/plan", json=_sign(envelope, command_key)
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "command issuer is not assigned to deployment capability instance"
    )
    assert gateway.seen == []


def test_same_deployment_unassigned_instance_is_refused_before_the_gateway() -> None:
    command_key, _ = _crypto()
    plan = PlanCommand(
        deployment_ref="deployment-1",
        capability_id="managed.service.provision.v1",
        capability_instance_ref="secondary",
        capability_binding_id=UUID("d9e93437-fb89-4db6-8a53-bf85beb26a33"),
        plan_hash="sha256:" + "a" * 64,
        config_digest="sha256:" + "c" * 64,
        steps=(_step(),),
    )
    envelope = PlanCommandEnvelope(
        contract_version="integrator.provisioning-command.v1",
        key_id="vendor-key",
        audience="dotmac-integrator:test",
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=2),
        command_id="unassigned-instance-command-1",
        nonce="unassigned-instance-command-1",
        body_sha256=body_digest(plan),
        signature="unsigned",
        body=plan,
    )
    gateway = RecordingGateway()
    response = TestClient(create_app(_settings(), provisioning_gateway=gateway)).post(
        "/commands/provisioning/plan", json=_sign(envelope, command_key)
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "command issuer is not assigned to deployment capability instance"
    )
    assert gateway.seen == []


def test_assignment_guard_covers_apply_observe_and_cancel_before_gateway() -> None:
    command_key, _ = _crypto()
    fixture = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "docs"
            / "fixtures"
            / "provisioning_apply_command_v1.json"
        ).read_text(encoding="utf-8")
    )
    apply = ApplyCommand.model_validate(fixture["body"])
    observe = ObserveCommand(
        deployment_ref="deployment-outside-assignment",
        capability_instance_ref="primary",
        operation_id=UUID("f818c730-a0a2-4ace-a50d-91ead9c9f1ed"),
        step_key="identity-client",
        provider_operation_ref="provider-operation-1",
        plan_hash="sha256:" + "a" * 64,
        approval_digest="sha256:" + "d" * 64,
        artifact_digest="sha256:" + "b" * 64,
        config_digest="sha256:" + "c" * 64,
    )
    cancel = CancelCommand.model_validate(
        {**observe.model_dump(mode="json"), "reason": "approval withdrawn"}
    )
    cases = (
        ("apply", ApplyCommandEnvelope, apply),
        ("observe", ObserveCommandEnvelope, observe),
        ("cancel", CancelCommandEnvelope, cancel),
    )
    gateway = RecordingGateway()
    client = TestClient(create_app(_settings(), provisioning_gateway=gateway))
    for operation, envelope_type, body in cases:
        unsigned = envelope_type.model_validate(
            {
                "contract_version": "integrator.provisioning-command.v1",
                "key_id": "vendor-key",
                "audience": "dotmac-integrator:test",
                "issued_at": NOW - timedelta(seconds=1),
                "expires_at": NOW + timedelta(minutes=2),
                "command_id": f"unassigned-{operation}-command-1",
                "nonce": f"unassigned-{operation}-command-1",
                "body_sha256": body_digest(body),
                "signature": "unsigned",
                "body": body.model_dump(mode="json"),
            }
        )
        response = client.post(
            f"/commands/provisioning/{operation}",
            json=_sign(unsigned, command_key),
        )
        assert response.status_code == 401
        assert response.json()["detail"] == (
            "command issuer is not assigned to deployment capability instance"
        )

    assert gateway.seen == []
