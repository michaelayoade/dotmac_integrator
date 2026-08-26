from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID

import dotmac_integration as integration
import pytest
from sqlalchemy.engine import Engine

from dotmac_integrator import operations
from dotmac_integrator.machine_commands import (
    ApplyCommand,
    ApprovalGrant,
    ApprovedCommandTemplate,
    CapabilityOperationPin,
    ObserveCommand,
    PlanCommand,
    PrerequisiteEvidenceBinding,
    PrerequisiteReceiptPin,
    ProvisioningStep,
    body_digest,
    command_template_digest,
)

SAVED_PLAN_ID = UUID("11111111-1111-4111-8111-111111111111")
APPROVAL_REQUEST_ID = UUID("22222222-2222-4222-8222-222222222222")
PLAN_VALIDATION_RECEIPT_ID = UUID("77777777-7777-4777-8777-777777777777")


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
        "artifact_digest": "sha256:" + "4" * 64,
        "component_artifact_digest": "sha256:" + "7" * 64,
        "config_digest": "sha256:" + "5" * 64,
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


class _SessionHarness:
    def __init__(self) -> None:
        self.active = 0
        self.commits = 0

    def session(self, engine: object) -> _FakeSession:
        return _FakeSession(self)


class _FakeSession:
    def __init__(self, harness: _SessionHarness) -> None:
        self.harness = harness

    def __enter__(self) -> _FakeSession:
        self.harness.active += 1
        return self

    def __exit__(self, *args: object) -> None:
        self.harness.active -= 1

    def commit(self) -> None:
        self.harness.commits += 1


def _receipt() -> SimpleNamespace:
    return SimpleNamespace(
        sequence=2,
        receipt_kind="observation_succeeded",
        step_key="identity-client",
        provider_operation_ref="provider-operation-1",
        previous_receipt_hash="sha256:" + "0" * 64,
        receipt_hash="sha256:" + "1" * 64,
        plan_hash="sha256:" + "2" * 64,
        capability_instance_ref="primary",
        connector_key="installed-connector",
        connector_version="1.2.3",
        manifest_digest="3" * 64,
        artifact_digest="sha256:" + "4" * 64,
        config_digest="sha256:" + "5" * 64,
        approval_digest="sha256:" + "6" * 64,
        evidence={"provider_evidence_digest": "sha256:" + "7" * 64},
    )


def test_plan_uses_immutable_module_receipt_and_invokes_without_a_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _SessionHarness()
    seen: dict[str, object] = {}
    body = PlanCommand(
        deployment_ref="deployment-1",
        capability_id="managed.service.provision.v1",
        capability_instance_ref="primary",
        capability_binding_id=UUID("d9e93437-fb89-4db6-8a53-bf85beb26a33"),
        plan_hash="sha256:" + "2" * 64,
        config_digest="sha256:" + "5" * 64,
        steps=(
            ProvisioningStep(
                step_key="identity-client",
                endpoint_code="managed.service.provision.v1",
            ),
        ),
    )

    def prepare(db: object, **values: object) -> SimpleNamespace:
        assert harness.active == 1
        seen["prepare"] = values
        return SimpleNamespace(command_id="plan-command-1")

    def invoke(prepared: object, **values: object) -> SimpleNamespace:
        assert harness.active == 0, "connector I/O ran with a session in scope"
        seen["invoke"] = values
        return SimpleNamespace(status="succeeded")

    def settle(db: object, **values: object) -> None:
        assert harness.active == 1
        seen["settle"] = values

    def read_receipt(db: object, **values: object) -> SimpleNamespace:
        assert harness.active == 1
        seen["read"] = values
        return SimpleNamespace(
            command_id="plan-command-1",
            command_fingerprint="sha256:" + "6" * 64,
            capability_instance_ref="primary",
            request_body_digest=body_digest(body),
            result_digest="sha256:" + "7" * 64,
            receipt_hash="sha256:" + "8" * 64,
        )

    symbols: dict[str, Any] = {
        "ProvisionStep": lambda **values: SimpleNamespace(**values),
        "prepare_provisioning_plan": prepare,
        "invoke_prepared_plan": invoke,
        "settle_provisioning_plan": settle,
        "read_provisioning_plan_receipt": read_receipt,
    }
    monkeypatch.setattr(operations, "Session", harness.session)
    monkeypatch.setattr(operations, "_module_symbol", symbols.__getitem__)
    monkeypatch.setattr(integration, "discover", lambda: object())

    outcome = operations.ModuleProvisioningGateway().plan(
        cast(Engine, object()), "plan-command-1", body
    )

    prepare_values = cast(dict[str, object], seen["prepare"])
    assert prepare_values["request_body_digest"] == body_digest(body)
    assert prepare_values["capability_instance_ref"] == body.capability_instance_ref
    assert seen["read"] == {"command_id": "plan-command-1"}
    assert harness.commits == 2
    assert outcome.module_plan_receipt_hash == "sha256:" + "8" * 64
    assert outcome.evidence["module_plan_receipt"] == {
        "command_id": "plan-command-1",
        "command_fingerprint": "sha256:" + "6" * 64,
        "capability_instance_ref": "primary",
        "request_body_digest": body_digest(body),
        "result_digest": "sha256:" + "7" * 64,
        "receipt_hash": "sha256:" + "8" * 64,
    }


def test_observe_checks_every_expected_pin_and_invokes_without_a_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _SessionHarness()
    seen: dict[str, object] = {}
    operation_id = UUID("e8216c0a-6249-4704-a327-47bfc343904d")

    def expected_type(**values: object) -> SimpleNamespace:
        seen["expected"] = values
        return SimpleNamespace(**values)

    def prepare(db: object, **values: object) -> SimpleNamespace:
        assert harness.active == 1
        seen["prepare"] = values
        return SimpleNamespace(command_id=values["command_id"])

    def invoke(prepared: object, **values: object) -> SimpleNamespace:
        assert harness.active == 0, "connector I/O ran with a session in scope"
        seen["invoke"] = values
        return SimpleNamespace(status="succeeded")

    def settle(db: object, **values: object) -> SimpleNamespace:
        assert harness.active == 1
        seen["settle"] = values
        return SimpleNamespace(state="succeeded")

    def read_receipts(db: object, **values: object) -> tuple[SimpleNamespace, ...]:
        assert harness.active == 1
        return (_receipt(),)

    symbols: dict[str, Any] = {
        "ExpectedProvisioningPin": expected_type,
        "prepare_next_observation": prepare,
        "invoke_prepared_observation": invoke,
        "settle_observation": settle,
        "read_provisioning_receipts": read_receipts,
    }
    monkeypatch.setattr(operations, "Session", harness.session)
    monkeypatch.setattr(operations, "_module_symbol", symbols.__getitem__)
    monkeypatch.setattr(integration, "discover", lambda: object())

    body = ObserveCommand(
        deployment_ref="deployment-1",
        capability_instance_ref="primary",
        operation_id=operation_id,
        step_key="identity-client",
        provider_operation_ref="external-operation-1",
        plan_hash="sha256:" + "2" * 64,
        approval_digest="sha256:" + "6" * 64,
        artifact_digest="sha256:" + "4" * 64,
        config_digest="sha256:" + "5" * 64,
    )
    engine = cast(Engine, object())
    outcome = operations.ModuleProvisioningGateway().observe(
        engine, "observe-command-1", body
    )

    assert seen["expected"] == {
        "deployment_ref": body.deployment_ref,
        "capability_instance_ref": body.capability_instance_ref,
        "step_key": body.step_key,
        "provider_operation_ref": body.provider_operation_ref,
        "plan_hash": body.plan_hash,
        "artifact_digest": body.artifact_digest,
        "config_digest": body.config_digest,
        "approval_digest": body.approval_digest,
    }
    assert harness.commits == 2
    assert outcome.plan_hash == _receipt().plan_hash
    assert outcome.artifact_digest == _receipt().artifact_digest
    assert outcome.config_digest == _receipt().config_digest
    assert outcome.approval_digest == _receipt().approval_digest
    assert outcome.capability_instance_ref == body.capability_instance_ref
    projected = cast(list[dict[str, object]], outcome.evidence["module_receipts"])
    assert projected[-1]["step_key"] == "identity-client"
    assert projected[-1]["provider_operation_ref"] == "provider-operation-1"
    assert projected[-1]["capability_instance_ref"] == "primary"


def test_apply_passes_prerequisite_receipt_pins_to_module_acceptance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _SessionHarness()
    seen: dict[str, object] = {}
    operation_id = UUID("e8216c0a-6249-4704-a327-47bfc343904d")

    def construct_pin(**values: object) -> SimpleNamespace:
        seen["pin"] = values
        return SimpleNamespace(**values)

    def construct_evidence_binding(**values: object) -> SimpleNamespace:
        seen["evidence_binding"] = values
        return SimpleNamespace(**values)

    def construct_command(**values: object) -> SimpleNamespace:
        seen["command"] = values
        return SimpleNamespace(**values)

    def accept(db: object, command: object, **values: object) -> SimpleNamespace:
        assert harness.active == 1
        return SimpleNamespace(
            operation_id=operation_id,
            state="succeeded",
            is_new=False,
        )

    def read_receipts(db: object, **values: object) -> tuple[SimpleNamespace, ...]:
        assert harness.active == 1
        return (_receipt(),)

    symbols: dict[str, Any] = {
        "ProvisionStep": lambda **values: SimpleNamespace(**values),
        "VerifiedApprovalGrant": lambda **values: SimpleNamespace(**values),
        "ProvisioningCapabilityOperationPin": lambda **values: SimpleNamespace(
            **values
        ),
        "PrerequisiteReceiptPin": construct_pin,
        "PrerequisiteEvidenceBinding": construct_evidence_binding,
        "ProvisioningCommand": construct_command,
        "accept_provisioning_command": accept,
        "prepare_next_apply": lambda *args, **kwargs: None,
        "invoke_prepared_provisioning": lambda *args, **kwargs: None,
        "settle_provisioning": lambda *args, **kwargs: None,
        "read_provisioning_receipts": read_receipts,
    }
    monkeypatch.setattr(operations, "Session", harness.session)
    monkeypatch.setattr(operations, "_module_symbol", symbols.__getitem__)
    monkeypatch.setattr(integration, "discover", lambda: object())

    prerequisite_binding_id = UUID("b6451c6f-6f6a-44a7-9464-85ea18088cf7")
    prerequisite = PrerequisiteReceiptPin(
        operation_id=UUID("0f615bf7-3067-432f-b93e-e8bcde410d0a"),
        capability_binding_id=prerequisite_binding_id,
        terminal_receipt_sequence=3,
        terminal_receipt_digest="sha256:" + "e" * 64,
        required_terminal_status="succeeded",
    )
    evidence_binding = PrerequisiteEvidenceBinding(
        source_capability_binding_id=prerequisite_binding_id,
        source_step_key="upstream-tenant",
        source_schema_ref="schema:provisioning/apply-result@v1",
        source_schema_digest="sha256:" + "2" * 64,
        source_pointer="/public/client_id",
        target_step_key="identity-client",
        target_schema_ref="schema:provisioning/apply-request@v1",
        target_schema_digest="sha256:" + "1" * 64,
        target_pointer="/upstream/client_id",
        required=True,
    )
    plan_hash = "sha256:" + "2" * 64
    binding_id = UUID("d9e93437-fb89-4db6-8a53-bf85beb26a33")
    steps = (
        ProvisioningStep(
            step_key="identity-client",
            endpoint_code="managed.service.provision.v1",
        ),
    )
    template_digest = command_template_digest(
        ApprovedCommandTemplate.model_validate(
            {
                **_static_fields(binding_id),
                "prerequisite_capability_binding_ids": (prerequisite_binding_id,),
                "prerequisite_evidence_bindings": (evidence_binding,),
                "steps": steps,
            }
        )
    )
    body = ApplyCommand.model_validate(
        {
            **_static_fields(binding_id),
            **_approval_evidence_fields(),
            "plan_hash": plan_hash,
            "expected_plan_hash": plan_hash,
            "approved_command_template_digest": template_digest,
            "prerequisite_capability_binding_ids": (prerequisite_binding_id,),
            "prerequisite_evidence_bindings": (evidence_binding,),
            "prerequisite_receipt_pins": (prerequisite,),
            "approval": ApprovalGrant.model_validate(
                {
                    "grant_ref": "approval-1",
                    **_approval_evidence_fields(),
                    "saved_plan_id": SAVED_PLAN_ID,
                    "approved_plan_hash": plan_hash,
                    "approved_command_template_digest": template_digest,
                    "digest": "sha256:" + "6" * 64,
                    "expires_at": datetime(2026, 8, 17, 12, 10, tzinfo=UTC),
                    "verified_at": datetime(2026, 8, 17, 12, 0, tzinfo=UTC),
                }
            ),
            "steps": steps,
        }
    )
    outcome = operations.ModuleProvisioningGateway().apply(
        cast(Engine, object()), "apply-command-1", body
    )

    assert seen["pin"] == prerequisite.model_dump(mode="python")
    assert seen["evidence_binding"] == evidence_binding.model_dump(mode="python")
    command_values = cast(dict[str, object], seen["command"])
    pins = cast(
        tuple[SimpleNamespace, ...],
        command_values["prerequisite_receipt_pins"],
    )
    assert len(pins) == 1
    assert vars(pins[0]) == prerequisite.model_dump(mode="python")
    evidence_bindings = cast(
        tuple[SimpleNamespace, ...],
        command_values["prerequisite_evidence_bindings"],
    )
    assert len(evidence_bindings) == 1
    assert vars(evidence_bindings[0]) == evidence_binding.model_dump(mode="python")
    assert command_values["capability_instance_ref"] == body.capability_instance_ref
    assert outcome.operation_id == operation_id


def test_replayed_apply_dispatch_claims_at_most_one_next_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _SessionHarness()
    operation_id = UUID("e8216c0a-6249-4704-a327-47bfc343904d")
    calls = {"accept": 0, "prepare": 0, "invoke": 0, "settle": 0}
    fixture = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "docs"
            / "fixtures"
            / "provisioning_apply_command_v1.json"
        ).read_text(encoding="utf-8")
    )
    body = ApplyCommand.model_validate(fixture["body"])

    def accept(db: object, command: object, **values: object) -> SimpleNamespace:
        assert harness.active == 1
        calls["accept"] += 1
        return SimpleNamespace(
            operation_id=operation_id,
            state="accepted",
            is_new=calls["accept"] == 1,
        )

    def prepare(db: object, **values: object) -> SimpleNamespace:
        assert harness.active == 1
        calls["prepare"] += 1
        return SimpleNamespace(step_number=calls["prepare"])

    def invoke(prepared: object, **values: object) -> SimpleNamespace:
        assert harness.active == 0, "connector I/O ran with a session in scope"
        calls["invoke"] += 1
        return SimpleNamespace(status="succeeded")

    def settle(db: object, **values: object) -> SimpleNamespace:
        assert harness.active == 1
        calls["settle"] += 1
        return SimpleNamespace(
            state="succeeded" if calls["settle"] == 2 else "accepted"
        )

    def read_receipts(db: object, **values: object) -> tuple[SimpleNamespace, ...]:
        assert harness.active == 1
        return (_receipt(),)

    symbols: dict[str, Any] = {
        "ProvisionStep": lambda **values: SimpleNamespace(**values),
        "VerifiedApprovalGrant": lambda **values: SimpleNamespace(**values),
        "ProvisioningCapabilityOperationPin": lambda **values: SimpleNamespace(
            **values
        ),
        "PrerequisiteReceiptPin": lambda **values: SimpleNamespace(**values),
        "PrerequisiteEvidenceBinding": lambda **values: SimpleNamespace(**values),
        "ProvisioningCommand": lambda **values: SimpleNamespace(**values),
        "accept_provisioning_command": accept,
        "prepare_next_apply": prepare,
        "invoke_prepared_provisioning": invoke,
        "settle_provisioning": settle,
        "read_provisioning_receipts": read_receipts,
    }
    monkeypatch.setattr(operations, "Session", harness.session)
    monkeypatch.setattr(operations, "_module_symbol", symbols.__getitem__)
    monkeypatch.setattr(integration, "discover", lambda: object())
    gateway = operations.ModuleProvisioningGateway()

    first = gateway.apply(cast(Engine, object()), "apply-command-1", body)
    replay = gateway.apply(cast(Engine, object()), "apply-command-1", body)

    assert first.replayed is False
    assert replay.replayed is True
    assert replay.state == "succeeded"
    assert calls == {"accept": 2, "prepare": 2, "invoke": 2, "settle": 2}
    assert harness.commits == 6


def test_transport_signer_refuses_a_latest_pin_detached_from_module_chain() -> None:
    outcome = operations.ProvisioningOutcome(
        state="succeeded",
        latest_module_receipt_sequence=2,
        latest_module_receipt_hash="sha256:" + "f" * 64,
        evidence={
            "module_receipts": [
                {
                    "sequence": 1,
                    "previous_receipt_hash": None,
                    "receipt_hash": "sha256:" + "0" * 64,
                },
                {
                    "sequence": 2,
                    "previous_receipt_hash": "sha256:" + "0" * 64,
                    "receipt_hash": "sha256:" + "1" * 64,
                },
            ]
        },
    )

    with pytest.raises(RuntimeError, match="differs from projected chain"):
        operations._require_signed_module_chain_projection(outcome)


def test_transport_signer_refuses_a_module_receipt_from_another_instance() -> None:
    receipt_hash = "sha256:" + "1" * 64
    outcome = operations.ProvisioningOutcome(
        state="succeeded",
        capability_instance_ref="primary",
        latest_module_receipt_sequence=1,
        latest_module_receipt_hash=receipt_hash,
        evidence={
            "module_receipts": [
                {
                    "sequence": 1,
                    "previous_receipt_hash": None,
                    "receipt_hash": receipt_hash,
                    "capability_instance_ref": "secondary",
                }
            ]
        },
    )

    with pytest.raises(RuntimeError, match="capability instance differs"):
        operations._require_signed_module_chain_projection(outcome)
