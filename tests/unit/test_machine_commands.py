from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dotmac_integrator.machine_commands import (
    ApplyCommand,
    ApplyCommandEnvelope,
    ApprovalGrant,
    ApprovedCommandTemplate,
    CapabilityOperationPin,
    CommandAuthenticationRefused,
    CommandIssuerAssignments,
    PlanCommand,
    PlanCommandEnvelope,
    PrerequisiteEvidenceBinding,
    PrerequisiteReceiptPin,
    ProvisioningStep,
    ReceiptPayload,
    body_digest,
    canonical_body_bytes,
    canonical_command_bytes,
    command_template_digest,
    install_crypto,
    sign_receipt,
    verify_apply_command,
    verify_receipt,
)
from dotmac_integrator.settings import Settings
from tests.support import build_settings

NOW = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
ASSIGNMENT_REF = "env://INTEGRATOR_SECRET_ISSUER_ASSIGNMENTS"
SAVED_PLAN_ID = UUID("11111111-1111-4111-8111-111111111111")
APPROVAL_REQUEST_ID = UUID("22222222-2222-4222-8222-222222222222")
PLAN_VALIDATION_RECEIPT_ID = UUID("77777777-7777-4777-8777-777777777777")


def _assignments(*deployments: str, instances: tuple[str, ...] = ("primary",)) -> str:
    return json.dumps(
        {
            "contract_version": "integrator.command-issuer-assignments.v2",
            "assignments": [
                {
                    "key_id": "vendor-key",
                    "account_ref": "vendor-account-1",
                    "deployment_instances": [
                        {
                            "deployment_ref": deployment,
                            "capability_instance_refs": list(instances),
                        }
                        for deployment in (deployments or ("deployment-1",))
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
        # dotmac_integration.DEFAULT_POLICY_DIGEST; the wire carries the
        # module-owned fingerprint, never assembly-authored policy values.
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


def _raw_private(key: Ed25519PrivateKey) -> str:
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode("ascii")


def _raw_public(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _settings() -> Settings:
    return build_settings(
        command_surface_enabled=True,
        command_audience="dotmac-integrator:test",
        command_public_key_refs="vendor-key=env://INTEGRATOR_SECRET_VENDOR_PUB",
        command_issuer_assignments_ref=ASSIGNMENT_REF,
        receipt_signing_key_id="integrator-receipt-1",
        receipt_signing_private_key_ref=("env://INTEGRATOR_SECRET_RECEIPT_PRIVATE"),
    )


def _body() -> ApplyCommand:
    digest = "sha256:" + "a" * 64
    binding_id = UUID("d9e93437-fb89-4db6-8a53-bf85beb26a33")
    prerequisite_binding_id = UUID("b6451c6f-6f6a-44a7-9464-85ea18088cf7")
    steps = (
        ProvisioningStep(
            step_key="identity-client",
            endpoint_code="managed.service.provision.v1",
            depends_on=(),
            input={"desired_ref": "deployment-1"},
        ),
    )
    evidence_bindings = (
        PrerequisiteEvidenceBinding(
            source_capability_binding_id=prerequisite_binding_id,
            source_step_key="upstream-tenant",
            source_pointer="/public/client_id",
            source_schema_ref="schema:provisioning/apply-result@v1",
            source_schema_digest="sha256:" + "2" * 64,
            target_step_key="identity-client",
            target_pointer="/upstream/client_id",
            target_schema_ref="schema:provisioning/apply-request@v1",
            target_schema_digest="sha256:" + "1" * 64,
            required=True,
        ),
    )
    template_digest = command_template_digest(
        ApprovedCommandTemplate.model_validate(
            {
                **_static_fields(binding_id),
                "steps": steps,
                "prerequisite_capability_binding_ids": (prerequisite_binding_id,),
                "prerequisite_evidence_bindings": evidence_bindings,
            }
        )
    )
    return ApplyCommand.model_validate(
        {
            **_static_fields(binding_id),
            **_approval_evidence_fields(),
            "plan_hash": digest,
            "expected_plan_hash": digest,
            "approved_command_template_digest": template_digest,
            "prerequisite_capability_binding_ids": (prerequisite_binding_id,),
            "prerequisite_evidence_bindings": evidence_bindings,
            "prerequisite_receipt_pins": (
                PrerequisiteReceiptPin(
                    operation_id=UUID("0f615bf7-3067-432f-b93e-e8bcde410d0a"),
                    capability_binding_id=prerequisite_binding_id,
                    terminal_receipt_sequence=3,
                    terminal_receipt_digest="sha256:" + "e" * 64,
                    required_terminal_status="succeeded",
                ),
            ),
            "approval": ApprovalGrant.model_validate(
                {
                    "grant_ref": "approval-grant-1",
                    **_approval_evidence_fields(),
                    "saved_plan_id": SAVED_PLAN_ID,
                    "approved_plan_hash": digest,
                    "approved_command_template_digest": template_digest,
                    "digest": "sha256:" + "d" * 64,
                    "expires_at": NOW + timedelta(minutes=10),
                    "verified_at": NOW - timedelta(minutes=1),
                }
            ),
            "steps": steps,
        }
    )


def _signed_envelope(
    signer: Ed25519PrivateKey,
    *,
    body: ApplyCommand | None = None,
    body_sha256: str | None = None,
) -> ApplyCommandEnvelope:
    command_body = body or _body()
    unsigned = ApplyCommandEnvelope(
        contract_version="integrator.provisioning-command.v1",
        key_id="vendor-key",
        audience="dotmac-integrator:test",
        issued_at=NOW - timedelta(seconds=5),
        expires_at=NOW + timedelta(minutes=2),
        command_id="command-0001",
        nonce="command-0001",
        body_sha256=body_sha256 or body_digest(command_body),
        signature="unsigned",
        body=command_body,
    )
    signature = (
        base64.urlsafe_b64encode(signer.sign(canonical_command_bytes(unsigned)))
        .rstrip(b"=")
        .decode("ascii")
    )
    return unsigned.model_copy(update={"signature": signature})


def _install(command_key: Ed25519PrivateKey, receipt_key: Ed25519PrivateKey) -> None:
    settings = _settings()
    install_crypto(
        settings,
        {
            "env://INTEGRATOR_SECRET_VENDOR_PUB": _raw_public(command_key),
            ASSIGNMENT_REF: _assignments("deployment-1"),
            "env://INTEGRATOR_SECRET_RECEIPT_PRIVATE": _raw_private(receipt_key),
        },
    )


def test_canonical_signature_binds_body_hash_and_every_envelope_field() -> None:
    command_key = Ed25519PrivateKey.generate()
    _install(command_key, Ed25519PrivateKey.generate())
    envelope = _signed_envelope(command_key)

    authenticated = verify_apply_command(envelope, now=NOW)
    assert authenticated.command_id == "command-0001"
    assert authenticated.nonce == "command-0001"
    assert authenticated.issuer_account_ref == "vendor-account-1"
    assert authenticated.body == envelope.body

    changed = envelope.model_copy(update={"nonce": "nonce-0002"})
    with pytest.raises(CommandAuthenticationRefused, match="nonce must equal"):
        verify_apply_command(changed, now=NOW)


def test_prerequisite_receipt_pins_require_unique_canonical_operation_order() -> None:
    body = _body()
    first = body.prerequisite_receipt_pins[0]
    earlier = first.model_copy(
        update={"operation_id": UUID("00000000-0000-4000-8000-000000000001")}
    )

    with pytest.raises(ValueError, match="canonical operation_id order"):
        ApplyCommand.model_validate(
            {
                **body.model_dump(mode="json"),
                "prerequisite_receipt_pins": [first, earlier],
            }
        )

    with pytest.raises(ValueError, match="unique"):
        ApplyCommand.model_validate(
            {
                **body.model_dump(mode="json"),
                "prerequisite_receipt_pins": [first, first],
            }
        )


def test_dynamic_receipt_pins_change_body_signature_but_not_approved_template() -> None:
    body = _body()
    pin = body.prerequisite_receipt_pins[0]
    changed = body.model_copy(
        update={
            "prerequisite_receipt_pins": (
                pin.model_copy(
                    update={"terminal_receipt_digest": "sha256:" + "f" * 64}
                ),
            )
        }
    )

    assert command_template_digest(body) == command_template_digest(changed)
    assert body_digest(body) != body_digest(changed)


def test_evidence_bindings_are_static_and_require_canonical_unique_targets() -> None:
    body = _body()
    binding = body.prerequisite_evidence_bindings[0]
    second = binding.model_copy(
        update={
            "source_step_key": "another-upstream-step",
            "source_pointer": "/public/earlier_id",
            "target_pointer": "/upstream/another_id",
        }
    )
    template_values = {
        field_name: getattr(body, field_name)
        for field_name in ApprovedCommandTemplate.model_fields
    }

    with pytest.raises(ValueError, match="canonical evidence-binding order"):
        ApprovedCommandTemplate.model_validate(
            {**template_values, "prerequisite_evidence_bindings": (binding, second)}
        )
    with pytest.raises(ValueError, match="must be unique"):
        ApprovedCommandTemplate.model_validate(
            {
                **template_values,
                "prerequisite_evidence_bindings": (binding, binding),
            }
        )
    with pytest.raises(ValueError, match="target input locations must be unique"):
        ApprovedCommandTemplate.model_validate(
            {
                **template_values,
                "prerequisite_evidence_bindings": (
                    second.model_copy(
                        update={"target_pointer": binding.target_pointer}
                    ),
                    binding,
                ),
            }
        )

    changed = body.model_copy(
        update={
            "prerequisite_evidence_bindings": (
                binding.model_copy(update={"required": False}),
            )
        }
    )
    assert command_template_digest(body) != command_template_digest(changed)
    assert body_digest(body) != body_digest(changed)


def test_evidence_binding_array_is_present_even_when_empty() -> None:
    body = _body()
    template_values = {
        field_name: getattr(body, field_name)
        for field_name in ApprovedCommandTemplate.model_fields
    }
    template_values.pop("prerequisite_evidence_bindings")
    with pytest.raises(ValueError, match="prerequisite_evidence_bindings"):
        ApprovedCommandTemplate.model_validate(template_values)

    without_bindings = {
        **body.model_dump(mode="json"),
        "prerequisite_evidence_bindings": [],
    }
    template = ApprovedCommandTemplate.model_validate(
        {name: without_bindings[name] for name in ApprovedCommandTemplate.model_fields}
    )
    template_digest = command_template_digest(template)
    without_bindings["approved_command_template_digest"] = template_digest
    without_bindings["approval"]["approved_command_template_digest"] = template_digest
    validated = ApplyCommand.model_validate(without_bindings)
    assert validated.prerequisite_evidence_bindings == ()
    assert "prerequisite_evidence_bindings" in validated.model_dump(mode="json")


@pytest.mark.parametrize(
    "pointer",
    ("", "public/client_id", "/public/~2client_id"),
)
def test_evidence_bindings_refuse_noncanonical_json_pointers(pointer: str) -> None:
    body = _body()
    binding = body.prerequisite_evidence_bindings[0]
    with pytest.raises(ValueError, match="RFC 6901"):
        PrerequisiteEvidenceBinding.model_validate(
            {**binding.model_dump(mode="json"), "source_pointer": pointer}
        )


def test_evidence_bindings_reference_bindings_steps_and_apply_schema() -> None:
    body = _body()
    binding = body.prerequisite_evidence_bindings[0]
    cases = (
        (
            "source_capability_binding_id",
            UUID("99999999-9999-4999-8999-999999999999"),
            "approved prerequisite",
        ),
        ("target_step_key", "missing-step", "target step"),
        (
            "target_schema_digest",
            "sha256:" + "f" * 64,
            "apply input schema",
        ),
    )
    for field_name, replacement, message in cases:
        with pytest.raises(ValueError, match=message):
            ApplyCommand.model_validate(
                {
                    **body.model_dump(mode="json"),
                    "prerequisite_evidence_bindings": [
                        {
                            **binding.model_dump(mode="json"),
                            field_name: replacement,
                        }
                    ],
                }
            )


def test_post_plan_approval_evidence_is_signed_but_not_in_static_template() -> None:
    body = _body()
    changed_request_id = UUID("99999999-9999-4999-8999-999999999999")
    changed = body.model_copy(
        update={
            "approval_request_id": changed_request_id,
            "approval": body.approval.model_copy(
                update={"approval_request_id": changed_request_id}
            ),
        }
    )

    assert command_template_digest(body) == command_template_digest(changed)
    assert body_digest(body) != body_digest(changed)


@pytest.mark.parametrize(
    "field_name",
    (
        "approval_request_binding_hash",
        "plan_command_id",
        "plan_validation_receipt_id",
        "plan_validation_receipt_digest",
        "plan_validation_request_body_digest",
        "module_plan_receipt_hash",
    ),
)
def test_apply_requires_exact_plan_evidence_from_approval(field_name: str) -> None:
    body = _body()
    replacement: object = "sha256:" + "f" * 64
    if field_name == "plan_command_id":
        replacement = "another-plan-command"
    elif field_name == "plan_validation_receipt_id":
        replacement = UUID("99999999-9999-4999-8999-999999999999")

    with pytest.raises(ValueError, match=field_name):
        ApplyCommand.model_validate(
            {
                **body.model_dump(mode="json"),
                field_name: replacement,
            }
        )


def test_capability_id_binds_code_and_schema_version() -> None:
    body = _body()
    with pytest.raises(ValueError, match="capability_id"):
        ApplyCommand.model_validate(
            {
                **body.model_dump(mode="json"),
                "capability_id": "managed.service.provision.v2",
            }
        )


def test_prerequisite_bindings_and_pins_must_match_exactly() -> None:
    body = _body()
    with pytest.raises(ValueError, match="exactly match"):
        ApplyCommand.model_validate(
            {
                **body.model_dump(mode="json"),
                "prerequisite_receipt_pins": [],
            }
        )


def test_planned_step_action_is_the_capability_not_an_engine_operation_code() -> None:
    body = _body()
    assert body.steps[0].endpoint_code == body.capability_id
    assert body.steps[0].endpoint_code not in {
        operation.operation_code for operation in body.capability_operations
    }

    with pytest.raises(ValueError, match="versioned capability_id"):
        ApplyCommand.model_validate(
            {
                **body.model_dump(mode="json"),
                "steps": [
                    {
                        **body.steps[0].model_dump(mode="json"),
                        "endpoint_code": "invented.operation.v1",
                    }
                ],
            }
        )


@pytest.mark.parametrize("value", (float("nan"), float("inf"), float("-inf")))
def test_command_body_rejects_non_finite_json_numbers(value: float) -> None:
    # Sensitivity: Python's default encoder emits these non-JSON tokens, so
    # allow_nan=False without the typed body refusal would surface too late.
    assert any(token in json.dumps({"value": value}) for token in ("NaN", "Infinity"))

    with pytest.raises(ValueError, match="non-finite"):
        ProvisioningStep(
            step_key="identity-client",
            endpoint_code="managed.service.provision.v1",
            input={"nested": [{"value": value}]},
        )


def test_body_hash_is_checked_before_the_signature_is_accepted() -> None:
    command_key = Ed25519PrivateKey.generate()
    _install(command_key, Ed25519PrivateKey.generate())
    envelope = _signed_envelope(command_key, body_sha256="sha256:" + "0" * 64)
    with pytest.raises(CommandAuthenticationRefused, match="body hash"):
        verify_apply_command(envelope, now=NOW)


@pytest.mark.parametrize(
    "value",
    ("", "Uppercase", "bad_instance", "bad..instance", "bad-", "a" * 201),
)
def test_capability_instance_reference_grammar_is_strict(value: str) -> None:
    body = _body()
    with pytest.raises(ValueError, match="capability_instance_ref"):
        ApplyCommand.model_validate(
            {**body.model_dump(mode="json"), "capability_instance_ref": value}
        )


def test_same_capability_instances_have_distinct_plan_body_hashes() -> None:
    common = {
        "deployment_ref": "deployment-1",
        "capability_id": "managed.service.provision.v1",
        "capability_binding_id": UUID("d9e93437-fb89-4db6-8a53-bf85beb26a33"),
        "plan_hash": "sha256:" + "a" * 64,
        "config_digest": "sha256:" + "c" * 64,
        "steps": (
            ProvisioningStep(
                step_key="identity-client",
                endpoint_code="managed.service.provision.v1",
            ),
        ),
    }
    email = PlanCommand.model_validate(
        {**common, "capability_instance_ref": "email.oidc-client"}
    )
    collaboration = PlanCommand.model_validate(
        {**common, "capability_instance_ref": "collaboration.oidc-client"}
    )

    assert body_digest(email) != body_digest(collaboration)


def test_issuer_assignment_refuses_an_unassigned_instance_in_the_same_deployment() -> (
    None
):
    command_key = Ed25519PrivateKey.generate()
    receipt_key = Ed25519PrivateKey.generate()
    install_crypto(
        _settings(),
        {
            "env://INTEGRATOR_SECRET_VENDOR_PUB": _raw_public(command_key),
            ASSIGNMENT_REF: _assignments("deployment-1", instances=("secondary",)),
            "env://INTEGRATOR_SECRET_RECEIPT_PRIVATE": _raw_private(receipt_key),
        },
    )

    with pytest.raises(CommandAuthenticationRefused, match="capability instance"):
        verify_apply_command(_signed_envelope(command_key), now=NOW)


def test_v1_issuer_assignment_document_is_not_a_wildcard_migration() -> None:
    command_key = Ed25519PrivateKey.generate()
    receipt_key = Ed25519PrivateKey.generate()
    legacy = json.dumps(
        {
            "contract_version": "integrator.command-issuer-assignments.v1",
            "assignments": [
                {
                    "key_id": "vendor-key",
                    "account_ref": "vendor-account-1",
                    "deployment_refs": ["deployment-1"],
                }
            ],
        }
    )

    with pytest.raises(ValueError, match="invalid command issuer assignment"):
        install_crypto(
            _settings(),
            {
                "env://INTEGRATOR_SECRET_VENDOR_PUB": _raw_public(command_key),
                ASSIGNMENT_REF: legacy,
                "env://INTEGRATOR_SECRET_RECEIPT_PRIVATE": _raw_private(receipt_key),
            },
        )


@pytest.mark.parametrize(
    ("deployment_instances", "message"),
    (
        (
            [
                {
                    "deployment_ref": "deployment-1",
                    "capability_instance_refs": ["secondary", "primary"],
                }
            ],
            "must be sorted",
        ),
        (
            [
                {
                    "deployment_ref": "deployment-1",
                    "capability_instance_refs": ["primary", "primary"],
                }
            ],
            "must be unique",
        ),
        (
            [
                {
                    "deployment_ref": "deployment-2",
                    "capability_instance_refs": ["primary"],
                },
                {
                    "deployment_ref": "deployment-1",
                    "capability_instance_refs": ["primary"],
                },
            ],
            "must be sorted",
        ),
    ),
)
def test_v2_issuer_assignment_requires_canonical_deployment_instances(
    deployment_instances: list[dict[str, object]], message: str
) -> None:
    document = {
        "contract_version": "integrator.command-issuer-assignments.v2",
        "assignments": [
            {
                "key_id": "vendor-key",
                "account_ref": "vendor-account-1",
                "deployment_instances": deployment_instances,
            }
        ],
    }

    with pytest.raises(ValueError, match=message):
        CommandIssuerAssignments.model_validate(document)


def test_request_verification_uses_the_preparsed_held_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import dotmac_integrator.machine_commands as command_module

    command_key = Ed25519PrivateKey.generate()
    _install(command_key, Ed25519PrivateKey.generate())
    envelope = _signed_envelope(command_key)

    def must_not_parse_on_request(material: str) -> object:
        raise AssertionError("request path reparsed held key material")

    monkeypatch.setattr(command_module, "_public_key", must_not_parse_on_request)
    monkeypatch.setattr(
        command_module, "_issuer_assignments", must_not_parse_on_request
    )
    assert verify_apply_command(envelope, now=NOW).command_id == "command-0001"


def test_assignment_and_key_sets_must_match_and_failed_rotation_keeps_working_set() -> (
    None
):
    command_key = Ed25519PrivateKey.generate()
    receipt_key = Ed25519PrivateKey.generate()
    _install(command_key, receipt_key)
    envelope = _signed_envelope(command_key)
    wrong = json.dumps(
        {
            "contract_version": "integrator.command-issuer-assignments.v2",
            "assignments": [
                {
                    "key_id": "another-key",
                    "account_ref": "another-account",
                    "deployment_instances": [
                        {
                            "deployment_ref": "deployment-1",
                            "capability_instance_refs": ["primary"],
                        }
                    ],
                }
            ],
        }
    )
    with pytest.raises(ValueError, match="exactly match"):
        install_crypto(
            _settings(),
            {
                "env://INTEGRATOR_SECRET_VENDOR_PUB": _raw_public(command_key),
                ASSIGNMENT_REF: wrong,
                "env://INTEGRATOR_SECRET_RECEIPT_PRIVATE": _raw_private(receipt_key),
            },
        )

    assert verify_apply_command(envelope, now=NOW).issuer_account_ref == (
        "vendor-account-1"
    )


@pytest.mark.parametrize("offset", [timedelta(minutes=-3), timedelta(minutes=3)])
def test_expired_or_not_yet_valid_envelopes_are_refused(offset: timedelta) -> None:
    command_key = Ed25519PrivateKey.generate()
    _install(command_key, Ed25519PrivateKey.generate())
    envelope = _signed_envelope(command_key)
    with pytest.raises(CommandAuthenticationRefused):
        verify_apply_command(envelope, now=NOW + offset)


def test_receipt_is_signed_by_a_distinct_integrator_key_and_detects_tampering() -> None:
    command_key = Ed25519PrivateKey.generate()
    receipt_key = Ed25519PrivateKey.generate()
    _install(command_key, receipt_key)
    envelope = _signed_envelope(command_key)
    authenticated = verify_apply_command(envelope, now=NOW)
    payload = ReceiptPayload(
        receipt_contract_version="integrator.provisioning-receipt.v1",
        command_contract_version=authenticated.contract_version,
        operation="apply",
        command_id=authenticated.command_id,
        nonce=authenticated.nonce,
        issuer_account_ref=authenticated.issuer_account_ref,
        deployment_ref=authenticated.body.deployment_ref,
        capability_instance_ref=authenticated.body.capability_instance_ref,
        request_body_sha256=authenticated.body_sha256,
        plan_hash=authenticated.body.plan_hash,
        approval_digest=authenticated.body.approval.digest,
        artifact_digest=authenticated.body.artifact_digest,
        config_digest=authenticated.body.config_digest,
        outcome="accepted",
        operation_id=UUID("e8216c0a-6249-4704-a327-47bfc343904d"),
        replayed=False,
        occurred_at=NOW,
        evidence={"state": "pending"},
    )

    receipt = sign_receipt(payload)
    verify_receipt(receipt, receipt_key.public_key())
    assert receipt.key_id == "integrator-receipt-1"
    tampered_payload = payload.model_copy(update={"outcome": "succeeded"})
    with pytest.raises(CommandAuthenticationRefused):
        verify_receipt(
            receipt.model_copy(update={"receipt": tampered_payload}),
            receipt_key.public_key(),
        )


def test_receipt_key_cannot_reuse_a_command_signing_key() -> None:
    same_key = Ed25519PrivateKey.generate()
    settings = _settings()
    with pytest.raises(ValueError, match="distinct"):
        install_crypto(
            settings,
            {
                "env://INTEGRATOR_SECRET_VENDOR_PUB": _raw_public(same_key),
                ASSIGNMENT_REF: _assignments("deployment-1"),
                "env://INTEGRATOR_SECRET_RECEIPT_PRIVATE": _raw_private(same_key),
            },
        )


def test_key_material_never_renders_from_authentication_objects() -> None:
    command_key = Ed25519PrivateKey.generate()
    receipt_key = Ed25519PrivateKey.generate()
    sentinel = _raw_private(receipt_key)
    _install(command_key, receipt_key)
    assert sentinel not in repr(_signed_envelope(command_key))


def test_apply_contract_matches_the_cross_repository_golden_fixture() -> None:
    fixture_path = (
        Path(__file__).resolve().parents[2]
        / "docs"
        / "fixtures"
        / "provisioning_apply_command_v1.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    body = ApplyCommand.model_validate(fixture["body"])
    assert body.capability_instance_ref == "managed.service-primary"
    template = ApprovedCommandTemplate.model_validate(
        {name: getattr(body, name) for name in ApprovedCommandTemplate.model_fields}
    )
    envelope = ApplyCommandEnvelope.model_validate(
        {**fixture["unsigned_header"], "signature": "unsigned", "body": fixture["body"]}
    )
    assert canonical_body_bytes(body).decode("utf-8") == fixture["canonical_body"]
    assert body_digest(body) == fixture["body_sha256"]
    assert (
        canonical_body_bytes(template).decode("utf-8")
        == fixture["canonical_approved_command_template"]
    )
    assert (
        command_template_digest(template) == fixture["approved_command_template_digest"]
    )
    assert (
        canonical_command_bytes(envelope).decode("utf-8")
        == fixture["canonical_signature_input"]
    )


def test_plan_contract_matches_the_cross_repository_golden_fixture() -> None:
    fixture_path = (
        Path(__file__).resolve().parents[2]
        / "docs"
        / "fixtures"
        / "provisioning_plan_command_v1.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    body = PlanCommand.model_validate(fixture["body"])
    envelope = PlanCommandEnvelope.model_validate(
        {**fixture["unsigned_header"], "signature": "unsigned", "body": fixture["body"]}
    )

    assert body.deployment_ref == "deployment-0001"
    assert body.capability_instance_ref == "managed.service-primary"
    assert canonical_body_bytes(body).decode("utf-8") == fixture["canonical_body"]
    assert body_digest(body) == fixture["body_sha256"]
    assert (
        canonical_command_bytes(envelope).decode("utf-8")
        == (fixture["canonical_signature_input"])
    )
