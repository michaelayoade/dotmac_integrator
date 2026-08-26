"""The provisioning command edge is a fourth authenticated population.

These checks are intentionally structural.  A happy-path request test cannot
prove that a later route did not inherit operator authentication, add a local
nonce cache, or grow an arbitrary-shell escape hatch.
"""

from __future__ import annotations

import ast
from pathlib import Path

from fastapi import Depends, FastAPI

from dotmac_integrator.machine_commands import (
    ApplyCommand,
    MachineCommandGuard,
    PlanCommand,
    require_apply_command,
)
from dotmac_integrator.operator_auth import require_operator
from dotmac_integrator.surface import audit_routes

SRC = Path(__file__).resolve().parents[2] / "src" / "dotmac_integrator"


def test_command_routes_use_machine_auth_and_never_operator_auth() -> None:
    source = (SRC / "assembly.py").read_text(encoding="utf-8")
    for operation in ("plan", "apply", "observe", "cancel"):
        assert f'"/commands/provisioning/{operation}"' in source
    assert "require_plan_command" in source
    assert "require_apply_command" in source
    assert "require_observe_command" in source
    assert "require_cancel_command" in source


def test_surface_auditor_rejects_an_unguarded_or_operator_guarded_command() -> None:
    app = FastAPI()

    @app.post("/commands/provisioning/plan")
    def unguarded() -> dict[str, bool]:
        return {"ok": True}

    @app.post(
        "/commands/provisioning/apply",
        dependencies=[Depends(require_operator)],
    )
    def wrong_population() -> dict[str, bool]:
        return {"ok": True}

    violations = audit_routes(app)
    assert any("machine-command route with no" in item for item in violations)
    assert any("operator guard" in item for item in violations)


def test_surface_auditor_accepts_the_machine_guard() -> None:
    app = FastAPI()

    @app.post(
        "/commands/provisioning/apply",
        dependencies=[Depends(require_apply_command)],
    )
    def guarded() -> dict[str, bool]:
        return {"ok": True}

    assert audit_routes(app) == []


def test_machine_guard_sensitivity_fixture_is_the_real_guard_type() -> None:
    assert isinstance(require_apply_command, MachineCommandGuard)


def test_typed_bodies_have_no_arbitrary_process_escape_hatch() -> None:
    forbidden = {"argv", "command", "command_line", "exec", "script", "shell"}
    assert forbidden.isdisjoint(PlanCommand.model_fields)
    assert forbidden.isdisjoint(ApplyCommand.model_fields)


def test_assembly_owns_no_command_or_nonce_ledger() -> None:
    """Replay/collision belongs to dotmac-integration's durable ledger."""
    for name in ("assembly.py", "machine_commands.py", "operations.py"):
        path = SRC / name
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        if name == "machine_commands.py":
            assert "sqlalchemy" not in imports
            assert not imports & {
                "httpx",
                "os",
                "pathlib",
                "requests",
                "socket",
                "subprocess",
                "urllib",
            }
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                assert "ledger" not in node.name.lower()


def test_module_remains_the_evidence_schema_and_injection_authority() -> None:
    """Sensitivity: an assembly import would create a second schema owner."""
    planted = ast.parse(
        "from dotmac_kernel.capability_contract import CapabilitySchemaDocument\n"
    )
    assert any(
        isinstance(node, ast.ImportFrom)
        and node.module == "dotmac_kernel.capability_contract"
        for node in ast.walk(planted)
    )

    for name in ("assembly.py", "machine_commands.py", "operations.py"):
        source = (SRC / name).read_text(encoding="utf-8")
        tree = ast.parse(source)
        assert not any(
            isinstance(node, ast.ImportFrom)
            and node.module == "dotmac_kernel.capability_contract"
            for node in ast.walk(tree)
        )
        assert "require_public_non_secret_pointer" not in source


def test_nonce_is_exactly_the_module_owned_command_identity() -> None:
    source = (SRC / "machine_commands.py").read_text(encoding="utf-8")
    assert "envelope.nonce != envelope.command_id" in source
    assert "sole replay owner" in source


def test_no_subprocess_or_shell_primitive_exists_in_the_assembly() -> None:
    planted = ast.parse("import subprocess\nsubprocess.run(['x'])\n")
    assert any(
        isinstance(node, ast.Import)
        and any(alias.name == "subprocess" for alias in node.names)
        for node in ast.walk(planted)
    )

    for path in sorted(SRC.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(alias.name != "subprocess" for alias in node.names), path
            if isinstance(node, ast.ImportFrom):
                assert node.module != "subprocess", path
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in {"exec", "popen", "spawn", "system"}, path


def test_gateway_names_the_real_a6_transaction_phases() -> None:
    tree = ast.parse((SRC / "operations.py").read_text(encoding="utf-8"))
    named = {
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_module_symbol"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }
    assert {
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
        "ExpectedProvisioningPin",
        "PrerequisiteReceiptPin",
        "PrerequisiteEvidenceBinding",
        "read_provisioning_plan_receipt",
        "read_provisioning_receipts",
    } <= named
    placeholders = {
        "plan_provisioning",
        "observe_provisioning",
        "cancel_provisioning",
    }
    assert placeholders.isdisjoint(named)


def test_command_surface_fails_boot_before_mounting_an_unavailable_module() -> None:
    assembly_source = (SRC / "assembly.py").read_text(encoding="utf-8")
    operations_source = (SRC / "operations.py").read_text(encoding="utf-8")

    assert "require_provisioning_module_surface()" in assembly_source
    assert "PROVISIONING_MODULE_SYMBOLS" in operations_source
    assert '"ProvisioningPlanReceiptView"' in operations_source
    assert '"read_provisioning_plan_receipt"' in operations_source
