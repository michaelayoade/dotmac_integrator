"""Source-level startup ordering guard, including a planted unsafe ordering.

Behavioral descriptor tests exercise the reader and transaction seam separately.
This guard keeps the thin assembly from silently rejoining those phases.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


def _require_owner_before_destination(source: str) -> None:
    tree = ast.parse(source)
    lifespan = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "lifespan"
    )
    calls = [node for node in ast.walk(lifespan) if isinstance(node, ast.Call)]

    def line(name: str) -> int:
        return min(
            node.lineno
            for node in calls
            if isinstance(node.func, ast.Attribute) and node.func.attr == name
        )

    assert (
        line("prepare_owner") < line("install_capability_registry") < line("reconcile")
    )
    assert line("reconcile") < line("install_product_port") < line("start")
    assert not any(
        isinstance(node.func, ast.Attribute) and node.func.attr == "require_no_orphans"
        for node in calls
    )
    active = next(
        node
        for node in ast.walk(lifespan)
        if isinstance(node, ast.If)
        and ast.unparse(node.test) == "settings.product_port_enabled"
    )
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "reconcile"
        for node in ast.walk(active)
    )
    assert "install_registry=False" in ast.unparse(active)


def test_startup_installs_combined_owner_before_destination_writes() -> None:
    source = Path("src/dotmac_integrator/assembly.py").read_text()
    _require_owner_before_destination(source)
    bad = source.replace(
        "integration.install_capability_registry(registry)",
        "reconciler.reconcile(prepared, registry=registry)\n"
        "            integration.install_capability_registry(registry)",
    )
    with pytest.raises(AssertionError):
        _require_owner_before_destination(bad)


@pytest.mark.parametrize("prepare_only", [False, True])
def test_real_lifespan_prepares_owner_before_active_reconcile(
    monkeypatch: pytest.MonkeyPatch,
    prepare_only: bool,
) -> None:
    from dataclasses import replace
    from types import SimpleNamespace
    from typing import Any

    import dotmac_integration as integration
    from fastapi.testclient import TestClient

    from dotmac_integrator import (
        assembly,
        delivery,
        product_contracts,
        product_port,
        runtime_policy,
        secret_loading,
    )
    from tests.support import build_settings
    from tests.unit.test_product_port import _descriptor_document

    document = _descriptor_document()
    contract_document = document["capability_contract"]
    capability_id = document["capability_id"]
    application = document["application"]
    owner_module = document["owner_module"]
    summary = document["capability_summary"]
    assert isinstance(contract_document, dict)
    assert isinstance(capability_id, str)
    assert isinstance(application, str)
    assert isinstance(owner_module, str)
    assert isinstance(summary, str)
    contract = integration.capability_contract_from_document(
        contract_document,
        capability_id=capability_id,
        application=application,
        owner_module=owner_module,
        summary=summary,
    )
    port_registry = integration.CapabilityRegistry.from_declarations([contract])
    extra_registry = integration.CapabilityRegistry.from_declarations(
        [
            replace(contract, capability_id="synthetic.other.v1"),
        ]
    )
    prepared = SimpleNamespace(registry=port_registry)
    events: list[str] = []
    installed: list[Any] = []
    client = object()

    class Engine:
        def dispose(self) -> None:
            events.append("dispose")

    class Worker:
        def __init__(self, **kwargs: Any) -> None:
            pass

        async def start(self) -> None:
            events.append("worker-start")

        async def stop(self) -> None:
            events.append("worker-stop")

    class Reconciler:
        def prepare_owner(self) -> Any:
            events.append("authenticated-prepare")
            return prepared

        def reconcile(self, value: Any, *, registry: Any) -> tuple[object, Any]:
            assert value is prepared
            assert installed == [registry]
            assert registry.get("synthetic.other.v1") is not None
            events.append("module-reconcile-commit")
            return client, registry

    def install_owner(registry: Any) -> None:
        events.append("install-combined-owner")
        installed.append(registry)

    def install_port(value: object, *, registry: Any, install_registry: bool) -> None:
        assert value is client and installed == [registry]
        assert install_registry is False
        events.append("install-delivery")

    monkeypatch.setattr(assembly, "build_engine", lambda settings: Engine())
    monkeypatch.setattr(assembly, "Worker", Worker)
    monkeypatch.setattr(
        runtime_policy, "require_declared_runtime_boundaries", lambda: None
    )
    monkeypatch.setattr(
        secret_loading,
        "install_secrets",
        lambda *args: SimpleNamespace(held=("env://INTEGRATOR_SECRET_SYNTHETIC",)),
    )
    monkeypatch.setattr(
        product_port,
        "reconciler_from_settings",
        lambda *args, **kwargs: Reconciler(),
    )
    monkeypatch.setattr(
        product_contracts,
        "build_from_settings",
        lambda *args, **kwargs: extra_registry,
    )
    monkeypatch.setattr(integration, "install_capability_registry", install_owner)
    monkeypatch.setattr(
        integration,
        "require_no_orphans",
        lambda *args: pytest.fail("coverage is reported, not a startup gate"),
    )
    monkeypatch.setattr(delivery, "install_product_port", install_port)
    app = assembly.create_app(
        build_settings(
            worker_enabled=False,
            product_port_enabled=not prepare_only,
            product_port_prepare_only=prepare_only,
            product_port_descriptor_url="https://destination.example/descriptor",
            product_port_descriptor_expected_digest="a" * 64,
            product_port_api_key_ref="env://INTEGRATOR_SECRET_SYNTHETIC",
            product_port_shadow_revision="synthetic-revision",
            product_contract_registry_enabled=True,
            product_contract_registry_url="https://destination.example/contracts",
            product_contract_registry_expected_digest="b" * 64,
            product_contract_registry_api_key_ref="env://INTEGRATOR_SECRET_SYNTHETIC",
        )
    )
    with TestClient(app):
        expected = ["authenticated-prepare", "install-combined-owner"]
        if not prepare_only:
            expected += ["module-reconcile-commit", "install-delivery"]
        assert events == [*expected, "worker-start"]
    assert events[-2:] == ["worker-stop", "dispose"]
