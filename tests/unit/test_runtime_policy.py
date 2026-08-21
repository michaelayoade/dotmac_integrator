"""The SPI 1.3 projection: what it publishes, and what it refuses.

Three claims, and the middle one is the reason this file exists at all.

1. The projection is the MODULE's. This deployment renders it and adds nothing
   — no host, no secret name, no provider identity of its own.
2. An installed connector that declares no runtime boundary REFUSES THE BOOT.
   Every distribution this assembly pins declares SPI `>=1.3,<2.0`, so that
   refusal is unreachable through the pins and would sit here forever as an
   untested branch. It is therefore driven with a planted pre-1.3 manifest —
   a guard whose only evidence is that it never fired is not enforcement
   (ADR-0018).
3. Capability coverage is REPORTED in both directions and decides nothing. An
   implemented capability nobody declared is a product decision to make or
   decline; this deployment may never mint a capability declaration, and it may
   not quietly hide the gap either.
"""

from __future__ import annotations

from typing import Any

import dotmac_integration as integration
import pytest
from dotmac_integration.capability_registry import _reset_capability_registry
from dotmac_integration.conformance import FakePlugin, fake_manifest, fake_registry

from dotmac_integrator import runtime_policy

#: A pre-1.3 manifest: SPI 1.2, and therefore BOTH boundary fields omitted.
#: `ConnectorManifest` refuses one without the other, so this is the only shape
#: a legacy connector can actually have — which is what makes it the right
#: vehicle for the refusal rather than an invented one.
LEGACY_MANIFEST = integration.ConnectorManifest(
    connector_key="planted_legacy",
    version="0.0.1",
    spi_range=integration.SpiRange.parse(">=1.2,<2.0"),
    capabilities=(
        integration.CapabilityDeclaration(capability_id="planted.observation.v1"),
    ),
)


def _plant(monkeypatch: pytest.MonkeyPatch, *manifests: Any) -> None:
    """Make discovery answer with exactly these manifests.

    Patched on the `integration` name `runtime_policy` actually calls, so a
    refactor that started importing `discover` directly would fail here rather
    than silently test the real installation.
    """
    registry = fake_registry(
        plugins=[FakePlugin(manifest_=manifest) for manifest in manifests]
    )
    monkeypatch.setattr(integration, "discover", lambda: registry)


# ── 1. The projection is the module's, and this deployment adds nothing ─────


def test_the_report_is_projected_from_the_installed_manifests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _plant(monkeypatch, fake_manifest(connector_key="planted_one"))

    report = runtime_policy.policy_report(runtime_policy.projected_policy())

    assert [c["connector_key"] for c in report["connectors"]] == ["planted_one"]
    assert report["policy_digest"] == runtime_policy.projected_policy().digest
    assert report["spi_version"] == str(integration.CURRENT_SPI_VERSION)


def test_an_empty_egress_declaration_is_reported_as_an_explicit_deny_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The load-bearing half of the 1.3 contract.

    `fake_manifest` declares no egress hosts, which under 1.3 is an affirmative
    deny-all rather than an unset field. An operator reading an empty list
    cannot tell those apart, so the report states it.
    """
    _plant(monkeypatch, fake_manifest(connector_key="planted_one"))

    report = runtime_policy.policy_report(runtime_policy.projected_policy())

    assert report["egress_hosts"] == []
    assert report["egress_denies_all"] is True


def test_the_egress_union_is_the_sorted_union_of_every_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Positive control for the deny-all case above, which would also pass over
    a projection that dropped every declared host on the floor."""
    reaching = integration.ConnectorManifest(
        connector_key="planted_reaching",
        version="0.0.1",
        spi_range=integration.SpiRange.parse(">=1.3,<2.0"),
        capabilities=(
            integration.CapabilityDeclaration(capability_id="planted.observation.v1"),
        ),
        secret_bindings=(),
        egress=integration.EgressDeclaration(
            hosts=("zeta.example.com", "a.example.com")
        ),
    )
    _plant(monkeypatch, reaching, fake_manifest(connector_key="planted_quiet"))

    report = runtime_policy.policy_report(runtime_policy.projected_policy())

    assert report["egress_hosts"] == ["a.example.com", "zeta.example.com"]
    assert report["egress_denies_all"] is False


def test_the_report_carries_binding_names_and_no_reference_or_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AGENTS.md rule 13 is about VALUES. A binding name identifies a purpose,
    is not a reference, and cannot be dereferenced — so it is publishable to an
    operator, and nothing on this path can reach held material."""
    named = integration.ConnectorManifest(
        connector_key="planted_named",
        version="0.0.1",
        spi_range=integration.SpiRange.parse(">=1.3,<2.0"),
        capabilities=(
            integration.CapabilityDeclaration(capability_id="planted.observation.v1"),
        ),
        secret_bindings=(
            integration.SecretBindingDeclaration(name="planted_required"),
            integration.SecretBindingDeclaration(
                name="planted_optional", required=False
            ),
        ),
        egress=integration.EgressDeclaration(),
    )
    _plant(monkeypatch, named)

    report = runtime_policy.policy_report(runtime_policy.projected_policy())

    assert report["secret_bindings"] == [
        {
            "connector_key": "planted_named",
            "name": "planted_optional",
            "required": False,
        },
        {
            "connector_key": "planted_named",
            "name": "planted_required",
            "required": True,
        },
    ]
    rendered = repr(report)
    for scheme in ("env://", "file://"):
        assert scheme not in rendered


# ── 2. Omission refuses, and the refusal is proved to bite ──────────────────


def test_a_pre_spi_1_3_connector_refuses_the_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sensitivity proof (ADR-0018).

    Unreachable through this assembly's pins — every one of them declares
    `>=1.3,<2.0` — so the legacy manifest is planted. Treating the omission as
    deny-all would give the connector the APPEARANCE of declared evidence
    without any connector author ever having declared it.
    """
    _plant(monkeypatch, LEGACY_MANIFEST)

    with pytest.raises(integration.RuntimeBoundaryMissing) as raised:
        runtime_policy.require_declared_runtime_boundaries()

    assert "planted_legacy" in str(raised.value)


def test_one_legacy_connector_refuses_the_whole_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mixed installation is refused, not partially projected.

    The digest is meant to identify the manifest set the policy came from. A
    report that silently omitted the connector it could not project would carry
    a digest describing a smaller deployment than the one running.
    """
    _plant(monkeypatch, fake_manifest(connector_key="planted_modern"), LEGACY_MANIFEST)

    with pytest.raises(integration.RuntimeBoundaryMissing):
        runtime_policy.projected_policy()


def test_a_declaring_connector_is_projected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal above is only evidence if the passing case reaches a policy;
    a projection that raised on everything would satisfy it too."""
    _plant(monkeypatch, fake_manifest(connector_key="planted_modern"))

    policy = runtime_policy.require_declared_runtime_boundaries()

    assert [c.connector_key for c in policy.connectors] == ["planted_modern"]


# ── 3. Capability coverage reports; it never decides ────────────────────────


def _install_registry(*capability_ids: str) -> None:
    integration.install_capability_registry(
        integration.CapabilityRegistry.from_declarations(
            integration.CapabilityContract(
                capability_id=capability_id,
                owner=integration.CapabilityOwner(
                    application="planted_app", module="planted_module"
                ),
                summary="planted",
            )
            for capability_id in capability_ids
        )
    )


@pytest.fixture(autouse=True)
def _uninstalled_registry() -> Any:
    """The registry is process-global module state, like the held secrets.

    Reset around every test in this file so an installation made by one case
    cannot decide another's verdict — and so the `"absent"` case is genuinely
    absent rather than left over.
    """
    _reset_capability_registry()
    yield
    _reset_capability_registry()


def test_an_uninstalled_registry_is_absent_and_not_an_empty_declaration_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`PRODUCT_PORT_ENABLED=false` has declared NOTHING; it has not declared
    that nothing is true. Reporting both as `[]` would make an unconfigured
    deployment read exactly like one whose product deliberately declares no
    capability."""
    _plant(monkeypatch, fake_manifest(connector_key="planted_one"))

    coverage = runtime_policy.capability_coverage()

    assert coverage["registry"] == "absent"
    assert coverage["declared"] is None
    assert coverage["implemented_without_declaration"] is None
    assert coverage["implemented"]


def test_a_capability_no_product_declared_is_named_rather_than_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The state the settlement connectors are in.

    Refusing here would be this assembly deciding which application owns an
    observation. Reporting nothing would leave an operator looking at a green
    screen for an integration that can never be bound — the module refuses the
    destination binding, so no receipt is ever mis-delivered either way.
    """
    served = fake_manifest(
        connector_key="planted_served", capabilities=("planted.served.v1",)
    )
    unserved = fake_manifest(
        connector_key="planted_unserved", capabilities=("planted.unserved.v1",)
    )
    _plant(monkeypatch, served, unserved)
    _install_registry("planted.served.v1")

    coverage = runtime_policy.capability_coverage()

    assert coverage["registry"] == "installed"
    assert coverage["implemented_without_declaration"] == ["planted.unserved.v1"]
    assert coverage["declared_without_implementation"] == []


def test_a_declaration_no_connector_implements_is_named_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other direction, which fails differently: the contract resolves,
    every screen reads healthy, and nothing ever arrives."""
    _plant(
        monkeypatch,
        fake_manifest(
            connector_key="planted_served", capabilities=("planted.served.v1",)
        ),
    )
    _install_registry("planted.served.v1", "planted.orphan.v1")

    coverage = runtime_policy.capability_coverage()

    assert coverage["declared_without_implementation"] == ["planted.orphan.v1"]
    assert coverage["implemented_without_declaration"] == []


def test_full_coverage_reports_neither_gap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sensitivity control for both cases above: a coverage function that
    always reported a gap would satisfy them and be useless."""
    _plant(
        monkeypatch,
        fake_manifest(
            connector_key="planted_served", capabilities=("planted.served.v1",)
        ),
    )
    _install_registry("planted.served.v1")

    coverage = runtime_policy.capability_coverage()

    assert coverage["implemented_without_declaration"] == []
    assert coverage["declared_without_implementation"] == []
    assert coverage["implemented"] == coverage["declared"] == ["planted.served.v1"]
