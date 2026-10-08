"""The host-local Traccar profile preserves the Integrator runtime boundary."""

from __future__ import annotations

import copy
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "deploy" / "traccar-host" / "compose.yml"


def _document() -> dict[str, object]:
    document = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _traccar_network_violations(document: dict[str, object]) -> list[str]:
    services = document.get("services")
    assert isinstance(services, dict)
    violations: list[str] = []
    for name, value in services.items():
        assert isinstance(name, str)
        assert isinstance(value, dict)
        networks = value.get("networks", [])
        if "traccar_api" in networks and name != "integrator-traccar-api":
            violations.append(name)
    return violations


def test_only_integrator_api_joins_private_traccar_network() -> None:
    document = _document()
    services = document["services"]
    networks = document["networks"]
    assert isinstance(services, dict)
    assert isinstance(networks, dict)
    assert _traccar_network_violations(document) == []
    assert "traccar_api" in services["integrator-traccar-api"]["networks"]
    assert networks["traccar_api"]["external"] is True
    assert networks["traccar_api"]["name"] == (
        "${TRACCAR_API_NETWORK:-dotmac_traccar_api}"
    )


def test_traccar_network_detector_rejects_an_erp_service() -> None:
    document = copy.deepcopy(_document())
    services = document["services"]
    assert isinstance(services, dict)
    services["dotmac_erp_app"] = {"networks": ["traccar_api"]}
    assert _traccar_network_violations(document) == ["dotmac_erp_app"]


def test_provider_material_is_exact_read_only_files_on_integrator_api() -> None:
    document = _document()
    services = document["services"]
    secrets = document["secrets"]
    assert isinstance(services, dict)
    assert isinstance(secrets, dict)
    api = services["integrator-traccar-api"]
    migrate = services["integrator-traccar-migrate"]
    mounted = {item["source"]: item for item in api["secrets"]}
    assert set(mounted) == {
        "traccar_service_email",
        "traccar_service_password",
        "erp_contract_registry_api_key",
    }
    assert mounted["traccar_service_email"]["target"] == "traccar/service_email"
    assert mounted["traccar_service_password"]["target"] == ("traccar/service_password")
    assert all(item["mode"] == 0o400 for item in mounted.values())
    assert "secrets" not in migrate
    assert "TRACCAR_SERVICE_EMAIL_FILE" in secrets["traccar_service_email"]["file"]
    assert (
        "TRACCAR_SERVICE_PASSWORD_FILE" in (secrets["traccar_service_password"]["file"])
    )


def test_profile_exposes_only_loopback_integrator_contract() -> None:
    document = _document()
    services = document["services"]
    assert isinstance(services, dict)
    published = [
        port
        for service in services.values()
        if isinstance(service, dict)
        for port in service.get("ports", [])
    ]
    assert len(published) == 1
    assert published[0]["host_ip"] == "127.0.0.1"
    assert published[0]["target"] == 8080
    rendered = PROFILE.read_text(encoding="utf-8")
    assert "5001" not in rendered
    assert "8082" not in rendered
    assert "5432" not in rendered


def test_profile_uses_the_exact_released_module_and_connector() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = project["tool"]["poetry"]["dependencies"]
    assert dependencies["dotmac-integration"] == "0.1.0a18"
    assert dependencies["dotmac-connector-traccar"] == "0.1.0a1"

    lock = tomllib.loads((ROOT / "poetry.lock").read_text(encoding="utf-8"))
    versions = {package["name"]: package["version"] for package in lock["package"]}
    assert versions["dotmac-integration"] == "0.1.0a18"
    assert versions["dotmac-connector-traccar"] == "0.1.0a1"


def test_profile_requires_an_operator_supplied_image_and_never_defaults_latest() -> (
    None
):
    document = _document()
    image = document["x-image"]
    assert isinstance(image, str)
    assert "INTEGRATOR_TRACCAR_IMAGE:?" in image
    assert "latest" not in image
