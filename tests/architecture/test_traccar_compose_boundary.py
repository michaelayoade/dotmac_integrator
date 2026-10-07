"""The Integrator compose boundary keeps Traccar private and ERP-independent."""

from __future__ import annotations

from pathlib import Path

import yaml

COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"


def _document() -> dict[str, object]:
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def test_only_api_joins_the_private_traccar_network_and_mounts_material() -> None:
    document = _document()
    services = document["services"]
    networks = document["networks"]
    assert isinstance(services, dict)
    assert isinstance(networks, dict)

    api = services["api"]
    migrate = services["migrate"]
    assert isinstance(api, dict)
    assert isinstance(migrate, dict)
    assert "dotmac_traccar_api" in api["networks"]
    assert "dotmac_traccar_api" not in migrate["networks"]
    assert networks["dotmac_traccar_api"]["external"] is True

    mounts = [
        mount
        for mount in api["volumes"]
        if isinstance(mount, dict) and str(mount.get("target", "")).endswith("/traccar")
    ]
    assert len(mounts) == 1
    assert mounts[0]["read_only"] is True
    assert "TRACCAR_SECRET_FILE_ROOT_HOST" in mounts[0]["source"]


def test_compose_publishes_no_provider_or_database_ports() -> None:
    document = _document()
    services = document["services"]
    assert isinstance(services, dict)
    published = [
        str(port)
        for service in services.values()
        if isinstance(service, dict)
        for port in service.get("ports", [])
    ]
    assert all(":5001" not in port for port in published)
    assert all(":8082" not in port for port in published)
    assert all(":5432" not in port for port in published)
    assert any(
        "BIND_ADDRESS:-127.0.0.1" in port and "PUBLISHED_PORT:-8080" in port
        for port in published
    )
