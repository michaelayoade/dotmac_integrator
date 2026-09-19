"""The ERP invoice destination has an isolated, renderable Compose topology."""

import json
import os
import subprocess
from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"
ERP_ENV = Path(__file__).resolve().parents[2] / "deploy" / "erp-invoice.env.example"


def _compose_config(
    *, runtime: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    for name in (
        "DATABASE_URL",
        "MIGRATION_DATABASE_URL",
        "PLATFORM_ROOT_DOMAIN",
        "JWT_SECRET",
    ):
        environment.pop(name, None)
    if runtime:
        environment.update(runtime)
    return subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(ERP_ENV),
            "-f",
            str(COMPOSE),
            "config",
            "--format",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_erp_template_fails_closed_without_runtime_material() -> None:
    result = _compose_config()

    assert result.returncode != 0
    assert "DATABASE_URL" in result.stderr or "MIGRATION_DATABASE_URL" in result.stderr


def test_rendered_erp_config_is_not_the_generic_compose_alias() -> None:
    result = _compose_config(
        runtime={
            "DATABASE_URL": "postgresql+psycopg://erp_online@127.0.0.1:1/erp_invoice",
            "MIGRATION_DATABASE_URL": (
                "postgresql+psycopg://erp_owner@127.0.0.1:1/erp_invoice"
            ),
            "PLATFORM_ROOT_DOMAIN": "erp.invalid",
            "JWT_SECRET": "test-only-render-value",
        }
    )
    assert result.returncode == 0, result.stderr
    rendered = json.loads(result.stdout)

    assert rendered["name"] == "integrator-erp-invoice"
    assert rendered["networks"]["integrator"]["name"] == "integrator-erp-invoice"
    assert rendered["services"]["api"]["ports"] == [
        {
            "mode": "ingress",
            "host_ip": "127.0.0.1",
            "target": 8080,
            "published": "18081",
            "protocol": "tcp",
        }
    ]
    assert rendered["services"]["api"]["environment"]["DEPLOYMENT_ID"] == (
        "erp-invoice-accounting-sync"
    )
    assert rendered["services"]["api"]["environment"]["DATABASE_URL"] == (
        "postgresql+psycopg://erp_online@127.0.0.1:1/erp_invoice"
    )
    assert rendered["services"]["migrate"]["environment"]["MIGRATION_DATABASE_URL"] == (
        "postgresql+psycopg://erp_owner@127.0.0.1:1/erp_invoice"
    )
    assert rendered["services"]["api"]["environment"]["SECRET_FILE_ROOT"] == (
        "/run/secrets/erp-invoice"
    )


def test_product_port_controls_reach_the_api_with_fail_closed_defaults() -> None:
    source = COMPOSE.read_text(encoding="utf-8")
    template = ERP_ENV.read_text(encoding="utf-8")
    assert "name: ${COMPOSE_PROJECT_NAME:-integrator}" in source
    assert "DATABASE_URL: ${DATABASE_URL:?online platform DSN is required}" in source
    assert (
        "MIGRATION_DATABASE_URL: ${MIGRATION_DATABASE_URL:?owner DSN is required}"
        in source
    )
    assert "COMPOSE_PROJECT_NAME=integrator-erp-invoice" in template
    assert "COMPOSE_NETWORK=integrator-erp-invoice" in template
    assert "DEPLOYMENT_ID=erp-invoice-accounting-sync" in template
    assert "DATABASE_URL=" in template
    assert "MIGRATION_DATABASE_URL=" in template
    assert "PLATFORM_ROOT_DOMAIN=" in template
    assert "JWT_SECRET=" in template
    assert "postgresql://" not in template
    assert "https://" not in template
    for name, default in (
        ("PRODUCT_PORT_ENABLED", "false"),
        ("PRODUCT_PORT_MODE", "mirror"),
        ("PRODUCT_PORT_DESCRIPTOR_URL", ""),
        ("PRODUCT_PORT_DESCRIPTOR_EXPECTED_DIGEST", ""),
        ("PRODUCT_PORT_API_KEY_REF", ""),
        ("PRODUCT_PORT_SHADOW_REVISION", ""),
    ):
        assert f"{name}: ${{{name}:-{default}}}" in source
