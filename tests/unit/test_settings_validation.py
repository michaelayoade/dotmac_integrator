"""The prod-fatal list, exercised against what it must refuse.

A validation function is only evidence once it has been shown to fail. Every
case here is a configuration that WOULD start a production deployment looking
healthy, which is the failure mode `validate_settings` exists to prevent —
a control plane on loopback with a signing secret published in the kernel's
source is worse than one that did not start, because nothing pages anyone.
"""

from __future__ import annotations

import pytest

from dotmac_integrator.settings import (
    OPERATOR_AUTH_MECHANISMS,
    Settings,
    validate_settings,
)
from tests.support import UNREACHABLE_DSN, build_settings


def _production(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "environment": "production",
        "deployment_id": "integrator-abuja",
        "database_url": "postgresql+psycopg://platform_api@db.internal:5432/integrator",
        "migration_database_url": (
            "postgresql+psycopg://app_admin@db.internal:5432/integrator"
        ),
        "host": "0.0.0.0",  # noqa: S104 — a container binds its interface
        "platform_root_domain": "integrator.dotmac.io",
        "jwt_secret": "a-real-signing-secret-from-the-store",
        "secret_file_root": "/run/secrets",
        # The scrape endpoint is prod-fatal without a token. Present here
        # because this fixture's whole job is to be a configuration with
        # NOTHING wrong with it — a missing knob would make the "no problems"
        # direction pass for the wrong reason.
        "metrics_token": "a-real-scrape-token-from-the-store",
    }
    return Settings(**{**base, **overrides})  # type: ignore[arg-type]


def test_a_correct_production_configuration_has_no_problems() -> None:
    """The other direction. Without this, a validator that returned a complaint
    for everything would pass every case below."""
    assert validate_settings(_production()) == []


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"deployment_id": "integrator-local"}, "DEPLOYMENT_ID"),
        (
            {"database_url": UNREACHABLE_DSN.replace("127.0.0.1", "localhost")},
            "DATABASE_URL",
        ),
        (
            {"migration_database_url": "postgresql+psycopg://app_admin@localhost/x"},
            "MIGRATION_DATABASE_URL",
        ),
        ({"host": "127.0.0.1"}, "HOST"),
        ({"platform_root_domain": "localhost"}, "PLATFORM_ROOT_DOMAIN"),
        ({"jwt_secret": "dev-insecure-change-me"}, "JWT_SECRET"),
        ({"secret_file_root": "/tmp/secrets"}, "SECRET_FILE_ROOT"),  # noqa: S108
    ],
)
def test_each_unsafe_production_value_is_fatal(
    override: dict[str, object], expected: str
) -> None:
    problems = validate_settings(_production(**override))
    assert any(expected in problem for problem in problems), problems


def test_an_unimplemented_operator_mechanism_is_fatal_outside_production_too() -> None:
    """The one unconditional check.

    Every other entry is about a production default being left in place. This
    one is about the operations surface having no working authentication at
    all, and a development deployment with an open control plane is how the
    'temporary' bypass reaches production.
    """
    problems = validate_settings(build_settings(operator_auth_mechanism="none"))
    assert any("OPERATOR_AUTH_MECHANISM" in problem for problem in problems)


def test_the_implemented_mechanism_passes_everywhere() -> None:
    assert OPERATOR_AUTH_MECHANISMS == ("platform_admin",)
    assert validate_settings(build_settings()) == []


def _configured_product_port(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "product_port_enabled": True,
        "product_port_mode": "mirror",
        "product_port_application": "destination",
        "product_port_base_url": "https://destination.example",
        "product_port_api_key_ref": "env://INTEGRATOR_SECRET_DESTINATION",
        "product_port_bindings": (
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa="
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        ),
        "product_port_capabilities": (
            "messaging.receive.v1 = destination/communications : observations"
        ),
        "product_port_shadow_revision": "image-sha256:comparison-v1",
    }
    return build_settings(**{**base, **overrides})


def test_a_shadow_port_requires_an_explicit_comparison_revision() -> None:
    problems = validate_settings(
        _configured_product_port(product_port_shadow_revision="")
    )

    assert any("PRODUCT_PORT_SHADOW_REVISION" in problem for problem in problems)


def test_a_configured_shadow_revision_and_retry_interval_are_accepted() -> None:
    settings = _configured_product_port(product_port_shadow_retry_seconds=90)

    assert validate_settings(settings) == []
    assert settings.product_port_shadow_revision == "image-sha256:comparison-v1"
    assert settings.product_port_shadow_retry_seconds == 90


def test_write_mode_does_not_invent_a_shadow_revision_requirement() -> None:
    assert (
        validate_settings(
            _configured_product_port(
                product_port_mode="write", product_port_shadow_revision=""
            )
        )
        == []
    )
