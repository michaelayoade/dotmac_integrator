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
        "product_port_descriptor_url": "https://destination.example/descriptor",
        "product_port_descriptor_expected_digest": "a" * 64,
        "product_port_api_key_ref": "env://INTEGRATOR_SECRET_DESTINATION",
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


def test_descriptor_digest_is_validated_before_boot() -> None:
    problems = validate_settings(
        _configured_product_port(
            product_port_descriptor_expected_digest="A" * 64,
        )
    )

    assert any(
        "PRODUCT_PORT_DESCRIPTOR_EXPECTED_DIGEST" in problem for problem in problems
    )


def test_the_assembly_does_not_accept_a_parallel_binding_id_list() -> None:
    fields = Settings.model_fields

    assert "product_port_local_binding_id" not in fields
    assert "product_port_local_binding_ids" not in fields


def test_production_start_does_not_require_the_owner_dsn() -> None:
    """The api and worker are given no MIGRATION_DATABASE_URL at all.

    `docker-compose.yml` says so in as many words — "There is no
    MIGRATION_DATABASE_URL in this service's environment at all" — because the
    online role cannot create a table and the owner credential must not sit in
    the two long-running processes.

    Refusing to start them over that unset value would force exactly the
    credential the compose withholds into exactly the processes it withholds it
    from. This is the state a real production deployment is in, and it was found
    by the first one: the shipped compose and the shipped validation contradicted
    each other, and the api crash-looped.
    """

    settings = Settings(
        environment="production",
        deployment_id="integrator-prod",
        database_url="postgresql+psycopg://platform_api:pw@db:5432/integrator",
        host="0.0.0.0",  # noqa: S104 — a container binds its interface
        platform_root_domain="integrator.dotmac.io",
        jwt_secret="x" * 32,
        metrics_enabled=False,
    )

    problems = validate_settings(settings)

    assert not any("MIGRATION_DATABASE_URL" in problem for problem in problems), (
        problems
    )


def test_a_migration_dsn_that_was_SET_to_localhost_is_still_refused() -> None:
    """Sensitivity: the check must still bite where it was meant to.

    Scoping it to "was set" would be worthless if it also stopped catching the
    deployment that set it and left the example's localhost in place — which is
    the mistake the check exists for.
    """

    settings = Settings(
        environment="production",
        deployment_id="integrator-prod",
        database_url="postgresql+psycopg://platform_api:pw@db:5432/integrator",
        migration_database_url=(
            "postgresql+psycopg://app_admin:pw@localhost:5432/integrator"
        ),
        host="0.0.0.0",  # noqa: S104 — a container binds its interface
        platform_root_domain="integrator.dotmac.io",
        jwt_secret="x" * 32,
        metrics_enabled=False,
    )

    problems = validate_settings(settings)

    assert any("MIGRATION_DATABASE_URL" in problem for problem in problems)
