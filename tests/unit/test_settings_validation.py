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


def test_an_enabled_machine_command_surface_requires_all_held_key_refs() -> None:
    problems = validate_settings(build_settings(command_surface_enabled=True))
    assert any("COMMAND_AUDIENCE" in problem for problem in problems)
    assert any("COMMAND_PUBLIC_KEY_REFS" in problem for problem in problems)
    assert any("COMMAND_ISSUER_ASSIGNMENTS_REF" in problem for problem in problems)
    assert any("RECEIPT_SIGNING_KEY_ID" in problem for problem in problems)
    assert any("RECEIPT_SIGNING_PRIVATE_KEY_REF" in problem for problem in problems)


def test_machine_command_key_references_are_valid_and_distinct() -> None:
    settings = build_settings(
        command_surface_enabled=True,
        command_audience="dotmac-integrator:test",
        command_public_key_refs=("issuer-1=env://INTEGRATOR_SECRET_SHARED_KEY"),
        command_issuer_assignments_ref=("env://INTEGRATOR_SECRET_ISSUER_ASSIGNMENTS"),
        receipt_signing_key_id="receipt-1",
        receipt_signing_private_key_ref=("env://INTEGRATOR_SECRET_SHARED_KEY"),
    )
    problems = validate_settings(settings)
    assert any("must be distinct" in problem for problem in problems)


def test_issuer_assignment_document_cannot_alias_key_material() -> None:
    settings = build_settings(
        command_surface_enabled=True,
        command_audience="dotmac-integrator:test",
        command_public_key_refs=("issuer-1=env://INTEGRATOR_SECRET_ISSUER_PUBLIC"),
        command_issuer_assignments_ref=("env://INTEGRATOR_SECRET_ISSUER_PUBLIC"),
        receipt_signing_key_id="receipt-1",
        receipt_signing_private_key_ref=("env://INTEGRATOR_SECRET_RECEIPT_PRIVATE"),
    )
    assert any(
        "issuer-assignment reference must be distinct" in problem
        for problem in validate_settings(settings)
    )


def test_a_complete_machine_command_configuration_is_accepted() -> None:
    settings = build_settings(
        command_surface_enabled=True,
        command_audience="dotmac-integrator:test",
        command_public_key_refs=("issuer-1=env://INTEGRATOR_SECRET_ISSUER_PUBLIC"),
        command_issuer_assignments_ref=("env://INTEGRATOR_SECRET_ISSUER_ASSIGNMENTS"),
        receipt_signing_key_id="receipt-1",
        receipt_signing_private_key_ref=("env://INTEGRATOR_SECRET_RECEIPT_PRIVATE"),
    )
    assert validate_settings(settings) == []
