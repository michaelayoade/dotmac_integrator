"""The operator guard, driven per route rather than reasoned about.

`tests/architecture/test_operator_surface.py` proves every `/operations` route
DECLARES the dependency. This proves the declaration does something: each route
is called with no credential and must answer 401 — not 200, and not 500.

The 500 matters as much as the 200. A 500 means the request reached real
business logic and died on the database instead of being turned away, which is
the shape a missing guard takes when the handler happens to need a connection
the test does not have. The Starter learned that with its non-admin sweep.

Nothing here needs a database: every assertion is about a decision made before a
query would be issued, and the DSN points at a port nothing listens on so a
regression cannot pass by accident.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from dotmac_integrator.assembly import create_app
from tests.support import build_settings

SAMPLE_UUID = "00000000-0000-4000-8000-000000000000"


def _client() -> TestClient:
    # NOT used as a context manager, deliberately: entering runs the lifespan,
    # which loads secret material from a database these tests do not have.
    return TestClient(create_app(build_settings()))


def _operations_routes() -> list[tuple[str, str]]:
    app = create_app(build_settings())
    calls: list[tuple[str, str]] = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/operations/"):
            continue
        concrete = route.path
        for parameter in ("installation_id", "delivery_id", "receipt_id"):
            concrete = concrete.replace(f"{{{parameter}}}", SAMPLE_UUID)
        for method in sorted(route.methods or set()):
            if method in {"HEAD", "OPTIONS"}:
                continue
            calls.append((method, concrete))
    return calls


ROUTES = _operations_routes()


def test_the_sweep_found_routes_to_drive() -> None:
    """Sensitivity proof: an empty parametrization collects zero cases and
    reports success, which is exactly how this guard would stop working."""
    assert len(ROUTES) >= 7, ROUTES
    assert any(method == "POST" for method, _ in ROUTES)
    assert any(method == "GET" for method, _ in ROUTES)


@pytest.mark.parametrize(("method", "path"), ROUTES)
def test_no_operations_route_answers_without_a_credential(
    method: str, path: str
) -> None:
    response = _client().request(method, path, json={"reason": "a stated reason"})
    assert response.status_code == 401, (
        f"{method} {path} answered {response.status_code}. A 200 means the "
        "route is open; a 500 means it reached business logic and died there, "
        "which is what a missing guard looks like when the handler needs a "
        "connection"
    )


@pytest.mark.parametrize(
    "header",
    [
        "",
        "Basic dXNlcjpwYXNz",
        "Bearer",
        "bearer ",
        "Token abcdef",
    ],
)
def test_a_malformed_authorization_header_is_not_a_credential(header: str) -> None:
    response = _client().get(
        "/operations/connectors", headers={"Authorization": header}
    )
    assert response.status_code == 401


def test_a_bearer_token_on_the_wrong_host_is_refused_without_a_query() -> None:
    """Host-exact, and checked FIRST.

    The kernel's platform predicate compares the request host to the configured
    platform root before it looks anything up, so an operator surface exposed on
    an unexpected hostname refuses without a database round trip. Asserted
    because it is load-bearing here: this deployment's DSN is unreachable in
    these tests, so a 401 proves the check happened before the query.
    """
    response = _client().get(
        "/operations/connectors",
        headers={"Authorization": "Bearer not-a-real-token", "Host": "elsewhere.test"},
    )
    assert response.status_code == 401


def test_a_misconfigured_mechanism_refuses_to_serve_rather_than_skipping() -> None:
    """503, never a pass.

    `create_app` already refuses to boot on this (see below), so reaching the
    guard with a bad mechanism takes a deliberate mutation. It is asserted
    anyway: the two checks fail in opposite directions, and the dangerous
    direction is a guard that treats "no mechanism" as "no check".
    """
    app = create_app(build_settings())
    app.state.settings = app.state.settings.model_copy(
        update={"operator_auth_mechanism": "none"}
    )
    response = TestClient(app).get(
        "/operations/connectors", headers={"Authorization": "Bearer anything"}
    )
    assert response.status_code == 503


def test_the_app_refuses_to_boot_with_an_unimplemented_mechanism() -> None:
    with pytest.raises(RuntimeError, match="OPERATOR_AUTH_MECHANISM"):
        create_app(build_settings(operator_auth_mechanism="none"))


# ── Probes stay open ────────────────────────────────────────────────────────


@pytest.mark.parametrize("path", ["/health/live", "/health/composition"])
def test_probes_need_no_credential(path: str) -> None:
    assert _client().get(path).status_code == 200


def test_readiness_reports_rather_than_raising_when_the_database_is_gone() -> None:
    """A readiness probe that raises gives the orchestrator a 500 with no body,
    which reads as a crash rather than as "not ready yet"."""
    response = _client().get("/health/ready")
    assert response.status_code == 503
    body: dict[str, Any] = response.json()
    assert body["database"] == "unreachable"
