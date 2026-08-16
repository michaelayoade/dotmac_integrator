"""Every route is classified, and each class's rule is proved to bite.

`create_app` already refuses to return an app whose surface breaks a rule, so
the first test here is nearly a formality — it fails only if the mounted
surface regressed. The rest is the part that matters: an auditor that reports
nothing is evidence only once it has been shown to report something.

The planted app is deliberately built out of the mistakes that are actually
available to make. Each of them is one plausible diff away:

* mounting the coming ingress adapter at `/webhooks/...` — unclassified, so no
  rule applies to it at all;
* copying an operations route and forgetting the guard;
* copying one and forgetting the reason;
* giving the ingress adapter the operator guard "for now";
* putting the guard on `/health/ready` so the probe "is consistent";
* hanging endpoint rotation off the ingress router because that is where the
  provider's credential is used.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI

from dotmac_integrator.assembly import create_app
from dotmac_integrator.operator_auth import OperationReason, Operator
from dotmac_integrator.surface import (
    CREDENTIAL_LIFECYCLE_VERBS,
    RouteClass,
    SurfaceViolation,
    audit_routes,
    classify,
    require_a_correct_surface,
)
from tests.support import build_settings


def test_the_real_surface_is_correct() -> None:
    assert audit_routes(create_app(build_settings())) == []


def test_every_mounted_route_is_classified() -> None:
    """Read positively: the audit above would also pass over an empty app."""
    from fastapi.routing import APIRoute

    app = create_app(build_settings())
    paths = [r.path for r in app.routes if isinstance(r, APIRoute)]
    assert len(paths) >= 9, paths
    assert all(classify(path) is not None for path in paths)
    classes = {classify(path) for path in paths}
    assert RouteClass.OPERATOR in classes
    assert RouteClass.PROBE in classes


def test_no_ingress_route_is_mounted_yet() -> None:
    """The classification exists BEFORE the surface it governs.

    Slice 3 of the assembly plan (the public ingress adapter) waits for the
    module release. Asserted so that whoever lands it reads this file first —
    the rule they must satisfy is already written, and it is the one that keeps
    a provider's signature scheme and an operator's bearer token apart.
    """
    from fastapi.routing import APIRoute

    app = create_app(build_settings())
    assert not [
        r.path
        for r in app.routes
        if isinstance(r, APIRoute) and classify(r.path) is RouteClass.INGRESS
    ]


# ── Sensitivity proof (ADR-0018) ────────────────────────────────────────────


def _planted() -> FastAPI:
    app = FastAPI()

    @app.post("/webhooks/provider")
    def unclassified() -> dict[str, str]:
        return {}

    @app.post("/operations/unguarded")
    def unguarded(body: OperationReason) -> dict[str, str]:
        return {}

    @app.post("/operations/reasonless")
    def reasonless(_actor: Operator) -> dict[str, str]:
        return {}

    @app.post("/ingress/provider")
    def ingress_with_operator_guard(_actor: Operator) -> dict[str, str]:
        return {}

    @app.get("/health/ready")
    def guarded_probe(_actor: Operator) -> dict[str, str]:
        return {}

    @app.post("/ingress/endpoints/rotate")
    def rotation_outside_the_operator_surface() -> dict[str, str]:
        return {}

    return app


def test_the_auditor_reports_every_planted_mistake() -> None:
    violations = "\n".join(audit_routes(_planted()))

    assert "/webhooks/provider is unclassified" in violations
    assert "/operations/unguarded" in violations and "require_operator" in violations
    assert "/operations/reasonless" in violations and "OperationReason" in violations
    assert "/ingress/provider" in violations and "public ingress" in violations
    assert "/health/ready" in violations and "probe carrying the operator" in violations
    assert "/ingress/endpoints/rotate" in violations


def test_require_a_correct_surface_raises_on_the_planted_app() -> None:
    with pytest.raises(SurfaceViolation):
        require_a_correct_surface(_planted())


def test_the_credential_verb_list_is_not_empty() -> None:
    """The verb scan iterates this tuple. Empty, it would inspect nothing while
    every case above still passed on its other rules."""
    assert set(CREDENTIAL_LIFECYCLE_VERBS) >= {"mint", "rotate", "revoke"}


def test_a_credential_verb_on_an_operator_path_is_accepted() -> None:
    """The other direction: the verb rule must not forbid the correct
    placement, or the first real rotation route gets it deleted."""
    app = FastAPI()

    @app.post("/operations/secrets/refresh")
    def refresh(body: OperationReason, _actor: Operator) -> dict[str, str]:
        return {}

    assert audit_routes(app) == []
