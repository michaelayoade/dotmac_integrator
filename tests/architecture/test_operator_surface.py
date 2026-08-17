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
from dotmac_kernel.audit_actions import AuditActionRegistry
from fastapi import FastAPI

from dotmac_integrator import assembly
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

#: The configured scrape path. Passed to every audit here rather than assumed,
#: because `METRICS_PATH` is a knob and `classify` is deliberately told its
#: value instead of hardcoding one — see `surface.classify`.
METRICS_PATH = "/metrics"


def test_the_real_surface_is_correct() -> None:
    settings = build_settings()
    assert audit_routes(create_app(settings), metrics_path=settings.metrics_path) == []


def test_the_provider_neutral_authoring_routes_are_mounted() -> None:
    """The first connector can be installed without a provider-shaped route.

    The assembly supplies one generic lifecycle surface.  A connector appears
    here only through entry-point discovery and operator-supplied identifiers;
    adding the next connector must not add another route.
    """
    from fastapi.routing import APIRoute

    app = create_app(build_settings())
    mounted = {
        (method, route.path)
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in route.methods or set()
    }
    expected = {
        ("POST", "/operations/installations"),
        ("POST", "/operations/installations/{installation_id}/bindings"),
        ("POST", "/operations/installations/{installation_id}/config-revisions"),
        ("POST", "/operations/bindings/{binding_id}/ingress-endpoint/mint"),
        ("POST", "/operations/bindings/{binding_id}/enable"),
    }
    assert expected <= mounted, sorted(expected - mounted)


def test_app_construction_installs_the_composed_audit_vocabulary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed: list[AuditActionRegistry] = []
    monkeypatch.setattr(assembly, "install_audit_actions", installed.append)

    create_app(build_settings())

    assert len(installed) == 1
    registry = installed[0]
    assert registry.actions() >= {
        "integrator.secrets.refreshed",
        "integration.delivery.replayed",
    }


def test_every_mounted_route_is_classified() -> None:
    """Read positively: the audit above would also pass over an empty app."""
    from fastapi.routing import APIRoute

    settings = build_settings()
    app = create_app(settings)
    paths = [r.path for r in app.routes if isinstance(r, APIRoute)]
    assert len(paths) >= 9, paths
    assert all(
        classify(path, metrics_path=settings.metrics_path) is not None for path in paths
    )
    classes = {classify(path, metrics_path=settings.metrics_path) for path in paths}
    assert RouteClass.OPERATOR in classes
    assert RouteClass.PROBE in classes
    assert RouteClass.SCRAPE in classes


def test_the_ingress_routes_are_mounted_and_carry_no_operator_guard() -> None:
    """The rule was written before the surface it governs; this is the surface.

    `/ingress/**` is a PROVIDER calling in. It authenticates by that provider's
    own signature scheme, inside the connector that knows it, and it must never
    carry `require_operator` — a provider holds no operator credential, so
    sharing the guard ends with the operator guard loosened until both fit
    through it. `audit_routes` enforces that; this asserts the routes exist, so
    the enforcement is not passing over an empty set.
    """
    from fastapi.routing import APIRoute

    settings = build_settings()
    app = create_app(settings)
    ingress_routes = [
        r
        for r in app.routes
        if isinstance(r, APIRoute)
        and classify(r.path, metrics_path=settings.metrics_path) is RouteClass.INGRESS
    ]
    assert ingress_routes, "the ingress adapter is not mounted"

    methods = {m for r in ingress_routes for m in (r.methods or set())} - {"HEAD"}
    # TWO operations with two eligibility rules, stated by the request line
    # rather than guessed from a byte count. Inferring a handshake from an empty
    # body is wrong in both directions: a bodyless POST is still a delivery, and
    # a provider that confirms a subscription with a bodied request could not
    # handshake at all.
    assert methods == {"GET", "POST"}, methods

    assert audit_routes(app, metrics_path=settings.metrics_path) == []


def test_ingress_is_not_mounted_when_the_deployment_turns_it_off() -> None:
    """The other direction, and a real deployment shape: an operator-and-worker
    replica in a different network zone from the one taking provider traffic."""
    from fastapi.routing import APIRoute

    settings = build_settings(ingress_enabled=False)
    app = create_app(settings)
    assert not [
        r
        for r in app.routes
        if isinstance(r, APIRoute)
        and classify(r.path, metrics_path=settings.metrics_path) is RouteClass.INGRESS
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

    # The scrape endpoint with its authentication written in the handler BODY
    # instead of as a dependency — which is exactly what it looked like before
    # `ScrapeGuard` existed, and exactly what the dependency walk cannot see.
    @app.get("/metrics")
    def unguarded_scrape() -> dict[str, str]:
        return {}

    return app


def test_the_auditor_reports_every_planted_mistake() -> None:
    violations = "\n".join(audit_routes(_planted(), metrics_path=METRICS_PATH))

    assert "/webhooks/provider is unclassified" in violations
    assert "/operations/unguarded" in violations and "require_operator" in violations
    assert "/operations/reasonless" in violations and "OperationReason" in violations
    assert "/ingress/provider" in violations and "public ingress" in violations
    assert "/health/ready" in violations and "probe carrying the operator" in violations
    assert "/ingress/endpoints/rotate" in violations
    assert "/metrics" in violations and "ScrapeGuard" in violations


def test_require_a_correct_surface_raises_on_the_planted_app() -> None:
    with pytest.raises(SurfaceViolation):
        require_a_correct_surface(_planted(), metrics_path=METRICS_PATH)


# ── The SCRAPE class, both directions ───────────────────────────────────────


def test_an_unclassified_metrics_path_is_reported_rather_than_waved_through() -> None:
    """`METRICS_PATH` is a knob, so the auditor is TOLD the value.

    A deployment that moved the scrape endpoint and an auditor that assumed
    `/metrics` would disagree silently, and the disagreement resolves in the
    unsafe direction: the route falls out of every class and out of every rule.
    Here the auditor is told the wrong path, and the real one must be reported
    as unclassified rather than quietly accepted.
    """
    app = FastAPI()

    @app.get("/internal/telemetry")
    def moved_scrape() -> dict[str, str]:
        return {}

    violations = "\n".join(audit_routes(app, metrics_path="/metrics"))
    assert "/internal/telemetry is unclassified" in violations

    # Told the truth, the same route is a correctly-classified SCRAPE route —
    # which then fails only for the reason it should: it carries no guard.
    violations = "\n".join(audit_routes(app, metrics_path="/internal/telemetry"))
    assert "unclassified" not in violations
    assert "ScrapeGuard" in violations


def test_a_guarded_read_only_scrape_route_is_accepted() -> None:
    """The other direction. A rule that reported every scrape route as a
    violation would be removed the first time someone shipped a correct one."""
    from fastapi import Depends

    from dotmac_integrator.telemetry import ScrapeGuard

    app = FastAPI()

    @app.get("/metrics", dependencies=[Depends(ScrapeGuard(build_settings()))])
    def scrape() -> dict[str, str]:
        return {}

    assert audit_routes(app, metrics_path="/metrics") == []


def test_a_scrape_route_may_not_carry_the_operator_guard_or_mutate() -> None:
    """A monitoring system holds a scrape token, not an operator identity."""
    from fastapi import Depends

    from dotmac_integrator.telemetry import ScrapeGuard

    app = FastAPI()

    @app.post("/metrics", dependencies=[Depends(ScrapeGuard(build_settings()))])
    def mutating_scrape(_actor: Operator) -> dict[str, str]:
        return {}

    violations = "\n".join(audit_routes(app, metrics_path="/metrics"))
    assert "carrying the operator guard" in violations
    assert "mutating scrape" in violations


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

    assert audit_routes(app, metrics_path=METRICS_PATH) == []
