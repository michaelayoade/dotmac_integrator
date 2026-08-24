"""Every route belongs to exactly one class, and each class has its own rules.

The failure this exists to prevent is specific and near: the public ingress
adapter has not been written yet. When it is, it will be an HTTP endpoint a
provider POSTs to, authenticated by that provider's signature scheme and by
nothing else — and the shortest way to ship it is to hang it off the same
router as everything else and inherit the operator dependency. That would
either lock the provider out or, far worse, be "fixed" by loosening the
operator guard until both fit through it.

So the classification is declared BEFORE the surface it will govern exists,
and `create_app` runs the audit over its own routes at construction. A
violation is a boot failure, not a test failure — the test's job is only to
prove the auditor bites.

============================ ===============================================
`PROBE`      `/health/**`    Unauthenticated by design. An orchestrator
                             cannot present a credential, and a probe that
                             503s on an auth outage takes down a healthy
                             replica. Read-only, always.
`OPERATOR`   `/operations/**` A person acting on the control plane. Every
                             route — reads included — carries
                             `require_operator`; every mutation additionally
                             carries a required `reason`.
`INGRESS`    `/ingress/**`   A PROVIDER calling in. Authenticated by that
                             provider's own scheme, inside the connector that
                             knows it. Must never carry the operator guard:
                             the two populations share no credential, no
                             token audience and no failure mode.
`COMMAND`    `/commands/**`  A PRODUCT application asking for a typed
                             capability. Authenticated by the held command
                             credential; it names no provider, connector or
                             installation and every operation mutates.
`SCRAPE`     `METRICS_PATH`  A monitoring system. Read-only, and
                             authenticated by a scrape token that is neither
                             an operator credential nor a provider signature.
============================ ===============================================

## Why `/metrics` is a fourth class and not a probe

It is the closest fit and it is still wrong. PROBE's rule is that the route is
*unauthenticated by design*, because an orchestrator cannot present a
credential — so filing `/metrics` there would licence someone to remove its
token later and audit clean while doing it. `/metrics` publishes queue depths,
dead-letter counts and this deployment's operational shape; it must
authenticate. A fourth population with its own rule is the honest model, and
the rule it gets is the inverse of PROBE's: it MUST carry a guard.

Its path is the configured `METRICS_PATH` rather than a fixed prefix, so
`classify` is told the configured value. A knob whose value changes which
rules apply cannot be classified by a constant.

## Why reads are guarded too

`GET /operations/connectors` lists every integration this fleet runs and
`GET /operations/health-report` says which of them are stuck. That is a map of
where to push and when nobody is watching, not a status page.

## Credential-lifecycle verbs

`mint`, `rotate`, `revoke` and `refresh` may appear only on an OPERATOR path.
Naming is a weak signal in general, but here it is exact: these four words
describe operations on the material that authenticates everything else, and a
path containing one that is reachable without an operator identity is a
mistake with no benign reading.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from enum import StrEnum
from typing import Any, get_type_hints

from fastapi import FastAPI
from fastapi.routing import APIRoute

from dotmac_integrator.command_port import require_command_port
from dotmac_integrator.operator_auth import OperationReason, require_operator
from dotmac_integrator.telemetry import ScrapeGuard

__all__ = [
    "CREDENTIAL_LIFECYCLE_VERBS",
    "MUTATING_METHODS",
    "RouteClass",
    "SurfaceViolation",
    "audit_routes",
    "classify",
    "require_a_correct_surface",
]

MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: Verbs describing operations on authentication material itself.
CREDENTIAL_LIFECYCLE_VERBS = ("mint", "rotate", "revoke", "refresh")


class RouteClass(StrEnum):
    PROBE = "probe"
    OPERATOR = "operator"
    INGRESS = "ingress"
    COMMAND = "command"
    SCRAPE = "scrape"


#: Prefix → class. Derived, not a second list of routes to keep in sync with
#: `assembly.py`: a hand-maintained route table drifts, and the drift is
#: invisible until the unclassified route is the one that mattered.
_PREFIXES: tuple[tuple[str, RouteClass], ...] = (
    ("/health/", RouteClass.PROBE),
    ("/operations/", RouteClass.OPERATOR),
    ("/ingress/", RouteClass.INGRESS),
    ("/commands/", RouteClass.COMMAND),
)


class SurfaceViolation(RuntimeError):
    """The mounted surface breaks a class rule. Raised at app construction."""


def classify(path: str, *, metrics_path: str | None = None) -> RouteClass | None:
    """The class governing `path`, or `None` when nothing does.

    `metrics_path` is passed rather than assumed because it is a deployment
    knob (`METRICS_PATH`). Hardcoding `/metrics` here would silently unclassify
    the scrape endpoint of any deployment that moved it — and an unclassified
    route is exactly what this module refuses to serve.
    """
    if metrics_path and path == metrics_path:
        return RouteClass.SCRAPE
    for prefix, route_class in _PREFIXES:
        if path.startswith(prefix):
            return route_class
    return None


def _dependency_calls(route: APIRoute) -> set[Callable[..., Any]]:
    """Every dependency callable reachable from this route, at any depth.

    Recursive because `Depends(a)` where `a` itself depends on the guard is
    still guarded, and a check that only looked one level down would force
    every future composition to be flat.
    """
    found: set[Callable[..., Any]] = set()

    def walk(dependant: Any) -> None:
        for sub in getattr(dependant, "dependencies", ()):
            call = getattr(sub, "call", None)
            if call is not None:
                found.add(call)
            walk(sub)

    walk(route.dependant)
    return found


def _takes_a_reason(route: APIRoute) -> bool:
    """The endpoint accepts an `OperationReason` body parameter.

    `get_type_hints`, not `inspect.signature`. Every module here starts with
    `from __future__ import annotations`, so a raw signature yields the STRING
    `"OperationReason"`. Subclasses count too: authoring payloads add fields but
    inherit the same mandatory reason, and an identity-only check would reject
    every correctly guarded authoring route.
    """
    try:
        hints = get_type_hints(route.endpoint)
    except (NameError, TypeError):  # pragma: no cover — unresolvable annotation
        return False
    return any(
        isinstance(hint, type) and issubclass(hint, OperationReason)
        for hint in hints.values()
    )


def _api_routes(app: FastAPI) -> Iterator[APIRoute]:
    for route in app.routes:
        if isinstance(route, APIRoute):
            yield route


def audit_routes(app: FastAPI, *, metrics_path: str | None = None) -> list[str]:
    """Every rule violation on `app`'s mounted surface. Empty means correct."""
    violations: list[str] = []

    for route in _api_routes(app):
        path = route.path
        # FastAPI mounts its own docs/openapi as non-APIRoute routes, so
        # everything reaching here is a route this assembly declared.
        route_class = classify(path, metrics_path=metrics_path)
        if route_class is None:
            violations.append(
                f"{path} is unclassified. Mount it under /health, /operations "
                "/ingress or /commands — a route with no class has no rules, "
                "which is how the ingress adapter would inherit the operator guard"
            )
            continue

        methods = {method.upper() for method in route.methods or set()}
        mutating = bool(methods & MUTATING_METHODS)
        guarded = require_operator in _dependency_calls(route)

        if route_class is RouteClass.OPERATOR:
            if not guarded:
                violations.append(
                    f"{sorted(methods)} {path} is an operator route with no "
                    "`require_operator` dependency"
                )
            if mutating and not _takes_a_reason(route):
                violations.append(
                    f"{sorted(methods)} {path} mutates without an "
                    "`OperationReason` body; an audit row that cannot say why "
                    "is not evidence"
                )
        elif route_class is RouteClass.PROBE:
            if guarded:
                violations.append(
                    f"{path} is a probe carrying the operator guard; an "
                    "orchestrator cannot present a credential, so this would "
                    "restart healthy replicas during an auth outage"
                )
            if mutating:
                violations.append(f"{sorted(methods)} {path} is a mutating probe")
        elif route_class is RouteClass.INGRESS and guarded:
            violations.append(
                f"{path} is public ingress carrying the operator guard. A "
                "provider holds no operator credential; sharing the guard ends "
                "with the operator guard loosened until both fit through it"
            )
        elif route_class is RouteClass.COMMAND:
            if guarded:
                violations.append(
                    f"{path} is a product command route carrying the operator "
                    "guard. A source application is not a platform operator"
                )
            if not mutating:
                violations.append(
                    f"{sorted(methods)} {path} is a non-mutating command route"
                )
            if require_command_port not in _dependency_calls(route):
                violations.append(
                    f"{path} is a command route with no `require_command_port` "
                    "dependency"
                )
        elif route_class is RouteClass.SCRAPE:
            if guarded:
                violations.append(
                    f"{path} is a scrape endpoint carrying the operator guard. "
                    "A monitoring system holds a scrape token, not an operator "
                    "identity, and every scrape would 401"
                )
            if mutating:
                violations.append(f"{sorted(methods)} {path} is a mutating scrape")
            if not any(
                isinstance(call, ScrapeGuard) for call in _dependency_calls(route)
            ):
                # The INVERSE of the probe rule, and the reason this is not a
                # probe. A scrape endpoint with no guard publishes queue depths,
                # dead-letter counts and this deployment's operational shape to
                # anyone who can reach the port.
                violations.append(
                    f"{path} is a scrape endpoint with no `ScrapeGuard` "
                    "dependency. An authentication check written in the handler "
                    "BODY is invisible to this audit, which is how an "
                    "unauthenticated /metrics would pass it"
                )

        lowered = path.lower()
        for verb in CREDENTIAL_LIFECYCLE_VERBS:
            if verb in lowered and route_class is not RouteClass.OPERATOR:
                violations.append(
                    f"{path} names the credential-lifecycle verb {verb!r} but "
                    f"is classified {route_class.value}. Minting, rotating and "
                    "revoking authentication material is an operator act"
                )

    return violations


def require_a_correct_surface(app: FastAPI, *, metrics_path: str | None = None) -> None:
    """`audit_routes`, raising. Called by `create_app` before it returns.

    At construction rather than in a test alone: a deployment that mounted an
    unguarded operations route must not start, and a test proves only the
    routes the test knows about.
    """
    violations = audit_routes(app, metrics_path=metrics_path)
    if violations:
        raise SurfaceViolation(
            "refusing to serve an incorrectly classified surface:\n  - "
            + "\n  - ".join(violations)
        )
