"""ADR-0009, statically: the resolution path cannot reach anything.

The Starter enforces this over the kernel's settings modules. The same rule
applies here for a sharper reason: this deployment's resolution path runs on
every connector dispatch and every enablement, so a store client imported into
it would put that store between a provider and its credential — and it would
look like a one-line convenience in review.

`secret_loading.py` is deliberately NOT on this list. It reads the database and
the filesystem, because loading is allowed to; the whole design is a split
between a half that may do I/O once and a half that may never do it at all. A
check that covered both would either have to permit `os` on the request path or
forbid the loader from working.

Neither this nor the runtime proof (`tests/unit/test_secret_resolver.py`) is
sufficient alone: the runtime proof catches a dereference however it is spelled
but only on paths a test drives; this catches every path but only the spellings
it knows.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "dotmac_integrator"

#: Modules a request may execute while resolving a secret.
RESOLUTION_MODULES = ("secret_resolver.py",)

#: Anything that could reach a network, a filesystem, a subprocess or the
#: database. Wider than the kernel's list by `os`, `pathlib` and `sqlalchemy`:
#: the kernel's resolution path legitimately reads rows, and this one must not
#: read anything at all.
FORBIDDEN_ROOTS = {
    "aiohttp",
    "asyncio",
    "azure",
    "boto3",
    "botocore",
    "ftplib",
    "google",
    "http",
    "httpx",
    "hvac",
    "os",
    "pathlib",
    "requests",
    "smtplib",
    "socket",
    "sqlalchemy",
    "subprocess",
    "telnetlib",
    "urllib",
    "urllib3",
}


def _imported_roots(path: Path) -> set[str]:
    roots: set[str] = set()
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


@pytest.mark.parametrize("module", RESOLUTION_MODULES)
def test_the_resolution_path_imports_nothing_that_can_reach_out(module: str) -> None:
    path = SRC / module
    assert path.exists(), f"{module} moved — update RESOLUTION_MODULES"
    offending = sorted(_imported_roots(path) & FORBIDDEN_ROOTS)
    assert not offending, (
        f"{module} imports {offending}. A secret is HELD, never fetched while "
        "handling a request (ADR-0009) — put the I/O in secret_loading.py, "
        "which runs at startup and on an explicit refresh"
    )


def test_no_accessor_dumps_every_held_value() -> None:
    """The kernel ships none; this assembly must not add one.

    `GET /operations/secrets` reports names and refusal reasons, which is what
    an operator diagnosing a refused enablement actually needs. A bulk accessor
    would exist for one reason.
    """
    from dotmac_integrator import secret_resolver

    for forbidden in ("secret_values", "all_secrets", "held_values", "as_dict"):
        assert not hasattr(secret_resolver, forbidden), (
            f"`secret_resolver.{forbidden}` would expose every held value at "
            "once — callers resolve one reference at a time"
        )


def test_the_operator_secret_route_reports_names_only() -> None:
    """The one route near the material returns a report built from references.

    Asserted against the report's own shape rather than a live call, because
    the guarantee is structural: `SecretLoadReport` has nowhere to put a value.
    """
    from dotmac_integrator.secret_loading import SecretLoadReport

    fields = set(SecretLoadReport().as_dict())
    assert fields == {"held", "held_count", "unresolved", "schema_absent"}


# ── Sensitivity proof (ADR-0018) ────────────────────────────────────────────


def test_the_import_scan_bites(tmp_path: Path) -> None:
    """Planted hits, in both import spellings, plus a near-miss it must ignore."""
    planted = tmp_path / "planted.py"
    planted.write_text(
        "import httpx\nfrom urllib import parse\nimport dotmac_kernel\n",
        encoding="utf-8",
    )
    assert _imported_roots(planted) & FORBIDDEN_ROOTS == {"httpx", "urllib"}


def test_the_scan_reads_a_real_module() -> None:
    """A `RESOLUTION_MODULES` that had gone stale would make every case above
    pass while inspecting nothing."""
    assert RESOLUTION_MODULES
    for module in RESOLUTION_MODULES:
        roots = _imported_roots(SRC / module)
        # It DOES import something, so an empty result means a parse that
        # silently produced nothing rather than a clean module.
        assert roots, module
        assert "dotmac_kernel" in roots, module
