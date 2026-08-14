"""The assembly pins, composes, configures and operates. Nothing else.

"Thin" is a claim that decays silently. The first provider branch added here
would work, pass review as a small change, and quietly make this deployment a
second writer for a decision `dotmac-integration` already owns — the exact
parallel-authority failure ADR-0024 exists to prevent. By the time it is
obvious, several more have followed.

So the boundary is a test rather than a paragraph in the README.

## What is checked

1. No connector is named. Connectors arrive through the
   `dotmac_integration.connectors` entry-point group; an import or a string
   literal naming one would make this assembly know about a specific provider.
2. No business-decision vocabulary. Retry counts, backoff, lease durations and
   attempt limits belong to `ExecutionPolicy`. A number here is a fork.
3. Routes hold no session and issue no query — the same adapter split the
   Starter enforces between `router.py` and `service.py`.
4. The module's decision functions are not reimplemented.
5. No DDL. Migrations are a deploy step run as the owner role.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "dotmac_integrator"


def _modules() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py") if p.name != "__init__.py")


def _source_without_docstrings(path: Path) -> str:
    """Code only.

    Every check below would otherwise match this repository's own prose — these
    files discuss retry policy and connectors at length precisely because they
    do not implement them, and a text scan that cannot tell explanation from
    implementation reports the explanation.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(
            node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                body.pop(0)
    return ast.unparse(tree)


# ── 1. No connector is named ────────────────────────────────────────────────

# Providers this assembly must never know about by name. Not an exhaustive list
# of every provider in the world — it is the set named in the programme's own
# plan, which is what a well-meaning shortcut would reach for first.
FORBIDDEN_PROVIDERS = (
    "whatsapp",
    "meta",
    "twilio",
    "erpnext",
    "stripe",
    "paystack",
    "flutterwave",
    "sendgrid",
    "mailgun",
)


@pytest.mark.parametrize("provider", FORBIDDEN_PROVIDERS)
def test_no_provider_is_named_anywhere_in_the_assembly(provider: str) -> None:
    # Word boundaries, not substrings. `meta` as a substring matches `metadata`
    # and `metaclass`, and a guard that cries wolf on ordinary code gets
    # weakened by whoever hits it next — which is how a real one stops working.
    pattern = re.compile(rf"\b{re.escape(provider)}\b", re.IGNORECASE)
    for path in _modules():
        code = _source_without_docstrings(path)
        assert not pattern.search(code), (
            f"{path.name} names the provider {provider!r}. Connectors are "
            "separately released distributions discovered through the "
            "`dotmac_integration.connectors` entry-point group — this assembly "
            "composes whatever is installed and knows none of them by name."
        )


def test_discovery_is_the_only_way_a_connector_enters() -> None:
    """Entry points, never a registration call or an import.

    Asserted positively: a test that only forbids names would still pass if
    discovery were removed and connectors arrived some other way.
    """
    code = (SRC / "operations.py").read_text(encoding="utf-8")
    assert "integration.discover()" in code
    assert "ENTRY_POINT_GROUP" in code


# ── 2. No business decision ─────────────────────────────────────────────────

# Vocabulary that belongs to `dotmac_integration.ExecutionPolicy`. A literal
# assignment to any of these in this repository forks a decision that has an
# owner: the module would hold one answer and the deployment another.
POLICY_NAMES = (
    "max_attempts",
    "base_delay_seconds",
    "max_backoff_seconds",
    "lease_seconds",
    "stale_checkpoint_after_seconds",
    "retry_delay",
    "backoff",
)


@pytest.mark.parametrize("name", POLICY_NAMES)
def test_no_execution_policy_value_is_defined_here(name: str) -> None:
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
            for target in targets:
                label = (
                    target.id
                    if isinstance(target, ast.Name)
                    else getattr(target, "attr", "")
                )
                assert label != name, (
                    f"{path.name} assigns {name!r}. That is an ExecutionPolicy "
                    "field owned by dotmac-integration; setting it here gives "
                    "the deployment a second, competing answer."
                )


def test_the_assembly_never_constructs_an_execution_policy() -> None:
    for path in _modules():
        code = _source_without_docstrings(path)
        assert "ExecutionPolicy(" not in code, (
            f"{path.name} builds an ExecutionPolicy. Use the module's "
            "DEFAULT_POLICY; a deployment-authored policy is a fork."
        )


# ── 3. Routes are adapters ──────────────────────────────────────────────────


def test_routes_hold_no_session_and_issue_no_query() -> None:
    """`assembly.py` is this repository's `router.py`.

    The session, the fetch and the commit live in `operations.py`. Same split
    the Starter enforces, and for the same reason: a handler that queries grows
    logic that nothing else can reuse and no service test covers.
    """
    code = _source_without_docstrings(SRC / "assembly.py")
    for banned in ("Session(", ".execute(", "select(", ".commit()", ".query("):
        assert (
            banned not in code
        ), f"assembly.py contains {banned!r} — move it into operations.py"


# ── 4. Module decisions are not reimplemented ───────────────────────────────

# Functions `dotmac_integration` owns. Defining one HERE would shadow the
# module's and make this assembly the writer.
OWNED_BY_THE_MODULE = (
    "resolve_binding",
    "claim_delivery",
    "settle",
    "prepare",
    "invoke",
    "next_state",
    "retry_delay_seconds",
    "check_activation",
    "require_activatable",
    "validate_secret_refs",
    "record_delivery_outcome",
)


@pytest.mark.parametrize("name", OWNED_BY_THE_MODULE)
def test_no_module_owned_function_is_redefined(name: str) -> None:
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                assert node.name != name, (
                    f"{path.name} defines {name!r}, which dotmac-integration "
                    "owns. Call it; do not restate it."
                )


# ── 5. No DDL ───────────────────────────────────────────────────────────────


def test_the_application_never_issues_ddl() -> None:
    """Migrations run as the owner role at deploy time, never on boot.

    `migrations/env.py` is excluded — it is the deploy path, and it is the one
    place DDL is legitimate.
    """
    pattern = re.compile(r"\b(CREATE|ALTER|DROP)\s+(TABLE|SCHEMA|INDEX)\b", re.I)
    for path in _modules():
        code = _source_without_docstrings(path)
        assert not pattern.search(code), f"{path.name} issues DDL"
        assert "create_all" not in code, f"{path.name} calls create_all"


# ── Sensitivity proof (ADR-0018) ────────────────────────────────────────────


def test_the_scan_actually_reads_files() -> None:
    """Every check above iterates `_modules()`. If that returned nothing, all of
    them would pass while inspecting no code at all."""
    modules = _modules()
    assert len(modules) >= 5, modules
    names = {p.name for p in modules}
    assert {"assembly.py", "operations.py", "worker.py"} <= names, names
    for path in modules:
        assert _source_without_docstrings(path).strip(), path


def test_docstring_stripping_removes_prose_but_keeps_code() -> None:
    """The stripper is what lets these checks be strict.

    If it silently returned the whole file, the provider scan would fail on this
    repository's own explanations; if it returned nothing, every scan would pass
    vacuously. Both directions are asserted.
    """
    sample = SRC / "worker.py"
    raw = sample.read_text(encoding="utf-8")
    stripped = _source_without_docstrings(sample)

    assert "ExecutionPolicy" in raw, "fixture assumption broke"
    assert "ExecutionPolicy" not in stripped, "prose survived stripping"
    assert "class Worker" in stripped, "code did not survive stripping"


def test_the_provider_detector_bites() -> None:
    """Exercised on a planted hit AND on the word it must not confuse, so the
    boundary refinement above cannot quietly become a substring match again."""
    assert re.search(r"\bwhatsapp\b", "handler = build_whatsapp_client()", re.I) is None
    assert re.search(r"\bwhatsapp\b", "client = whatsapp.Client()", re.I)
    assert re.search(r"\bmeta\b", "columns = table.metadata.columns", re.I) is None
    assert re.search(r"\bmeta\b", "from meta import graph", re.I)


def test_the_policy_detector_bites() -> None:
    tree = ast.parse("max_attempts = 5\n")
    found = [
        t.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        for t in node.targets
        if isinstance(t, ast.Name)
    ]
    assert "max_attempts" in found
