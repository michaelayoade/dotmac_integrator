"""The Dotmac dependencies are pinned exactly, and the lock agrees.

A library declares the EARLIEST version it works with, because it does not know
what it will be installed beside. A deployment declares the EXACT version it was
tested against, because it does.

`dotmac-kernel = ">=0.1.0a58"` here would let a `poetry install` months from now
compose a combination nobody has ever run — and it would do so silently, on a
machine that is not the one where the change was reviewed. That is the failure
an assembly exists to prevent, so it is asserted rather than trusted.

Third-party dependencies keep carets deliberately: pinning FastAPI exactly buys
nothing and blocks security patches. The rule is about the Dotmac distributions,
whose composition is the thing under review.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"
LOCKFILE = ROOT / "poetry.lock"

EXACTLY_PINNED = ("dotmac-kernel", "dotmac-integration")


def _dependencies() -> dict[str, object]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return data["tool"]["poetry"]["dependencies"]


@pytest.mark.parametrize("distribution", EXACTLY_PINNED)
def test_the_dotmac_dependencies_are_exact_versions(distribution: str) -> None:
    constraint = _dependencies()[distribution]
    assert isinstance(constraint, str), (
        f"{distribution} is declared as a table; this assembly pins a published "
        f"version, not a path or git source: {constraint!r}"
    )
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:a|b|rc)?\d*", constraint), (
        f"{distribution} is pinned as {constraint!r}. A deployment pins the "
        "exact version it was tested against — no caret, no >=, no wildcard."
    )


@pytest.mark.parametrize("distribution", EXACTLY_PINNED)
def test_the_lock_agrees_with_the_pin(distribution: str) -> None:
    """A pin nothing installs is a comment.

    Skipped when the lock is absent — it cannot be generated without registry
    credentials, so a contributor without them still gets the rest of the suite.
    CI has the credentials and does not skip, which is where this must hold.
    """
    if not LOCKFILE.exists():
        pytest.skip("poetry.lock absent — needs registry credentials to generate")

    lock = tomllib.loads(LOCKFILE.read_text(encoding="utf-8"))
    locked = {p["name"]: p["version"] for p in lock["package"]}
    assert distribution in locked, f"{distribution} is not in poetry.lock"
    assert locked[distribution] == _dependencies()[distribution], (
        f"{distribution}: pyproject pins {_dependencies()[distribution]} but the "
        f"lock resolves {locked[distribution]} — refresh with `poetry lock`"
    )


def test_no_dotmac_dependency_is_a_path_or_git_source() -> None:
    """This assembly consumes PUBLISHED wheels.

    A path dependency would make it a second checkout of the Starter rather than
    an independent deployment, and would silently pick up unreleased changes —
    exactly the coupling ADR-0024 § 6 removes.
    """
    for name, constraint in _dependencies().items():
        if not name.startswith("dotmac"):
            continue
        assert isinstance(constraint, str), (
            f"{name} uses a table constraint: {constraint!r}. Path and git "
            "sources are refused; pin a published version."
        )


def test_the_pinned_set_is_not_empty() -> None:
    """Sensitivity proof: both parametrized tests iterate `EXACTLY_PINNED`, and
    an empty tuple would collect zero cases and report success."""
    assert len(EXACTLY_PINNED) >= 2
    declared = _dependencies()
    for distribution in EXACTLY_PINNED:
        assert distribution in declared, f"{distribution} is not a dependency"


def test_the_version_pattern_rejects_a_range() -> None:
    """The matcher is exercised against what it must refuse, so a pattern that
    accidentally accepted everything would fail here rather than pass silently."""
    pattern = r"\d+\.\d+\.\d+(?:a|b|rc)?\d*"
    assert re.fullmatch(pattern, "0.1.0a58")
    assert re.fullmatch(pattern, "1.2.3")
    for bad in (">=0.1.0a58", "^0.1.0", "0.1.*", "0.1.0a58,<0.2"):
        assert not re.fullmatch(pattern, bad), bad
