"""What is INSTALLED equals what is PINNED, and it is a wheel.

`tests/architecture/test_pins_are_exact.py` proves the pin and the lock agree —
both of which are text in this repository. This proves the third thing, which is
the one that actually runs: the distribution resolved into the environment.

The three can disagree, and each way is a real deployment:

* an editable install or a `PYTHONPATH` pointing at a Starter checkout — the
  path dependency this assembly forbids, arriving through the back door;
* a stale image built before a pin moved;
* a wheel whose metadata version and `__version__` disagree, which makes
  `/health/composition` a liar about what is running.

Every assertion reads the INSTALLED distribution, never `pyproject.toml`'s
intent, so the image built by CI is the thing under test.
"""

from __future__ import annotations

import tomllib
from importlib.metadata import distribution, version
from pathlib import Path

import dotmac_integration
import dotmac_kernel
import pytest

ROOT = Path(__file__).resolve().parents[2]
PINNED = ("dotmac-kernel", "dotmac-integration")


def _pins() -> dict[str, str]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = data["tool"]["poetry"]["dependencies"]
    return {name: declared[name] for name in PINNED}


@pytest.mark.parametrize("name", PINNED)
def test_the_installed_version_is_the_pinned_version(name: str) -> None:
    assert version(name) == _pins()[name], (
        f"{name} {version(name)} is installed but {_pins()[name]} is pinned. "
        "The environment was not built from this lockfile"
    )


@pytest.mark.parametrize(
    ("module", "name"),
    [(dotmac_kernel, "dotmac-kernel"), (dotmac_integration, "dotmac-integration")],
)
def test_the_modules_own_version_matches_its_distribution_metadata(
    module: object, name: str
) -> None:
    """`/health/composition` reports `__version__`; the resolver honours
    metadata. A wheel where they differ makes the composition report wrong in a
    way nothing else would catch."""
    assert module.__version__ == version(name)  # type: ignore[attr-defined]


@pytest.mark.parametrize("name", PINNED)
def test_the_distribution_is_a_wheel_and_not_a_checkout(name: str) -> None:
    """No editable install, no path source.

    An editable `dotmac-kernel` would make this deployment a second checkout of
    the Starter, silently picking up unreleased changes — exactly the coupling
    ADR-0024 § 6 removes, and the reason the pins are exact in the first place.
    """
    files = distribution(name).files or []
    assert not any(
        str(f).startswith("__editable__") or str(f).endswith(".pth") for f in files
    ), f"{name} is installed as an editable/path distribution"


def test_the_integration_module_declares_the_platform_plane_only() -> None:
    """Read from the INSTALLED manifest.

    This assembly composes one lineage into a platform-only database. A release
    that grew a tenant table would need RLS, a tenant role and a tenant
    context, none of which exist here — and it would be discovered by the
    migration, in production.
    """
    assert dotmac_integration.module.tables == ()
    assert dotmac_integration.module.platform_tables
