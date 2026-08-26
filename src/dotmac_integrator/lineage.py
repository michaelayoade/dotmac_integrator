"""Where the composed Alembic lineages live, resolved from INSTALLED packages.

The Starter names its lineages by repository path
(`%(here)s/packages/dotmac-ticketing/src/.../versions`), which is correct there:
it builds those packages. This assembly *consumes wheels*. There is no
`packages/` directory, and a path would be a guess about someone else's
site-packages layout.

So the directories are asked of the installed modules themselves. That also
makes a missing or mis-pinned distribution fail HERE, at startup, with a name —
rather than as Alembic silently finding no revisions and reporting the database
already at head.

## Why this is the assembly's job

A module ships its migrations; it does not decide what it is composed with.
Binding lineages together is exactly the responsibility ADR-0024 assigns to the
assembly, and it is most of what this one does.
"""

from __future__ import annotations

from pathlib import Path

import dotmac_integration.migrations
import dotmac_kernel.migrations


def _versions(package: object, distribution: str) -> Path:
    file = getattr(package, "__file__", None)
    if file is None:  # namespace package — no single directory to point at
        raise RuntimeError(
            f"{distribution} exposes no migrations directory; the installed "
            "wheel is not the one this assembly pins"
        )
    directory = Path(file).resolve().parent / "versions"
    if not directory.is_dir():
        raise RuntimeError(
            f"{distribution} ships no migrations/versions directory at "
            f"{directory} — refusing to start with a lineage that cannot be "
            "found, rather than letting Alembic report 'already at head'"
        )
    return directory


def kernel_versions() -> Path:
    """The kernel lineage. Uses the kernel's own published helper where it has
    one, so this assembly does not encode the kernel's internal layout."""
    return Path(dotmac_kernel.migrations.versions_dir()).resolve()


def integration_versions() -> Path:
    """The `ig` lineage shipped by `dotmac-integration`.

    Computed rather than requested from the module: `dotmac-integration 0.1.0a16`
    still ships no `versions_dir()` helper of its own — re-checked at each pin
    bump rather than assumed. If a later release adds one, prefer it here: a
    package describing its own layout beats an assembly inferring it.
    """
    return _versions(dotmac_integration.migrations, "dotmac-integration")


def version_locations() -> tuple[Path, ...]:
    """Every lineage this deployment composes, kernel first.

    Order is presentation only — Alembic resolves dependencies from the revision
    graph, not from this sequence. It is kernel-first because that is the order a
    reader expects, and a misleading order is worth avoiding even when it is
    inert.
    """
    return (kernel_versions(), integration_versions())


def version_locations_setting() -> str:
    """The `version_locations` value, space-separated to match `path_separator`
    in `alembic.ini`. A directory containing a space would break this, and is
    refused rather than silently splitting into two bad paths."""
    paths = version_locations()
    for path in paths:
        if " " in str(path):
            raise RuntimeError(
                f"lineage path contains a space and cannot be expressed with "
                f"path_separator = space: {path}"
            )
    return " ".join(str(p) for p in paths)
