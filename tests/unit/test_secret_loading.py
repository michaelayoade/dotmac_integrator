"""The startup path: confinement, and the two failure kinds kept apart.

A reference is DATA an operator wrote into a configuration revision. Without
confinement, `env://DATABASE_URL` or `file:///proc/self/environ` in that row
would make this process hand its own credentials to a connector — a privilege
escalation whose only visible symptom is an integration that works.

So both implemented dereferencers are proved to refuse what they must, not
merely to accept what they should.

The second half is the distinction the design turns on: a broken MECHANISM
refuses the boot, one bad REFERENCE does not. Collapsing them either bricks a
control plane over somebody's typo or starts a control plane with no
credentials, and the second is the one that gets a degraded-start flag bolted
on during an incident.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dotmac_integrator.secret_loading import (
    EnvDereferencer,
    FileDereferencer,
    SecretMaterialMissing,
    SecretStoreUnavailable,
    build_dereferencers,
)
from dotmac_integrator.settings import Settings

PREFIX = "INTEGRATOR_SECRET_"


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "environment": "test",
        "secret_env_prefix": PREFIX,
        "secret_file_root": "/run/secrets",
    }
    return Settings(**{**base, **overrides})  # type: ignore[arg-type]


# ── env:// ──────────────────────────────────────────────────────────────────


def test_env_reads_a_prefixed_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{PREFIX}TOKEN", "the-material")
    assert EnvDereferencer(prefix=PREFIX).read(f"{PREFIX}TOKEN") == "the-material"


def test_env_refuses_a_variable_outside_the_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one that matters. `DATABASE_URL` is in this process's environment."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://someone:hunter2@db/x")
    with pytest.raises(SecretMaterialMissing, match="outside the configured prefix"):
        EnvDereferencer(prefix=PREFIX).read("DATABASE_URL")


def test_env_refuses_an_unset_variable() -> None:
    with pytest.raises(SecretMaterialMissing, match="unset or empty"):
        EnvDereferencer(prefix=PREFIX).read(f"{PREFIX}NOT_SET_ANYWHERE")


def test_env_refuses_an_empty_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty is indistinguishable from "configured as blank", and a connector
    given an empty credential fails at the provider rather than here."""
    monkeypatch.setenv(f"{PREFIX}BLANK", "")
    with pytest.raises(SecretMaterialMissing):
        EnvDereferencer(prefix=PREFIX).read(f"{PREFIX}BLANK")


# ── file:// ─────────────────────────────────────────────────────────────────


def test_file_reads_a_mounted_secret_and_strips_the_trailing_newline(
    tmp_path: Path,
) -> None:
    (tmp_path / "token").write_text("the-material\n", encoding="utf-8")
    assert FileDereferencer(root=tmp_path).read(str(tmp_path / "token")) == (
        "the-material"
    )


def test_file_refuses_a_path_outside_the_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / "elsewhere"
    outside.mkdir(exist_ok=True)
    (outside / "shadow").write_text("not yours\n", encoding="utf-8")
    root = tmp_path / "secrets"
    root.mkdir()
    with pytest.raises(SecretMaterialMissing, match="outside the configured root"):
        FileDereferencer(root=root).read(str(outside / "shadow"))


def test_file_refuses_a_traversal_out_of_the_root(tmp_path: Path) -> None:
    """Resolved BEFORE the containment check, so `..` cannot climb out."""
    root = tmp_path / "secrets"
    root.mkdir()
    (tmp_path / "escaped").write_text("not yours\n", encoding="utf-8")
    with pytest.raises(SecretMaterialMissing, match="outside the configured root"):
        FileDereferencer(root=root).read(str(root / ".." / "escaped"))


def test_a_missing_file_is_one_bad_reference_not_a_broken_mechanism(
    tmp_path: Path,
) -> None:
    with pytest.raises(SecretMaterialMissing):
        FileDereferencer(root=tmp_path).read(str(tmp_path / "absent"))


def test_a_missing_MOUNT_is_a_broken_mechanism_and_refuses_the_boot(
    tmp_path: Path,
) -> None:
    """The distinction the whole design turns on.

    One absent file means one installation cannot be enabled. An absent mount
    means NOTHING file-backed can be, and starting anyway is the degraded start
    ADR-0009 refuses — so this exception is the one that escapes `load()`.
    """
    gone = tmp_path / "never-mounted"
    with pytest.raises(SecretStoreUnavailable):
        FileDereferencer(root=gone).read(str(gone / "token"))


# ── Scheme enablement ───────────────────────────────────────────────────────


def test_only_implemented_schemes_may_be_enabled() -> None:
    """A deployment naming `bao` is claiming it can reach OpenBao.

    Refused at boot rather than at the first enablement six weeks later. There
    is no OpenBao client in this assembly, and adding one is a reviewed change
    with a named address and auth method — not a configuration toggle.
    """
    with pytest.raises(SecretStoreUnavailable, match="cannot dereference"):
        build_dereferencers(_settings(secret_schemes="env,file,bao"))


def test_the_default_schemes_are_the_two_that_need_no_network() -> None:
    built = build_dereferencers(_settings())
    assert sorted(built) == ["env", "file"]


def test_a_deployment_may_narrow_to_one_scheme() -> None:
    assert sorted(build_dereferencers(_settings(secret_schemes="file"))) == ["file"]
