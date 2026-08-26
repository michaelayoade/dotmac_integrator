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

from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest
from dotmac_kernel.secret_sources import (
    SecretSourceError,
    clear_secret_source,
    get_secret,
    install_secret_source,
    refresh_secrets,
)
from sqlalchemy.engine import Engine

from dotmac_integrator import secret_loading
from dotmac_integrator.secret_loading import (
    EnvDereferencer,
    FileDereferencer,
    SecretMaterialMissing,
    SecretStoreUnavailable,
    StoredReferenceSource,
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


class _AssemblyOnlySource(StoredReferenceSource):
    def _stored_references(self) -> tuple[set[str], bool]:
        return set(), False


def test_missing_required_crypto_ref_refuses_refresh_before_working_set_swap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = f"env://{PREFIX}COMMAND_PUBLIC"
    monkeypatch.delenv(f"{PREFIX}COMMAND_PUBLIC", raising=False)
    source = _AssemblyOnlySource(
        cast(Engine, object()),
        {"env": EnvDereferencer(prefix=PREFIX)},
        extra_references=(reference,),
        required_references=(reference,),
    )
    with pytest.raises(SecretStoreUnavailable, match="required cryptographic"):
        source.load()


def test_invalid_required_crypto_ref_refuses_the_whole_working_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = f"{PREFIX}COMMAND_PUBLIC"
    reference = f"env://{name}"
    monkeypatch.setenv(name, "not-an-ed25519-key")

    def reject(value: str) -> object:
        raise ValueError("parser detail must not escape")

    source = _AssemblyOnlySource(
        cast(Engine, object()),
        {"env": EnvDereferencer(prefix=PREFIX)},
        extra_references=(reference,),
        validators={reference: reject},
        required_references=(reference,),
    )
    with pytest.raises(SecretStoreUnavailable, match="configured cryptographic"):
        source.load()


def test_failed_whole_crypto_set_validation_retains_the_held_working_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = f"{PREFIX}COMMAND_PUBLIC"
    reference = f"env://{name}"
    monkeypatch.setenv(name, "valid-working-set")

    def validate_complete_set(material: Mapping[str, str]) -> object:
        if material[reference] != "valid-working-set":
            raise ValueError("secret parser detail must not escape")
        return object()

    source = _AssemblyOnlySource(
        cast(Engine, object()),
        {"env": EnvDereferencer(prefix=PREFIX)},
        extra_references=(reference,),
        required_references=(reference,),
        working_set_validator=validate_complete_set,
    )
    clear_secret_source()
    try:
        install_secret_source(source)
        monkeypatch.setenv(name, "invalid-rotated-set")

        with pytest.raises(SecretSourceError, match="SecretStoreUnavailable"):
            refresh_secrets()

        assert get_secret(reference) == "valid-working-set"
    finally:
        clear_secret_source()


def test_startup_loads_the_issuer_assignment_document_as_required_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    assignment_ref = f"env://{PREFIX}ISSUER_ASSIGNMENTS"

    def source_factory(
        engine: Engine,
        dereferencers: Mapping[str, object],
        **options: object,
    ) -> object:
        captured.update(options)
        return object()

    monkeypatch.setattr(secret_loading, "StoredReferenceSource", source_factory)
    monkeypatch.setattr(secret_loading, "build_dereferencers", lambda settings: {})
    monkeypatch.setattr(secret_loading, "install_secret_source", lambda source: ())
    settings = _settings(
        command_surface_enabled=True,
        command_audience="dotmac-integrator:test",
        command_public_key_refs=(f"vendor-key=env://{PREFIX}COMMAND_PUBLIC"),
        command_issuer_assignments_ref=assignment_ref,
        receipt_signing_key_id="integrator-receipt-1",
        receipt_signing_private_key_ref=f"env://{PREFIX}RECEIPT_PRIVATE",
    )

    secret_loading.install_secrets(cast(Engine, object()), settings)

    assert assignment_ref in cast(tuple[str, ...], captured["extra_references"])
    assert assignment_ref in cast(tuple[str, ...], captured["required_references"])
    assert assignment_ref in cast(Mapping[str, object], captured["validators"])
