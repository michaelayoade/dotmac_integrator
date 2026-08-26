"""The STARTUP path: dereference every stored reference, once, into memory.

This is the half of ADR-0009 that is allowed to be slow. It runs at boot and on
an explicit `POST /operations/secrets/refresh`, never on a request, and
`secret_resolver.py` — the half that DOES run on a request — imports nothing
from here.

## Which references, and why the database is the list

`dotmac_integration` already stores exactly the set of material this deployment
needs: every `connector_config_revisions.secret_refs` belonging to an
installation that is not retired. A second list in configuration would be a
second answer to "what does this deployment need", and it would be wrong the
first time someone added an installation without updating it.

Retired installations are excluded and nothing else is: a delivery claimed
against an older revision is still in flight, so holding only the CURRENT
revision's references would strand it.

## The one reference that is NOT in the database

The destination application's credential (`PRODUCT_PORT_API_KEY_REF`) belongs to
this assembly rather than to any connector, so no `connector_config_revisions`
row could ever hold it — the paragraph above forbids a second list of CONNECTOR
material, not a reference that has no connector. It is passed in as
`extra_references` and dereferenced by the identical mechanism, which is also
what lets `secret_resolver.redact` cover it: every held value is redacted out of
outbound strings by construction, and a credential resolved some other way would
need its own redaction remembered separately.

## Two failure kinds, deliberately not one

======================== ===================================================
`SecretStoreUnavailable` the MECHANISM is broken — a secrets mount is gone,
                         a store is unreachable. Propagates out of `load()`,
                         so `install_secret_source` raises and the process
                         refuses to start. ADR-0009: no degraded start.
`SecretMaterialMissing`  ONE reference cannot be resolved — a typo, material
                         not provisioned yet. Recorded and omitted. The
                         deployment starts; enablement of the installation
                         that needs it is refused, naming the reference.
======================== ===================================================

Collapsing them would mean one mistyped reference in one connector's config
bricks the whole control plane, which is how a fail-closed design gets a
degraded-start knob bolted on during the first incident.

## Which schemes are implemented here

`env` and `file` — neither touches a network, both are what an orchestrator
already provides (an injected environment, a mounted secret). The
network-backed schemes `dotmac_integration` recognises (`bao`, `aws-sm`,
`gcp-sm`) are deliberately NOT implemented: each needs a store client, an
address, an auth method and a rotation story, which are deployment decisions
with a named owner and not something an assembly should pick on its own. A
reference using one is reported unresolved by name, so the gap is visible in
`GET /operations/secrets` rather than discovered at enablement.

Both implemented schemes are CONFINED. `env` reads only variables under a
configured prefix, `file` only paths under a configured root. Without that, a
configuration revision — data an operator writes — could name
`env://DATABASE_URL` or `file:///proc/self/environ` and have this process hand
it to a connector. A reference is not a capability.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol

import dotmac_integration as integration
from dotmac_kernel.secret_sources import install_secret_source, refresh_secrets
from sqlalchemy import select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from dotmac_integrator.secret_resolver import MINIMUM_REDACTABLE_LENGTH
from dotmac_integrator.settings import Settings

logger = logging.getLogger(__name__)

__all__ = [
    "EnvDereferencer",
    "FileDereferencer",
    "ReferenceDereferencer",
    "SecretLoadReport",
    "SecretMaterialMissing",
    "SecretStoreUnavailable",
    "StoredReferenceSource",
    "build_dereferencers",
    "install_secrets",
    "last_report",
    "refresh",
]

#: Same shape `dotmac_integration.secret_refs` validates on the way in. Parsed
#: again here rather than imported, because that module's pattern is private;
#: the SCHEME VOCABULARY is taken from the module's public constant so the two
#: cannot drift.
_REFERENCE_RE: Final[re.Pattern[str]] = re.compile(r"^([a-z][a-z0-9-]*)://(\S+)$")


class SecretStoreUnavailable(RuntimeError):
    """A secret MECHANISM is broken. Refuse to start rather than start empty."""


class SecretMaterialMissing(RuntimeError):
    """ONE reference could not be resolved. Recorded, omitted, not fatal."""


class ReferenceDereferencer(Protocol):
    """How one scheme's locator becomes material. Startup only."""

    @property
    def scheme(self) -> str:
        """The reference scheme this handles. READ-ONLY on purpose: an
        implementation is a frozen dataclass, and a mutable protocol attribute
        would refuse every one of them."""

    def read(self, locator: str) -> str:
        """The material `locator` points at.

        Raise `SecretMaterialMissing` when THIS pointer is bad and
        `SecretStoreUnavailable` when the mechanism itself is. Never return an
        empty string for either — empty is indistinguishable from "configured
        as blank".
        """
        ...


@dataclass(frozen=True, slots=True)
class EnvDereferencer:
    """`env://NAME` — a variable the orchestrator injected.

    Confined to `prefix`. An unprefixed name is refused rather than read: the
    reference comes from a database row, and this process's environment holds
    `DATABASE_URL` and the registry password.
    """

    prefix: str
    scheme: str = "env"

    def read(self, locator: str) -> str:
        if not locator.startswith(self.prefix):
            raise SecretMaterialMissing(
                f"env://{locator} is outside the configured prefix "
                f"{self.prefix!r}. A configuration revision may not name an "
                "arbitrary environment variable of this process"
            )
        value = os.environ.get(locator)
        if not value:
            raise SecretMaterialMissing(
                f"env://{locator} is unset or empty in this process"
            )
        return value


@dataclass(frozen=True, slots=True)
class FileDereferencer:
    """`file:///run/secrets/x` — material an orchestrator mounted.

    Confined to `root`, resolved first so `..` cannot climb out of it. The
    trailing newline a secret file almost always ends with is stripped; a
    credential with a genuine trailing newline is not a thing, and the
    alternative is every connector failing authentication for an invisible
    reason.
    """

    root: Path
    scheme: str = "file"

    def read(self, locator: str) -> str:
        try:
            resolved = Path(locator).resolve()
        except OSError as exc:
            raise SecretMaterialMissing(
                f"file://{locator} cannot be resolved: {type(exc).__name__}"
            ) from exc
        root = self.root.resolve()
        if not resolved.is_relative_to(root):
            raise SecretMaterialMissing(
                f"file://{locator} resolves outside the configured root "
                f"{root}. A configuration revision may not name an arbitrary "
                "path on this host"
            )
        if not root.is_dir():
            # The MOUNT is gone, not one file. Every file reference would fail,
            # and starting with none of them held is the degraded start
            # ADR-0009 refuses.
            raise SecretStoreUnavailable(
                f"the secret file root {root} does not exist; refusing to "
                "start with no file-backed material rather than treating every "
                "reference as merely missing"
            )
        try:
            value = resolved.read_text(encoding="utf-8").rstrip("\n")
        except FileNotFoundError as exc:
            raise SecretMaterialMissing(f"file://{locator} does not exist") from exc
        except OSError as exc:
            raise SecretMaterialMissing(
                f"file://{locator} could not be read: {type(exc).__name__}"
            ) from exc
        if not value:
            raise SecretMaterialMissing(f"file://{locator} is empty")
        return value


def build_dereferencers(settings: Settings) -> dict[str, ReferenceDereferencer]:
    """The schemes this deployment can dereference, from configuration.

    Enabling a scheme that has no implementation is refused at boot rather than
    at the first enablement that needs it — a configuration naming `bao` is a
    statement that this deployment expects to reach OpenBao, and discovering
    six weeks later that it never could is worse than not starting.
    """
    implemented: dict[str, ReferenceDereferencer] = {
        "env": EnvDereferencer(prefix=settings.secret_env_prefix),
        "file": FileDereferencer(root=Path(settings.secret_file_root)),
    }
    enabled = tuple(
        part.strip() for part in settings.secret_schemes.split(",") if part.strip()
    )
    unknown = sorted(set(enabled) - set(implemented))
    if unknown:
        raise SecretStoreUnavailable(
            f"SECRET_SCHEMES enables {unknown}, which this deployment cannot "
            f"dereference. Implemented: {sorted(implemented)}. The "
            "network-backed schemes need a store client, an address and an "
            "auth method — adding one is a reviewed change with a named "
            "deployment target, not a configuration toggle"
        )
    return {scheme: implemented[scheme] for scheme in enabled}


@dataclass(frozen=True, slots=True)
class SecretLoadReport:
    """What a load produced. Names and references only, by construction."""

    #: References material is held for.
    held: tuple[str, ...] = ()
    #: `{reference: why}` for everything that could not be resolved. `why`
    #: names the mechanism and the pointer; it can never name a value, because
    #: a dereferencer that failed never obtained one.
    unresolved: dict[str, str] = field(default_factory=dict)
    #: True when the module's tables are absent — an unmigrated database. Not
    #: an error here: `/health/ready` is what reports it.
    schema_absent: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "held": list(self.held),
            "held_count": len(self.held),
            "unresolved": dict(sorted(self.unresolved.items())),
            "schema_absent": self.schema_absent,
        }


_last_report = SecretLoadReport()


def last_report() -> SecretLoadReport:
    """The most recent load's outcome, for the operator diagnostic."""
    return _last_report


class StoredReferenceSource:
    """The `dotmac_kernel.secret_sources.SecretSource` this deployment installs.

    Holds the engine rather than a session: `load()` is called by the kernel at
    install and on refresh, with no session in scope, and it must own its own
    short read.
    """

    def __init__(
        self,
        engine: Engine,
        dereferencers: Mapping[str, ReferenceDereferencer],
        *,
        extra_references: Iterable[str] = (),
        validators: Mapping[str, Callable[[str], object]] | None = None,
        required_references: Iterable[str] = (),
        working_set_validator: Callable[[Mapping[str, str]], object] | None = None,
    ) -> None:
        self._engine = engine
        self._dereferencers = dict(dereferencers)
        #: References this ASSEMBLY needs that no connector owns — today, the
        #: destination application's credential. Held here so it is loaded,
        #: refreshed and redacted by exactly the same machinery.
        self._extra = frozenset(
            reference.strip() for reference in extra_references if reference.strip()
        )
        self._validators = dict(validators or {})
        self._required = frozenset(
            reference.strip() for reference in required_references if reference.strip()
        )
        self._working_set_validator = working_set_validator

    def load(self) -> Mapping[str, str]:
        global _last_report
        references, schema_absent = self._stored_references()
        references |= set(self._extra)
        held: dict[str, str] = {}
        unresolved: dict[str, str] = {}

        for reference in sorted(references):
            match = _REFERENCE_RE.fullmatch(reference.strip())
            if match is None:
                unresolved[reference] = "not a <scheme>://<id> reference"
                continue
            scheme, locator = match.group(1), match.group(2)
            if scheme not in integration.SECRET_REFERENCE_SCHEMES:
                unresolved[reference] = f"scheme {scheme!r} is not recognised"
                continue
            dereferencer = self._dereferencers.get(scheme)
            if dereferencer is None:
                unresolved[reference] = (
                    f"scheme {scheme!r} is not enabled in this deployment "
                    f"(SECRET_SCHEMES={sorted(self._dereferencers)})"
                )
                continue
            try:
                value = dereferencer.read(locator)
            except SecretMaterialMissing as exc:
                unresolved[reference] = str(exc)
                continue
            if len(value) < MINIMUM_REDACTABLE_LENGTH:
                # Refused rather than held: a value this short cannot be
                # redacted out of a diagnostic without shredding the
                # diagnostic, so holding it would mean choosing between a
                # leaked credential and an unreadable error.
                unresolved[reference] = (
                    f"material is shorter than {MINIMUM_REDACTABLE_LENGTH} "
                    "characters and cannot be redacted from an error message"
                )
                continue
            validator = self._validators.get(reference)
            if validator is not None:
                try:
                    validator(value)
                except (TypeError, ValueError) as exc:
                    # A malformed rotation is a broken working set, not one
                    # optional connector reference. Raising makes the kernel's
                    # refresh retain the prior complete set. Name the pointer,
                    # never the material or the parser exception.
                    raise SecretStoreUnavailable(
                        f"material at {reference!r} is invalid for its "
                        "configured cryptographic purpose"
                    ) from exc
            held[reference] = value

        missing_required = sorted(self._required - held.keys())
        if missing_required:
            # Required assembly cryptography is one working set. A partial
            # result must raise BEFORE the kernel swaps it in, which is what
            # preserves the prior keys when a rotation is incomplete.
            raise SecretStoreUnavailable(
                "required cryptographic reference(s) are unavailable: "
                + ", ".join(missing_required)
            )

        if self._working_set_validator is not None:
            try:
                self._working_set_validator(held)
            except (TypeError, ValueError) as exc:
                # Cross-key rules (notably receipt/issuer separation) need the
                # whole candidate set. Validate before returning so the kernel
                # never swaps a broken rotation into the held working set.
                raise SecretStoreUnavailable(
                    "the complete cryptographic working set is invalid"
                ) from exc

        _last_report = SecretLoadReport(
            held=tuple(sorted(held)),
            unresolved=unresolved,
            schema_absent=schema_absent,
        )
        if unresolved:
            # Names and reasons. There is no value to leak here — every entry
            # is a reference whose dereference did not produce one.
            logger.warning(
                "%d secret reference(s) unresolved: %s",
                len(unresolved),
                "; ".join(f"{ref} ({why})" for ref, why in sorted(unresolved.items())),
            )
        return held

    def _stored_references(self) -> tuple[set[str], bool]:
        """Every reference belonging to a non-retired installation.

        Returns `(references, schema_absent)`. An unmigrated database is not an
        error at this layer: the process starts holding nothing, `/health/ready`
        already reports the schema missing, and `make migrate` followed by a
        refresh is the whole remedy. Refusing to boot here would mean the
        deploy order (migrate job, then runtime) could never be established for
        the very first deployment.
        """
        with Session(self._engine) as db:
            present = db.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = :s AND table_name = :t)"
                ),
                {"s": integration.SCHEMA, "t": "connector_config_revisions"},
            ).scalar_one()
            if not present:
                logger.warning(
                    "%s.connector_config_revisions is absent — holding no "
                    "secret material. Run the migration job, then refresh.",
                    integration.SCHEMA,
                )
                return set(), True

            rows = db.execute(
                select(integration.ConnectorConfigRevision.secret_refs)
                .join(
                    integration.ConnectorInstallation,
                    integration.ConnectorInstallation.id
                    == integration.ConnectorConfigRevision.installation_id,
                )
                .where(integration.ConnectorInstallation.state != "retired")
            ).scalars()

        references: set[str] = set()
        for refs in rows:
            for reference in (refs or {}).values():
                if isinstance(reference, str) and reference.strip():
                    references.add(reference.strip())
        return references, False


def install_secrets(engine: Engine, settings: Settings) -> SecretLoadReport:
    """Load every referenced secret NOW. Called once, at startup.

    Raises on a broken mechanism. That is the point: a process that started
    without the material it was configured to hold looks healthy and refuses
    every enablement, which is a harder failure to read than not starting.
    """
    from dotmac_integrator import machine_commands

    assembly_owned = list(
        (settings.product_port_api_key_ref,) if settings.product_port_enabled else ()
    )
    validators: dict[str, Callable[[str], object]] = {}
    required_references: list[str] = []
    if settings.command_surface_enabled:
        command_refs = settings.command_public_key_refs
        from dotmac_integrator.settings import command_public_key_references

        assembly_owned.extend(command_public_key_references(command_refs).values())
        assembly_owned.append(settings.command_issuer_assignments_ref)
        assembly_owned.append(settings.receipt_signing_private_key_ref)
        validators.update(machine_commands.crypto_material_validators(settings))
        required_references.extend(validators)
    working_set_validator = (
        (lambda material: machine_commands.validate_crypto_material(settings, material))
        if settings.command_surface_enabled
        else None
    )
    source = StoredReferenceSource(
        engine,
        build_dereferencers(settings),
        extra_references=assembly_owned,
        validators=validators,
        required_references=required_references,
        working_set_validator=working_set_validator,
    )
    names = install_secret_source(source)
    logger.info(
        "held %d secret reference(s) at startup; %d unresolved",
        len(names),
        len(_last_report.unresolved),
    )
    return _last_report


def refresh() -> SecretLoadReport:
    """Re-read every reference — THE rotation operation.

    Explicit, never a TTL. `dotmac_kernel.secret_sources.refresh_secrets` keeps
    the previously held set if this raises, so a mount that vanished during a
    rotation attempt leaves a working process working.
    """
    refresh_secrets()
    from dotmac_integrator import machine_commands

    machine_commands.refresh_crypto_from_held()
    return _last_report
