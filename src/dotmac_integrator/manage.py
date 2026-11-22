"""The `integration:manage` service layer (D12a). Not an operator.

One scoped product-management caller per companion. It authenticates with a
held key through the product mechanism (`product_auth`) and is confined to an
installation-id allowlist, a connector-key allowlist, its own binding ids and
an allowlist of non-egress configuration keys. This is the service layer for
those routes, in the same split as `operations.py`: `assembly.py` only adapts.

## What it can do (PLAN §1a)

reads: readiness, one installation's state and bindings, secret status by NAME
only, delivery counts by state; set non-egress configuration; disable or enable
its OWN binding; test-send through an injected sender.

## What it can never do, and where that is enforced

* **Repoint the destination (§1d).** A key naming a host, port, user, TLS mode,
  URL, credential or network target is refused 403 before any query
  (`settings.config_key_is_egress`), and a key outside the caller's explicit
  `config_keys` allowlist is refused too. The new revision is built FROM the
  current one: every key the caller did not name, the secret references and the
  bound network targets are carried over unchanged, so omission cannot drop a
  destination or a credential reference either.
* **Release a quarantine, activate for the first time, mint or rotate anything,
  create an installation or bind a target.** No route exists for them.
* **Leave a quarantine by side effect.** The module's configuration write
  resets an installation to `draft`, which would silently exit a quarantine, so
  configuration is refused while the installation is quarantined.
* **Enable a binding that was never activated.** The module keeps no
  "ever activated" marker (`enabled_at` is cleared by a disable), so the fact is
  read from the operator's audit row `integrator.binding.enabled`. No such row
  means an operator never activated it, and enable is refused.

## Attribution

The audit row's principal is the authenticated caller application. The
`asserted_actor` the caller forwards is recorded verbatim-bounded and labelled
`asserted_actor_authenticated: false`: this assembly cannot verify who a
caller's own user is, and must not let a row suggest it did.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any, Protocol
from uuid import UUID

import dotmac_integration as integration
from dotmac_kernel.audit import write_platform_audit_event
from dotmac_kernel.models_platform import PlatformAuditEvent
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dotmac_integrator import health, secret_loading
from dotmac_integrator.manifest import INTEGRATOR_AUDIT_ACTIONS
from dotmac_integrator.operations import _lifecycle_conflict
from dotmac_integrator.product_auth import ProductPrincipal
from dotmac_integrator.settings import ManageGrant, config_key_is_egress

__all__ = [
    "ConfigBody",
    "ManageActor",
    "ReasonBody",
    "ManageTestSendBody",
    "ManageTestSender",
    "require_manage_installation",
]

_Reason = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)
]
#: Forwarded by the caller and NOT authenticated here; bounded and printable.
_Asserted = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=1, max_length=160, pattern=r"^[^\x00-\x1f]+$"
    ),
]


class ReasonBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: _Reason
    asserted_actor: _Asserted | None = None


class ConfigBody(ReasonBody):
    config: dict[str, object]


class ManageTestSendBody(ReasonBody):
    to_address: str


#: `integrator.binding.enabled` is written only by the OPERATOR enable route
#: (`operations.enable_binding`), which is what makes it a usable record that an
#: operator performed the first activation.
_OPERATOR_ACTIVATION_ACTION = "integrator.binding.enabled"

_ADDRESS = re.compile(
    r"^[^@\s<>,;\"'\\\x00-\x1f]{1,64}@[^@\s<>,;\"'\\\x00-\x1f]{1,255}$"
)


class ManageTestSender(Protocol):
    """Whatever turns a test-send into a queued delivery on the caller's binding.

    Injected rather than built here: the payload a delivery capability accepts is
    declared by the product-owned capability contract, not by this assembly
    (hard rule 27). Without one the route answers 503 and sends nothing.
    """

    def __call__(
        self,
        engine: Engine,
        *,
        installation_id: UUID,
        binding_id: UUID,
        to_address: str,
        request_key: str,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class ManageActor:
    """Who acted: the authenticated application, and a claim about a person."""

    application: str
    asserted_actor: str | None

    @property
    def label(self) -> str:
        return self.application

    def audit_fields(self) -> dict[str, object]:
        return {
            "principal": self.application,
            "principal_authenticated": True,
            "asserted_actor": self.asserted_actor,
            "asserted_actor_authenticated": False,
        }


def _audit(
    db: Session,
    actor: ManageActor,
    *,
    action: str,
    entity_type: str,
    entity_id: str,
    details: dict[str, object],
) -> None:
    if action not in INTEGRATOR_AUDIT_ACTIONS:  # pragma: no cover
        raise AssertionError(f"undeclared audit action {action!r}")
    write_platform_audit_event(
        db,
        actor_admin_id=None,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details={**actor.audit_fields(), **details},
    )


def _parse(raw: str, field: str) -> UUID:
    try:
        return UUID(raw)
    except ValueError:
        raise HTTPException(422, f"{field} is not a UUID") from None


def _grant(principal: ProductPrincipal, identifier: UUID) -> ManageGrant:
    for grant in principal.manage_grants:
        if grant.installation_id == identifier:
            return grant
    raise HTTPException(403, "installation is not managed by this caller")


def require_manage_installation(
    principal: ProductPrincipal, installation_id: str
) -> UUID:
    """Allowlist check BEFORE any lookup, so existence is not an oracle."""
    identifier = _parse(installation_id, "installation_id")
    _grant(principal, identifier)
    return identifier


def _load_installation(
    db: Session, principal: ProductPrincipal, identifier: UUID
) -> Any:
    installation = db.get(integration.ConnectorInstallation, identifier)
    if installation is None:
        raise HTTPException(404, "installation not found")
    if installation.connector_key != _grant(principal, identifier).connector_key:
        raise HTTPException(403, "connector is not managed by this caller")
    return installation


def _load_binding(
    db: Session, principal: ProductPrincipal, installation: Any, raw: str
) -> Any:
    identifier = _parse(raw, "binding_id")
    if identifier not in _grant(principal, installation.id).binding_ids:
        raise HTTPException(403, "binding is not managed by this caller")
    binding = db.get(integration.CapabilityBinding, identifier)
    if binding is None or binding.installation_id != installation.id:
        raise HTTPException(404, "binding not found")
    return binding


# ── Reads ───────────────────────────────────────────────────────────────────


def readiness(engine: Engine) -> dict[str, Any]:
    ok, detail = health.readiness(engine)
    return {"ready": ok, "detail": detail}


def installation_view(
    engine: Engine, principal: ProductPrincipal, installation_id: str
) -> dict[str, Any]:
    identifier = require_manage_installation(principal, installation_id)
    with Session(engine) as db:
        installation = _load_installation(db, principal, identifier)
        grant = _grant(principal, identifier)
        revision = (
            db.get(
                integration.ConnectorConfigRevision,
                installation.current_config_revision_id,
            )
            if installation.current_config_revision_id is not None
            else None
        )
        bindings = (
            db.execute(
                select(integration.CapabilityBinding).where(
                    integration.CapabilityBinding.installation_id == installation.id
                )
            )
            .scalars()
            .all()
        )
        counts: dict[str, int] = {
            str(state): int(total)
            for state, total in db.execute(
                select(integration.DeliveryAttempt.state, func.count())
                .where(integration.DeliveryAttempt.installation_id == installation.id)
                .group_by(integration.DeliveryAttempt.state)
            ).all()
        }
        report = secret_loading.last_report()
        names: dict[str, str] = {}
        if revision is not None:
            for name, ref in sorted((revision.secret_refs or {}).items()):
                # NAME and held/unresolved only: neither the reference string
                # nor any value reaches the caller.
                names[str(name)] = "held" if str(ref) in report.held else "unresolved"
        config = revision.config_json if revision is not None else {}
        return {
            "installation": {
                "id": str(installation.id),
                "connector_key": installation.connector_key,
                "state": installation.state,
                "state_reason": installation.state_reason,
            },
            "bindings": [
                {
                    "id": str(b.id),
                    "capability_id": b.capability_id,
                    "state": b.state,
                    "managed": b.id in grant.binding_ids,
                }
                for b in bindings
            ],
            "config": {
                k: v for k, v in sorted(config.items()) if k in grant.config_keys
            },
            "secrets": names,
            "delivery_counts": dict(sorted(counts.items())),
        }


# ── Mutations ───────────────────────────────────────────────────────────────


def set_config(
    engine: Engine,
    principal: ProductPrincipal,
    actor: ManageActor,
    installation_id: str,
    *,
    config: dict[str, object],
    reason: str,
) -> dict[str, Any]:
    identifier = require_manage_installation(principal, installation_id)
    if not config:
        raise HTTPException(422, "config is empty")
    for key in sorted(config):
        if config_key_is_egress(key):
            raise HTTPException(
                403,
                "destination and credential settings are operator-only",
            )
        if key not in _grant(principal, identifier).config_keys:
            raise HTTPException(403, "configuration key is not managed by this caller")
    registry = integration.discover()
    with Session(engine) as db:
        installation = _load_installation(db, principal, identifier)
        if installation.state == "quarantined":
            # The module's configuration write resets the installation to
            # `draft`, which would leave a quarantine without the operator's
            # release. Refused rather than allowed to.
            raise HTTPException(409, "installation is quarantined; operator-only")
        current = (
            db.get(
                integration.ConnectorConfigRevision,
                installation.current_config_revision_id,
            )
            if installation.current_config_revision_id is not None
            else None
        )
        if current is None:
            raise HTTPException(
                409, "installation has no configuration; an operator authors it"
            )
        merged = {**(current.config_json or {}), **config}
        targets = (
            None
            if current.network_targets_json is None
            else integration.network_targets_from_json(current.network_targets_json)
        )
        try:
            revision, is_new = integration.put_config_revision(
                db,
                installation,
                registry=registry,
                config=merged,
                secret_refs=dict(current.secret_refs or {}),
                network_targets=targets,
                schema_version=current.schema_version,
                actor=actor.label,
            )
        except (
            integration.InvalidManifestError,
            integration.LifecycleError,
            integration.SecretValueError,
        ) as exc:
            raise _lifecycle_conflict(exc) from None
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "concurrent configuration write; retry") from None
        _audit(
            db,
            actor,
            action="integrator.manage.config_set",
            entity_type="connector_installation",
            entity_id=str(installation.id),
            details={
                "reason": reason,
                "keys": sorted(config),
                "config_revision_id": str(revision.id),
                "is_new": is_new,
            },
        )
        db.commit()
        return {
            "installation_id": str(installation.id),
            "config_revision_id": str(revision.id),
            "revision": revision.revision,
            "is_new": is_new,
            # A changed configuration takes the installation out of service
            # until an operator re-validates it; said, not hidden.
            "installation_state": installation.state,
        }


def disable_own_binding(
    engine: Engine,
    principal: ProductPrincipal,
    actor: ManageActor,
    installation_id: str,
    binding_id: str,
    *,
    reason: str,
) -> dict[str, Any]:
    identifier = require_manage_installation(principal, installation_id)
    registry = integration.discover()
    with Session(engine) as db:
        installation = _load_installation(db, principal, identifier)
        binding = _load_binding(db, principal, installation, binding_id)
        try:
            integration.set_binding_enabled(
                db,
                installation,
                binding,
                registry=registry,
                enabled=False,
                actor=actor.label,
            )
        except (integration.LifecycleError, integration.ActivationRefused) as exc:
            raise _lifecycle_conflict(exc) from None
        _audit(
            db,
            actor,
            action="integrator.manage.binding_disabled",
            entity_type="capability_binding",
            entity_id=str(binding.id),
            details={"reason": reason, "installation_id": str(installation.id)},
        )
        db.commit()
        return {"id": str(binding.id), "state": binding.state}


def _operator_has_activated(db: Session, binding_id: UUID) -> bool:
    found = db.execute(
        select(PlatformAuditEvent.id)
        .where(
            PlatformAuditEvent.action == _OPERATOR_ACTIVATION_ACTION,
            PlatformAuditEvent.entity_type == "capability_binding",
            PlatformAuditEvent.entity_id == str(binding_id),
        )
        .limit(1)
    ).first()
    return found is not None


def enable_own_binding(
    engine: Engine,
    principal: ProductPrincipal,
    actor: ManageActor,
    installation_id: str,
    binding_id: str,
    *,
    reason: str,
) -> dict[str, Any]:
    identifier = require_manage_installation(principal, installation_id)
    registry = integration.discover()
    with Session(engine) as db:
        installation = _load_installation(db, principal, identifier)
        binding = _load_binding(db, principal, installation, binding_id)
        if installation.state == "quarantined":
            raise HTTPException(409, "installation is quarantined; operator-only")
        if installation.state != "enabled":
            raise HTTPException(
                409, "installation is not enabled; an operator re-validates it"
            )
        if not _operator_has_activated(db, binding.id):
            raise HTTPException(
                409, "binding was never activated; first activation is operator-only"
            )
        try:
            integration.set_binding_enabled(
                db,
                installation,
                binding,
                registry=registry,
                enabled=True,
                actor=actor.label,
            )
        except (
            integration.ActivationRefused,
            integration.InvalidManifestError,
            integration.LifecycleError,
        ) as exc:
            raise _lifecycle_conflict(exc) from None
        _audit(
            db,
            actor,
            action="integrator.manage.binding_enabled",
            entity_type="capability_binding",
            entity_id=str(binding.id),
            details={"reason": reason, "installation_id": str(installation.id)},
        )
        db.commit()
        return {"id": str(binding.id), "state": binding.state}


def valid_address(address: str) -> bool:
    return bool(_ADDRESS.match(address)) and len(address) <= 254


def test_send(
    engine: Engine,
    principal: ProductPrincipal,
    actor: ManageActor,
    installation_id: str,
    binding_id: str,
    *,
    to_address: str,
    reason: str,
    sender: Callable[..., dict[str, Any]] | None,
) -> dict[str, Any]:
    identifier = require_manage_installation(principal, installation_id)
    if not valid_address(to_address):
        raise HTTPException(422, "to_address is not a plain address")
    if sender is None:
        raise HTTPException(503, "test send is not wired in this deployment")
    with Session(engine) as db:
        installation = _load_installation(db, principal, identifier)
        binding = _load_binding(db, principal, installation, binding_id)
        if installation.state != "enabled" or binding.state != "enabled":
            raise HTTPException(409, "installation and binding must both be enabled")
        _audit(
            db,
            actor,
            action="integrator.manage.test_send",
            entity_type="capability_binding",
            entity_id=str(binding.id),
            # The address is the caller's data; its DOMAIN is enough evidence.
            details={
                "reason": reason,
                "installation_id": str(installation.id),
                "to_domain": to_address.rpartition("@")[2].lower(),
            },
        )
        db.commit()
    result = sender(
        engine,
        installation_id=identifier,
        binding_id=binding.id,
        to_address=to_address,
        request_key=f"manage-test:{actor.application}:{binding.id}:{reason[:60]}",
    )
    return dict(result)
