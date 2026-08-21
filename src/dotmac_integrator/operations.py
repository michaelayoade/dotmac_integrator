"""Operational controls: session, fetch, delegate, serialise.

The routes in `assembly.py` hold no session and issue no query — same split the
Starter enforces between `router.py` and `service.py`, for the same reason. This
file is the assembly's service layer, and it is thin by construction: every
function here loads what the module's operation needs, calls it, and converts
the result to JSON.

**No decision is made in this file.** `release_expired_leases`, `health_report`,
`replay_delivery`, `replay_receipt` and `enable` all belong to
`dotmac_integration`. What is added is a transaction boundary, a serialisation,
and the two things a module composed by an unknown assembly cannot supply
itself: the materialised secrets its enablement gate needs, and the identity of
the person who asked.

## Actor and reason are threaded, not optional

`dotmac_integration.record_operation` takes `actor_admin_id` with a default of
`None`, so an unauthenticated repair writes an audit row with a null actor and
succeeds. That default is correct for a module that must not presume its host's
identity model, and wrong for this deployment — so every operator-triggered
function here takes an `OperatorIdentity` positionally and passes both
representations through. An audit row that cannot say who and why is not
evidence.

The one caller that legitimately passes no actor is the worker's timed lease
sweep: a schedule is not a person. It is a separate function
(`sweep_expired_leases`) rather than a default argument, so the distinction is
visible in the call site instead of hidden in a signature.

## The transaction owner exercises its authority

The module contains connector-owned validation detail from a6 onward: only a
bounded diagnostic code reaches state or an exception. This assembly still
redacts every external error and owns commit/rollback, because containment is a
layered contract rather than permission to trust a plugin's future text.
"""

from __future__ import annotations

import dataclasses
from typing import Any
from uuid import UUID

import dotmac_integration as integration
from dotmac_kernel.audit import write_platform_audit_event
from fastapi import HTTPException
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dotmac_integrator import runtime_policy, secret_loading, telemetry
from dotmac_integrator.manifest import INTEGRATOR_AUDIT_ACTIONS
from dotmac_integrator.operator_auth import OperatorIdentity
from dotmac_integrator.secret_resolver import (
    missing_references,
    redact,
    resolve_secrets,
)


#: Audit actions this ASSEMBLY writes, under its own prefix.
#:
#: `integration.*` is the module's vocabulary and it declares three of them on
#: its manifest; writing a fourth from here would make this deployment a second
#: author of someone else's registry (hard rule 12). These are operations the
#: assembly genuinely owns — enablement is gated on material only a deployment
#: can materialise, and a secret refresh has no module-side existence at all.
#:
#: `tests/architecture/test_audit_actions_are_declared.py` asserts in both
#: directions: nothing is written that is not declared here, and nothing is
#: declared here without a writer.
def _record(
    db: Session,
    actor: OperatorIdentity,
    *,
    action: str,
    entity_type: str,
    entity_id: str | None,
    details: dict[str, object],
) -> None:
    """Write one assembly-owned platform audit event.

    Goes through the kernel's platform ledger directly rather than through
    `integration.record_operation`, which would prefix the action with
    `integration.` and put an undeclared code into the module's namespace.
    """
    if action not in INTEGRATOR_AUDIT_ACTIONS:  # pragma: no cover — see the test
        raise AssertionError(f"undeclared audit action {action!r}")
    write_platform_audit_event(
        db,
        actor_admin_id=actor.admin_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details={"actor": actor.label, "mechanism": actor.mechanism, **details},
    )


def _jsonable(value: Any) -> Any:
    """Serialise a module result without importing its private types.

    Deliberately structural rather than a per-type mapping: a mapping would need
    editing every time the module adds a field, and a stale mapping silently
    drops data from an operational report — the one place a reader assumes they
    are seeing everything.
    """
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {k: _jsonable(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_jsonable(v) for v in value]
    if isinstance(value, UUID):
        return str(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def _jsonable_mapping(value: Any) -> dict[str, Any]:
    """`_jsonable` for a value that must serialise to an object.

    A checked narrowing rather than a `cast`. The module's operations return
    dataclasses today, so this always holds — but `cast` would assert it and a
    future return type that serialises to a list would then reach the client as
    a JSON array from a handler typed as returning an object, which fails at the
    consumer instead of here.
    """
    serialised = _jsonable(value)
    if not isinstance(serialised, dict):
        raise TypeError(
            f"expected an object-shaped result, got {type(value).__name__} "
            f"serialising to {type(serialised).__name__}"
        )
    return serialised


def _repaired(row: Any) -> dict[str, Any]:
    """What a repair command returns to the operator.

    An EXPLICIT projection, not `_jsonable`. The module's repair commands
    return the ORM row, which is neither a dataclass nor a mapping — the
    structural serialiser falls through to `str()` on it, and
    `_jsonable_mapping` then raises `TypeError` from inside a handler that has
    already committed. Both replay routes did exactly that.

    Explicit is also the right answer on its own terms: `InboxReceipt` and
    `DeliveryAttempt` carry `payload_json`, and a repair acknowledgement is no
    place to echo a provider payload back over HTTP.
    """
    return {
        "id": str(row.id),
        "state": row.state,
        "attempt_count": row.attempt_count,
    }


def _uuid(raw: str, field: str) -> UUID:
    try:
        return UUID(raw)
    except ValueError as exc:
        # Counted by REASON, never by value. `raw` reaches the caller who sent
        # it — it must not reach a metric label, where it would be stored for a
        # year and rendered on every dashboard that groups by it.
        telemetry.counters.record_refusal("malformed_identifier")
        raise HTTPException(422, f"{field} is not a UUID: {raw!r}") from exc


def installed_connectors() -> dict[str, Any]:
    """What this deployment can actually dispatch to.

    Entry-point discovery, so the answer is the set of INSTALLED connector
    distributions — not a list this assembly maintains. A connector appears here
    by being installed, which is the only mechanism; there is no registration
    call and no provider identity hardcoded in generic assembly source.
    """
    registry = integration.discover()
    plugins = getattr(registry, "plugins", ())
    return {
        "spi_version": str(integration.CURRENT_SPI_VERSION),
        "entry_point_group": integration.ENTRY_POINT_GROUP,
        "count": len(plugins),
        "connectors": _jsonable(
            [getattr(p, "manifest", p) for p in plugins],
        ),
    }


def connector_runtime_policy() -> dict[str, Any]:
    """The runtime boundaries the installed connectors declared, projected.

    A read, and a pure one: no session, no query, no held material. It sits here
    rather than in the route for the same reason `installed_connectors` does —
    `assembly.py` is this repository's `router.py`, and a handler that assembles
    its own answer is a handler somebody will later add a decision to.

    What an operator gets is the exact set a deployment may allow out, the named
    secret bindings it must satisfy, a digest identifying the manifest set the
    whole answer was projected from, and the capability coverage on both sides.
    See `runtime_policy.py` for why coverage is reported and never refused.
    """
    return runtime_policy.policy_report(runtime_policy.projected_policy())


def health_report(engine: Engine) -> dict[str, Any]:
    with Session(engine) as db:
        return _jsonable_mapping(integration.health_report(db))


def shadow_report(engine: Engine, comparison_revision: str) -> dict[str, object]:
    """Aggregate module-owned evidence; never approve a product cutover."""

    if not comparison_revision.strip():
        raise HTTPException(
            409,
            "shadow comparison is not configured; set an immutable "
            "PRODUCT_PORT_SHADOW_REVISION in mirror mode",
        )
    with Session(engine) as db:
        return integration.shadow_report(
            db, comparison_revision=comparison_revision
        ).as_dict()


def _lifecycle_conflict(exc: Exception) -> HTTPException:
    """Translate a module refusal without broadening or leaking its text."""
    detail = redact(str(exc)).strip() or "integration lifecycle operation refused"
    return HTTPException(409, detail)


def _installation(db: Session, raw: str) -> Any:
    identifier = _uuid(raw, "installation_id")
    row = db.get(integration.ConnectorInstallation, identifier)
    if row is None:
        raise HTTPException(404, f"no installation {raw}")
    return row


def _binding(db: Session, raw: str) -> Any:
    identifier = _uuid(raw, "binding_id")
    row = db.get(integration.CapabilityBinding, identifier)
    if row is None:
        raise HTTPException(404, f"no binding {raw}")
    return row


# ── Authoring — provider-neutral adapters over the module lifecycle ─────────


def create_installation(
    engine: Engine,
    *,
    connector_key: str,
    name: str,
    environment: str,
    actor: OperatorIdentity,
    reason: str,
) -> dict[str, Any]:
    """Draft and pin one connector discovered from installed metadata."""
    registry = integration.discover()
    with Session(engine) as db:
        try:
            installation = integration.create_draft(
                db,
                registry=registry,
                connector_key=connector_key,
                name=name,
                environment=environment,
                actor=actor.label,
            )
            _record(
                db,
                actor,
                action="integrator.installation.drafted",
                entity_type="connector_installation",
                entity_id=str(installation.id),
                details={
                    "reason": reason,
                    "connector_key": installation.connector_key,
                    "connector_version": installation.connector_version,
                    "environment": installation.environment,
                },
            )
            db.commit()
        except integration.InvalidManifestError as exc:
            raise _lifecycle_conflict(exc) from None
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                409,
                "an installation with this connector key and name already exists",
            ) from None
        return {
            "id": str(installation.id),
            "connector_key": installation.connector_key,
            "connector_version": installation.connector_version,
            "manifest_digest": installation.manifest_digest,
            "name": installation.name,
            "environment": installation.environment,
            "state": installation.state,
        }


def configure_installation(
    engine: Engine,
    installation_id: str,
    *,
    config: dict[str, object],
    secret_refs: dict[str, object],
    schema_version: str,
    actor: OperatorIdentity,
    reason: str,
) -> dict[str, Any]:
    """Mint or select an immutable, digest-idempotent configuration revision."""
    registry = integration.discover()
    with Session(engine) as db:
        installation = _installation(db, installation_id)
        try:
            revision, is_new = integration.put_config_revision(
                db,
                installation,
                registry=registry,
                config=config,
                secret_refs=secret_refs,
                schema_version=schema_version,
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
            raise HTTPException(
                409,
                "configuration revision conflicted with a concurrent write; retry",
            ) from None
        _record(
            db,
            actor,
            action="integrator.installation.configured",
            entity_type="connector_installation",
            entity_id=str(installation.id),
            details={
                "reason": reason,
                "config_revision_id": str(revision.id),
                "revision": revision.revision,
                "schema_version": revision.schema_version,
                "is_new": is_new,
            },
        )
        db.commit()
        return {
            "installation_id": str(installation.id),
            "config_revision_id": str(revision.id),
            "revision": revision.revision,
            "schema_version": revision.schema_version,
            "config_digest": revision.config_digest,
            "validation_status": revision.validation_status,
            "is_new": is_new,
            "installation_state": installation.state,
        }


def configure_binding(
    engine: Engine,
    installation_id: str,
    *,
    capability_id: str,
    scope: dict[str, object] | None,
    policy: dict[str, object] | None,
    actor: OperatorIdentity,
    reason: str,
) -> dict[str, Any]:
    """Create or update the one binding for a declared capability."""
    registry = integration.discover()
    with Session(engine) as db:
        installation = _installation(db, installation_id)
        try:
            binding = integration.add_binding(
                db,
                installation,
                registry=registry,
                capability_id=capability_id,
                scope=scope,
                policy=policy,
                actor=actor.label,
            )
        except (integration.InvalidManifestError, integration.LifecycleError) as exc:
            raise _lifecycle_conflict(exc) from None
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                409,
                "capability binding conflicted with a concurrent write; retry",
            ) from None
        _record(
            db,
            actor,
            action="integrator.binding.configured",
            entity_type="capability_binding",
            entity_id=str(binding.id),
            details={
                "reason": reason,
                "installation_id": str(installation.id),
                "capability_id": binding.capability_id,
            },
        )
        db.commit()
        return {
            "id": str(binding.id),
            "installation_id": str(installation.id),
            "capability_id": binding.capability_id,
            "state": binding.state,
        }


def mint_binding_ingress_endpoint(
    engine: Engine,
    binding_id: str,
    *,
    actor: OperatorIdentity,
    reason: str,
) -> dict[str, Any]:
    """Mint one bearer address and return its key exactly once."""
    registry = integration.discover()
    with Session(engine) as db:
        binding = _binding(db, binding_id)
        try:
            endpoint_key = integration.mint_ingress_endpoint(
                db, binding, registry=registry, actor=actor.label
            )
        except (integration.InvalidManifestError, integration.LifecycleError) as exc:
            raise _lifecycle_conflict(exc) from None
        _record(
            db,
            actor,
            action="integrator.ingress_endpoint.minted",
            entity_type="capability_binding",
            entity_id=str(binding.id),
            details={
                "reason": reason,
                "installation_id": str(binding.installation_id),
                "capability_id": binding.capability_id,
            },
        )
        db.commit()
        return {
            "binding_id": str(binding.id),
            "ingress_endpoint_key": endpoint_key,
        }


def enable_binding(
    engine: Engine,
    binding_id: str,
    *,
    actor: OperatorIdentity,
    reason: str,
) -> dict[str, Any]:
    """Enable one binding after the module proves it is activatable."""
    registry = integration.discover()
    with Session(engine) as db:
        binding = _binding(db, binding_id)
        installation = db.get(
            integration.ConnectorInstallation, binding.installation_id
        )
        if installation is None:  # pragma: no cover - protected by the FK
            raise HTTPException(409, "binding installation is missing")
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
        _record(
            db,
            actor,
            action="integrator.binding.enabled",
            entity_type="capability_binding",
            entity_id=str(binding.id),
            details={
                "reason": reason,
                "installation_id": str(installation.id),
                "capability_id": binding.capability_id,
            },
        )
        db.commit()
        return {
            "id": str(binding.id),
            "installation_id": str(installation.id),
            "capability_id": binding.capability_id,
            "state": binding.state,
            "enabled_at": (
                binding.enabled_at.isoformat()
                if binding.enabled_at is not None
                else None
            ),
        }


# ── Secret material ─────────────────────────────────────────────────────────


def secret_status() -> dict[str, Any]:
    """Which references this process holds material for. NAMES ONLY.

    There is no accessor anywhere in this deployment that returns a held value,
    and this is the closest thing to one on purpose: an operator diagnosing a
    refused enablement needs to know whether the reference resolved, and never
    needs to see what it resolved to.
    """
    return secret_loading.last_report().as_dict()


def refresh_secret_material(
    engine: Engine, actor: OperatorIdentity, reason: str
) -> dict[str, Any]:
    """Re-read every stored reference. THE rotation operation (ADR-0009).

    Explicit rather than a TTL: a rotation takes effect when an operator says
    so. `dotmac_kernel.secret_sources` keeps the working set if the reload
    fails, so a mount that vanished mid-rotation leaves a working process
    working — and this function propagates the failure so the operator learns
    the rotation did not land.
    """
    report = secret_loading.refresh()
    payload = report.as_dict()
    with Session(engine) as db:
        _record(
            db,
            actor,
            action="integrator.secrets.refreshed",
            entity_type="secret_material",
            entity_id=None,
            details={
                "reason": reason,
                # References and counts. A held VALUE has no path to this row.
                "held_count": len(report.held),
                "unresolved": sorted(report.unresolved),
            },
        )
        db.commit()
    return payload


# ── Enablement — the gate the resolver exists for ───────────────────────────


def enable_installation(
    engine: Engine, installation_id: str, actor: OperatorIdentity, reason: str
) -> dict[str, Any]:
    """Enable an installation after materialising its referenced secrets.

    This is the whole reason the held-secret resolver comes first.
    `lifecycle.enable` refuses to enable anything without a LIVE
    `validate_connection`, and `validate_connection` takes VALUES — so until
    something could turn `{"api_key": "bao://…"}` into material, no connector in
    this fleet could be enabled at all.

    Order matters: material is checked BEFORE the connector is asked to
    validate. A missing credential produces a refusal naming the reference,
    rather than a provider-side authentication failure that reads like the
    provider is down.
    """
    identifier = _uuid(installation_id, "installation_id")
    with Session(engine) as db:
        installation = db.get(integration.ConnectorInstallation, identifier)
        if installation is None:
            raise HTTPException(404, f"no installation {installation_id}")

        revision = (
            db.get(
                integration.ConnectorConfigRevision,
                installation.current_config_revision_id,
            )
            if installation.current_config_revision_id is not None
            else None
        )
        if revision is None:
            raise HTTPException(
                409,
                "installation has no configuration revision; there is nothing "
                "to validate a connection against",
            )

        secret_refs: dict[str, str] = {
            str(name): str(reference)
            for name, reference in (revision.secret_refs or {}).items()
        }
        absent = missing_references(secret_refs)
        if absent:
            _record(
                db,
                actor,
                action="integrator.installation.enable_refused",
                entity_type="connector_installation",
                entity_id=str(installation.id),
                details={
                    "reason": reason,
                    "refusal": "material_not_held",
                    "missing": sorted(absent.values()),
                },
            )
            db.commit()
            raise HTTPException(
                409,
                "referenced secret material is not held: "
                f"{sorted(absent.values())}. Material loads at startup and on "
                "an explicit POST /operations/secrets/refresh (ADR-0009); "
                "enablement is refused rather than attempted without it",
            )

        # A FRESH `dict[str, object]`, not the resolver's `dict[str, str]`.
        # `lifecycle.enable` takes `dict[str, object] | None` and `dict` is
        # invariant, so handing it the resolver's mapping does not type — and a
        # `cast` would be the wrong repair, because the widened parameter says
        # the module may put a non-`str` into whatever it is given. Copying is
        # what makes that its business rather than a mutation of the assembly's
        # resolved set. Surfaced by the a1 -> a3 pin bump, which widened the
        # parameter; there is no behaviour change.
        secrets: dict[str, object] = dict(resolve_secrets(secret_refs))
        registry = integration.discover()
        try:
            integration.enable(
                db,
                installation,
                registry=registry,
                secrets=secrets,
                actor=actor.label,
            )
        except integration.LifecycleError as exc:
            detail = redact(str(exc))
            reported = installation.state_reason or ""
            if redact(reported) != reported:
                # The connector put held material into its own diagnostic, and
                # the module already flushed it onto the installation row. This
                # assembly owns the transaction, so the row does not land.
                db.rollback()
                raise HTTPException(
                    502,
                    "the connector's validation diagnostic contained secret "
                    "material; the failure was NOT recorded, because a "
                    "configuration row is immutable and reaches every backup. "
                    "Fix the connector: a diagnostic may name a credential, "
                    "never quote one",
                ) from exc
            _record(
                db,
                actor,
                action="integrator.installation.enable_refused",
                entity_type="connector_installation",
                entity_id=str(installation.id),
                details={
                    "reason": reason,
                    "refusal": "validation_failed",
                    "detail": detail,
                },
            )
            db.commit()
            raise HTTPException(409, detail) from exc
        except integration.InvalidManifestError as exc:
            # The connector distribution named by the installation is not
            # installed in this runtime. Evidenced like the other refusals: an
            # operator whose enablement failed because the deploy shipped
            # without the connector needs that in the trail, not only in a
            # response body they may not have kept.
            _record(
                db,
                actor,
                action="integrator.installation.enable_refused",
                entity_type="connector_installation",
                entity_id=str(installation.id),
                details={
                    "reason": reason,
                    "refusal": "connector_not_installed",
                    "connector_key": installation.connector_key,
                },
            )
            db.commit()
            raise HTTPException(409, str(exc)) from exc

        _record(
            db,
            actor,
            action="integrator.installation.enabled",
            entity_type="connector_installation",
            entity_id=str(installation.id),
            details={
                "reason": reason,
                "connector_key": installation.connector_key,
                "config_revision": str(revision.id),
                # References, so the trail records WHICH material authorised
                # this enablement without recording the material.
                "secret_references": sorted(secret_refs.values()),
            },
        )
        db.commit()
        return {
            "id": str(installation.id),
            "connector_key": installation.connector_key,
            "state": installation.state,
            "enabled_at": (
                installation.enabled_at.isoformat()
                if installation.enabled_at is not None
                else None
            ),
        }


# ── Repair ──────────────────────────────────────────────────────────────────


def release_expired_leases(
    engine: Engine, actor: OperatorIdentity, reason: str
) -> dict[str, Any]:
    """Sweep leases whose holder died, at an operator's request.

    Committed here because the module's operation is a mutation and the module
    does not own the transaction — `dotmac_kernel.db` holds that authority in the
    Starter, and in this deployment the assembly does.

    `reason` is carried in this assembly's own audit detail because the module's
    `leases.released` event records the count and the ids but has no `reason`
    field — a gap raised with the module rather than papered over here.
    """
    with Session(engine) as db:
        released = integration.release_expired_leases(db, actor_admin_id=actor.admin_id)
        db.commit()
    return {"released": released, "reason": reason, "actor": actor.label}


def sweep_expired_leases(engine: Engine) -> int:
    """The TIMED sweep. No actor, because a schedule is not a person.

    Separate from `release_expired_leases` rather than an optional argument:
    the difference between "the deployment reclaimed a dead worker's lease on
    its timer" and "someone reclaimed it" is exactly what a reader of the trail
    needs, and a default parameter hides which one happened.
    """
    with Session(engine) as db:
        released = integration.release_expired_leases(db)
        db.commit()
    return released


def replay_delivery(
    engine: Engine, delivery_id: str, actor: OperatorIdentity, reason: str
) -> dict[str, Any]:
    """Replay one delivery.

    `reason` is required by the module and passed through unaltered. An assembly
    that supplied a default here ("replayed via API") would put a fabricated
    justification into the audit record of a manual intervention, which is worse
    than having no record.
    """
    identifier = _uuid(delivery_id, "delivery_id")
    with Session(engine) as db:
        delivery = db.get(integration.DeliveryAttempt, identifier)
        if delivery is None:
            telemetry.counters.record_refusal("not_found")
            raise HTTPException(404, f"no delivery {delivery_id}")
        try:
            replayed = integration.replay_delivery(
                db, delivery, actor_admin_id=actor.admin_id, reason=reason
            )
        except integration.NotRepairable as exc:
            telemetry.counters.record_refusal("not_repairable")
            raise HTTPException(409, str(exc)) from exc
        db.commit()
        return _repaired(replayed)


def replay_receipt(
    engine: Engine, receipt_id: str, actor: OperatorIdentity, reason: str
) -> dict[str, Any]:
    identifier = _uuid(receipt_id, "receipt_id")
    with Session(engine) as db:
        receipt = db.get(integration.InboxReceipt, identifier)
        if receipt is None:
            telemetry.counters.record_refusal("not_found")
            raise HTTPException(404, f"no receipt {receipt_id}")
        try:
            replayed = integration.replay_receipt(
                db, receipt, actor_admin_id=actor.admin_id, reason=reason
            )
        except integration.NotRepairable as exc:
            telemetry.counters.record_refusal("not_repairable")
            raise HTTPException(409, str(exc)) from exc
        db.commit()
        return _repaired(replayed)
