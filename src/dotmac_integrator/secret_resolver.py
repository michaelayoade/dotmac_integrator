"""The RESOLUTION path: held material, looked up by reference. No I/O, ever.

`dotmac_integration` stores secret REFERENCES — `{"api_key": "bao://…"}` — and
refuses to dereference them (`secret_refs.py`). `dispatch.invoke` and
`lifecycle.enable` both need VALUES. This module is the seam between the two,
and ADR-0009 fixes its shape: a secret is HELD, never fetched while handling a
request.

So there are two modules, not one, and the split is load-bearing:

===================== ======================================================
`secret_loading.py`   STARTUP. Reads the references out of the database,
                      dereferences each one through a configured mechanism,
                      installs the result in `dotmac_kernel.secret_sources`.
                      Slow, does I/O, runs once and on explicit refresh.
`secret_resolver.py`  REQUEST. Dict lookups over what was held. Imports no
                      store client, no socket, no filesystem, no ORM — it
                      *cannot* reach anything, which is why the guard over it
                      can be a simple import scan.
===================== ======================================================

`tests/architecture/test_secrets_are_held.py` asserts that separation by
reading this module's imports. A resolver that grew a `requests` import would
be a per-request network call on the authorization path of every connector in
the fleet, and it would look like a one-line convenience in review.

## Keyed by reference, not by name

The held mapping's keys are the reference strings themselves. Two installations
both calling their credential `api_key` point at different material, so the
logical name cannot be the key — the reference is the identity of the material,
and it is the only part of a secret that is safe to write down. That is exactly
why the module is allowed to store it in an immutable revision.

## What is safe to say out loud

References and logical names. Never values. Every error, log line and API
response in this file names what is missing; none of them can name what is
held, because `dotmac_kernel.secret_sources` deliberately ships no accessor
that dumps values.
"""

from __future__ import annotations

from collections.abc import Mapping

from dotmac_kernel.secret_sources import get_secret, secret_names

__all__ = [
    "REDACTION",
    "SecretsNotHeld",
    "held_references",
    "missing_references",
    "redact",
    "resolve_secrets",
]

#: What a held value is replaced with on any outbound string.
REDACTION = "«redacted»"

#: A held value shorter than this cannot be redacted from a message without
#: shredding the message, so `secret_loading` refuses to hold one. Three
#: characters is not a credential; treating it as one would mean either
#: leaking it or turning every diagnostic into confetti.
MINIMUM_REDACTABLE_LENGTH = 4


class SecretsNotHeld(RuntimeError):
    """Referenced material is not in the held set.

    Carries the logical names and their references — never a value, and never a
    hint about what IS held beyond the names `require_secret` would print.
    """

    def __init__(self, missing: Mapping[str, str]) -> None:
        self.missing = dict(missing)
        listed = ", ".join(
            f"{name}={ref}" for name, ref in sorted(self.missing.items())
        )
        super().__init__(
            f"referenced secret material is not held: {listed}. Material is "
            "loaded at startup and on an explicit refresh only (ADR-0009) — "
            "POST /operations/secrets/refresh after making it available, or "
            "correct the reference. Enablement is refused rather than "
            "attempted with a missing credential."
        )


def held_references() -> tuple[str, ...]:
    """Every reference this process currently holds material for.

    References, not values. A reference is a pointer the module already writes
    into an immutable configuration revision, so printing one leaks nothing
    that is not already in every backup.
    """
    return secret_names()


def missing_references(secret_refs: Mapping[str, str]) -> dict[str, str]:
    """`{logical_name: reference}` for everything referenced and not held.

    Separated from `resolve_secrets` because the caller that must REFUSE (the
    enablement gate) wants the whole list to show an operator, and a function
    that raises on the first miss turns one fix into three round trips.
    """
    return {
        name: reference
        for name, reference in (secret_refs or {}).items()
        if get_secret(reference) is None
    }


def resolve_secrets(secret_refs: Mapping[str, str]) -> dict[str, str]:
    """The `dotmac_integration.dispatch.SecretResolver` this deployment supplies.

    Turns `{name: reference}` into `{name: value}` with a dict lookup per
    reference. Nothing here opens a socket, reads a file or touches the
    database: the material was already loaded, which is the entire point of
    ADR-0009 and the reason a provider call cannot be delayed or failed by a
    secret store being unwell.

    Raises rather than returning a partial mapping. A connector handed
    `{"api_key": …}` with `"api_secret"` silently absent authenticates as
    nobody and fails at the provider, which is a much worse diagnosis than a
    refusal naming the reference.
    """
    absent = missing_references(secret_refs)
    if absent:
        raise SecretsNotHeld(absent)
    resolved: dict[str, str] = {}
    for name, reference in (secret_refs or {}).items():
        value = get_secret(reference)
        # Re-checked rather than asserted: `missing_references` and this loop
        # are two passes over a mutable module-level store, and a refresh
        # landing between them would otherwise put `None` into a dict typed
        # `dict[str, str]` and hand it to a connector.
        if value is None:  # pragma: no cover — a refresh raced this call
            raise SecretsNotHeld({name: reference})
        resolved[name] = value
    return resolved


def redact(text: str) -> str:
    """Replace any held value occurring in `text` with `REDACTION`.

    The last line of defence on the way OUT. `lifecycle.enable` puts a
    connector's own `Diagnostic.detail` into `installation.state_reason` and
    into the exception it raises, and a connector that echoes the credential it
    just failed to authenticate with would otherwise put that credential into an
    API response, a log line and an immutable row.

    This does not make a leaking connector acceptable — `operations.enable`
    refuses to COMMIT a revision whose diagnostic contained held material, and
    that refusal is the real guard. This is what keeps the refusal itself from
    quoting the secret while explaining it.

    Values shorter than `MINIMUM_REDACTABLE_LENGTH` cannot be redacted usefully
    and are refused at load time, so every held value reaching this function is
    long enough to substitute without destroying the message.
    """
    if not text:
        return text
    cleaned = text
    for reference in secret_names():
        value = get_secret(reference)
        if value and len(value) >= MINIMUM_REDACTABLE_LENGTH and value in cleaned:
            cleaned = cleaned.replace(value, REDACTION)
    return cleaned
