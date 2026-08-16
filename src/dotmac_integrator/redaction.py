"""The ingress endpoint key is a BEARER credential carried in the URL PATH.

`capability_bindings.ingress_endpoint_key` is the whole address of an ingress
endpoint, and whoever holds it can drive that connector's `verify`. The module
that mints it says so, and takes deliberate structural care to keep it out of
its own error text (`dotmac_integration.ingress`, "The endpoint key stops at
phase 1, and never renders"): it arrives as a `repr`-less `EndpointAddress`, it
is never interpolated into a refusal, the failing lookup is converted so a
driver cannot print its own bound parameters, and it is not a field of
`PreparedIngress`.

**Every one of those defences is inside the module, and none of them can help
with the URL.** The credential is in the request line, and the request line is
the single most reliably logged string in any HTTP deployment. An access log
that records

    GET /ingress/8f2c…e41 HTTP/1.1 200

has published the credential to whatever ships logs, for as long as they are
kept, and it did so on the SUCCESSFUL path — so nothing about it looks like an
incident. That is the leak this module exists to close, and it is why the
redaction lives at the edge rather than in the engine: the engine never sees
the URL.

## Where the key can reach, and what stops it

============================== =============================================
Access log (`uvicorn.access`)  A logging FILTER on the logger, installed by
                               name so it applies whether or not a handler
                               has been attached yet.
Error log (`uvicorn.error`),   The same filter. Starlette logs an unhandled
the root logger, ours          exception through `uvicorn.error`, and the
                               message can carry the path.
A traceback's frame LOCALS     Not a formatter's job — a standard traceback
                               renders source lines, not locals, but an error
                               REPORTER configured to capture locals uploads
                               them. The route handler `del`s the raw string
                               instead, so there is no binding to capture.
                               See `assembly.py`'s ingress routes.
A metric label                 Structurally impossible: `telemetry.render`
                               refuses a label value that is not in a closed
                               declared set, and no set contains a key.
A 422 validation body          The path parameter is an unvalidated `str`, so
                               FastAPI has no rejection that would echo the
                               value back into a response body — and into the
                               log line that response produces.
============================== =============================================

## Why the pattern matches more than a well-formed key

A well-formed key is 48 lowercase hex characters. This redacts *everything* in
the path segment after `/ingress/`, well-formed or not, because the strings
most worth redacting are the malformed ones: a probe carrying a credential
lifted from somewhere else, a truncated key, a key with a stray character from
a copy-paste. Matching only the valid shape would publish exactly those.

Redaction is one-way and lossy on purpose. An operator correlating a specific
endpoint uses the audit ledger and the `binding_id` the engine returns, never
the log line — the ledger is access-controlled and the log is not.
"""

from __future__ import annotations

import logging
import re
from typing import Final

__all__ = [
    "INGRESS_KEY_PATTERN",
    "REDACTED",
    "REDACTED_LOGGERS",
    "IngressKeyRedactingFilter",
    "install_log_redaction",
    "redact_ingress_keys",
]

#: What replaces the credential. A fixed marker rather than a truncation: a
#: prefix of a bearer credential is still a meaningful head start, and a
#: truncation invites someone to widen it "just enough to correlate".
REDACTED: Final = "<redacted>"

#: Everything in the path segment following `/ingress/`. Stops at a `/`, a
#: `?`, whitespace or a quote, so a query string and a following HTTP version
#: survive — an access log with the credential removed is still a useful
#: access log.
INGRESS_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(r"(?<=/ingress/)[^\s/?\"'#]+")

#: Loggers the filter is installed on. `uvicorn.access` is the one that
#: matters; the others are here because an unhandled exception's message and
#: any line this application logs itself can carry a path too.
#:
#: Attached to LOGGERS rather than to handlers, deliberately. Handlers are
#: attached by whatever configures logging — uvicorn, gunicorn, a deployment's
#: own dictConfig — at a time this module cannot depend on. A logger exists by
#: name the moment it is asked for, so installing here works regardless of
#: ordering, and re-installing is a no-op.
REDACTED_LOGGERS: Final[tuple[str, ...]] = (
    "uvicorn.access",
    "uvicorn.error",
    "dotmac_integrator",
)


def redact_ingress_keys(text: str) -> str:
    """Replace every ingress endpoint key in `text` with :data:`REDACTED`."""
    return INGRESS_KEY_PATTERN.sub(REDACTED, text)


class IngressKeyRedactingFilter(logging.Filter):
    """Redacts the rendered message of every record passing through.

    A `logging.Filter` rather than a `logging.Formatter`, and the difference
    matters: a formatter belongs to a HANDLER, and this application does not own
    the handlers — uvicorn attaches them, a deployment's `dictConfig` may
    replace them, and a log shipper may add another. A filter on the named
    LOGGER applies to every record that logger emits, whatever is attached
    downstream and whenever it was attached.

    The record's `msg` and `args` are collapsed into one already-rendered,
    already-redacted string. Collapsing is the point rather than a side effect:
    redacting `msg` alone would leave the credential sitting in `args`, where
    the formatter would interpolate it straight back in, and a structured
    handler reading `record.args` would ship it untouched.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:  # pragma: no cover — a broken format string is not ours
            return True
        redacted = redact_ingress_keys(rendered)
        if redacted != rendered:
            record.msg = redacted
            record.args = ()
        # Always True. This filter redacts; it does not decide what is logged.
        # Dropping the record instead would delete the evidence that a request
        # arrived at all, which is the opposite of what an access log is for.
        return True


def install_log_redaction() -> None:
    """Attach the filter to every logger a key could be rendered through.

    Idempotent: called again, it adds nothing. `create_app` calls it at
    construction, and a worker-only process calls it too — a deployment that
    only ran the redaction inside `create_app` would leave an API-less replica
    logging unredacted.
    """
    for name in REDACTED_LOGGERS:
        logger = logging.getLogger(name)
        if not any(
            isinstance(existing, IngressKeyRedactingFilter)
            for existing in logger.filters
        ):
            logger.addFilter(IngressKeyRedactingFilter())
