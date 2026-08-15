"""No identifier reaches a metric label, a log line or a help string.

A Prometheus label is the leak surface people forget is readable. The scrape is
stored unencrypted, kept for as long as the retention of the TSDB rather than
the retention of the row, rendered on dashboards, and pasted into tickets. An
endpoint key, a `provider_event_id`, a subscriber's phone number, message
content or anything derived from a secret must never reach one.

This file proves the exclusion rather than asserting it (ADR-0009, ADR-0018,
`AGENTS.md` rule 8). Every guard below is driven with a REAL-looking
identifier — a `wamid.`, a Nigerian mobile number, a `sha256=` signature — and
shown to be refused. A comment saying "do not put PII in labels" would have
passed every review and stopped nothing.

The mechanism being tested is structural, not textual: `MetricFamily` declares
the complete set of label values it will ever accept and `render` raises on
anything else, so there is no code path that could emit an identifier. That is
why these tests can be short.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from dotmac_integrator import telemetry
from dotmac_integrator.telemetry import (
    FAMILIES,
    IngressCounters,
    Sample,
    UndeclaredLabel,
    render,
)

SRC = Path(telemetry.__file__).resolve().parent

#: What must never appear. Real shapes, not placeholders: a guard proven against
#: `"secret"` proves nothing about `wamid.HBgNMjM0ODAxMjM0NTY3OA`.
LEAKY_VALUES = (
    "wamid.HBgNMjM0ODAxMjM0NTY3OBUCABIYFjNFQjBEQzY5",  # provider event id
    "+2348012345678",  # subscriber number
    "when is my router due",  # message content
    "sha256=8f9c1d0a5b",  # signature, secret-derived
    "EAAJx0ZBk8ZC4BO",  # endpoint / page access token
    "acct_1MqLd2eZvKYlo2C",  # provider account key
)

#: Attribute and field names whose VALUES are one of the above. A log call that
#: interpolates any of these is interpolating an identifier.
SENSITIVE_NAMES = frozenset(
    {
        "provider_event_id",
        "payload",
        "payload_json",
        "headers",
        "headers_json",
        "idempotency_key",
        "secret",
        "secrets",
        "secret_refs",
        "token",
        "signature",
        "connector_key",
        "endpoint_key",
        "config_json",
    }
)


# ── Detector, written as a pure function so it can be proven to bite ────────


def _logging_calls_naming_sensitive_fields(source: str) -> set[str]:
    """Names from `SENSITIVE_NAMES` reachable from a logging call's arguments.

    An AST walk rather than a regex over the file: `logger.info("payload")` in a
    docstring or a comment is not a leak, and a guard a comment can trip is a
    guard that gets turned off.
    """
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr not in {"debug", "info", "warning", "error", "exception"}:
            continue
        for argument in [*node.args, *(kw.value for kw in node.keywords)]:
            for inner in ast.walk(argument):
                if isinstance(inner, ast.Attribute) and inner.attr in SENSITIVE_NAMES:
                    found.add(inner.attr)
                elif isinstance(inner, ast.Name) and inner.id in SENSITIVE_NAMES:
                    found.add(inner.id)
                elif (
                    isinstance(inner, ast.Constant)
                    and isinstance(inner.value, str)
                    and inner.value in SENSITIVE_NAMES
                ):
                    found.add(inner.value)
    return found


# ── 1. Every label set is closed ────────────────────────────────────────────


def test_every_labelled_family_declares_its_complete_allowed_set() -> None:
    """An open label set is how an identifier becomes a time series. There is
    no "we will validate at the call site" option: the family either enumerates
    its values or it carries none."""
    for family in FAMILIES:
        if family.label is None:
            assert family.allowed == (), family.name
        else:
            assert family.allowed, (
                f"{family.name} is labelled but declares no allowed set. "
                "Cardinality would then be whatever a row contains"
            )
            assert len(family.allowed) == len(set(family.allowed)), family.name


def test_no_family_carries_more_than_one_label() -> None:
    """Two labels multiply. A control plane's metrics have no question that
    needs the product, and the cross product is where cardinality accidents
    live."""
    for family in FAMILIES:
        assert family.label is None or "," not in family.label


# ── 2. An identifier cannot reach a label. Proven, not asserted. ────────────


@pytest.mark.parametrize("leaky", LEAKY_VALUES)
def test_a_real_identifier_cannot_become_a_label(leaky: str) -> None:
    """The sensitivity proof for the whole file: the guard is shown firing on
    the exact values it exists to keep out."""
    labelled = next(f for f in FAMILIES if f.label is not None)
    with pytest.raises(UndeclaredLabel) as excinfo:
        render([Sample(labelled.name, 1.0, leaky)])
    assert labelled.name in str(excinfo.value)


@pytest.mark.parametrize("leaky", LEAKY_VALUES)
def test_a_counter_cannot_be_incremented_under_an_identifier(leaky: str) -> None:
    """The other door into the same series. Refusing only at render time would
    leave a caller believing the value was recorded."""
    counters = IngressCounters()
    with pytest.raises(UndeclaredLabel):
        counters.record_refusal(leaky)
    with pytest.raises(UndeclaredLabel):
        counters.record_signature(leaky)
    with pytest.raises(UndeclaredLabel):
        counters.record_challenge(leaky)


def test_an_unlabelled_family_refuses_a_label_it_never_declared() -> None:
    unlabelled = next(f for f in FAMILIES if f.label is None)
    with pytest.raises(UndeclaredLabel):
        render([Sample(unlabelled.name, 1.0, "+2348012345678")])


def test_an_undeclared_family_is_refused_too() -> None:
    """Otherwise a new metric could be emitted with no declared label set at
    all, which is the same hole reached from the other side."""
    with pytest.raises(UndeclaredLabel):
        render([Sample("integrator_something_someone_added", 1.0, "whatever")])


def test_the_guard_is_not_vacuous() -> None:
    """A check that refuses everything passes the tests above for the wrong
    reason. A DECLARED label must still render."""
    labelled = next(f for f in FAMILIES if f.label is not None)
    output = render([Sample(labelled.name, 3.0, labelled.allowed[0])])
    assert f'{labelled.label}="{labelled.allowed[0]}"' in output


# ── 3. Names and help strings ───────────────────────────────────────────────


def test_no_metric_name_or_help_text_promises_an_identifier() -> None:
    """A metric called `..._by_provider_event_id` would be a label leak someone
    was planning. The name is the design review."""
    for family in FAMILIES:
        for banned in ("provider_event_id", "phone", "msisdn", "token", "secret"):
            assert banned not in family.name, family.name
            assert banned not in family.help.lower(), family.name


# ── 4. Log lines ────────────────────────────────────────────────────────────


def test_no_log_call_in_this_assembly_interpolates_a_sensitive_field() -> None:
    """Same rule, second surface. A log line outlives the row it describes and
    is shipped to more places."""
    offenders: dict[str, set[str]] = {}
    for path in sorted(SRC.rglob("*.py")):
        found = _logging_calls_naming_sensitive_fields(path.read_text(encoding="utf-8"))
        if found:
            offenders[path.name] = found
    assert not offenders, (
        f"logging calls name {offenders}. Log a COUNT, an internal UUID or a "
        "declared reason — never a provider identifier, a payload or anything "
        "derived from a secret (ADR-0009: names are logged, values never)"
    )


def test_the_log_detector_bites() -> None:
    """Sensitivity proof. Without this, the empty result above would pass
    whether the detector worked or not."""
    violation = (
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def f(receipt):\n"
        "    logger.info('replaying %s', receipt.provider_event_id)\n"
    )
    assert _logging_calls_naming_sensitive_fields(violation) == {"provider_event_id"}


def test_the_log_detector_does_not_fire_on_prose() -> None:
    """A docstring mentioning `payload` is not a leak, and a detector that said
    so would be disabled within a week."""
    innocent = (
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def f(count):\n"
        "    '''Never logs a payload.'''\n"
        "    # payload stays in the row\n"
        "    logger.info('released %s expired lease(s)', count)\n"
    )
    assert _logging_calls_naming_sensitive_fields(innocent) == set()
