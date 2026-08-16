"""An alert on a metric nobody publishes is worse than no alert at all.

It never fires, and it never says it cannot fire — so it reads as a quiet
system, forever. This repository has already shipped one:
`IntegratorUnknownTargetRefusals` fired on
`integrator_ingress_refusals_total{reason="unknown_target"}`, and
`unknown_target` was a label value invented before the ingress adapter existed.
The engine produces `endpoint_unknown`. The alert would have sat green through
every unrouted delivery until somebody happened to compare the two files.

So this walks the rules and asserts that every `integrator_*` metric they
mention is a family `telemetry.py` actually declares, or a recording rule this
same file defines. It is deliberately a TEXT scan rather than a YAML parse:
PyYAML is not a dependency of this assembly, and adding one to lint a config
file would be a real cost for a check a regex does exactly as well.

Label VALUES are checked the same way for the two closed vocabularies whose
names are stable enough to match — the same drift, one level down.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from dotmac_integrator import telemetry

RULES = Path(__file__).resolve().parents[2] / "deploy" / "alerts" / "ingress.rules.yml"

#: Every `integrator_…` token anywhere in the file.
_METRIC = re.compile(r"\bintegrator_[a-z0-9_]+\b")
#: Names the rules file defines for itself. Matched even when commented out:
#: the retention recording rule ships commented BY DESIGN — it is the one
#: threshold this fleet refuses to invent — and its alert must still be
#: readable as "waiting for a value" rather than as "references nothing".
_RECORDED = re.compile(r"#?\s*-\s*record:\s*(integrator_[a-z0-9_]+)")


def test_the_rules_file_is_present_and_was_actually_read() -> None:
    """Without this, every check below passes over an empty string."""
    assert RULES.is_file(), RULES
    text = RULES.read_text(encoding="utf-8")
    assert len(_METRIC.findall(text)) > 20, "the scan found almost no metrics"


def _declared() -> set[str]:
    text = RULES.read_text(encoding="utf-8")
    return {family.name for family in telemetry.FAMILIES} | set(_RECORDED.findall(text))


def test_every_metric_an_alert_names_is_a_declared_family() -> None:
    declared = _declared()
    referenced = set(_METRIC.findall(RULES.read_text(encoding="utf-8")))
    # Alert NAMES are `IntegratorX`, never `integrator_x`, so nothing in the
    # referenced set is an alert name rather than a metric.
    orphans = sorted(referenced - declared)
    assert not orphans, (
        f"these alerts fire on metrics nothing publishes: {orphans}. An alert "
        "whose right-hand side has no data never fires and never says so — it "
        "reads as a quiet system"
    )


@pytest.mark.parametrize(
    ("label", "vocabulary"),
    [
        ("code", telemetry.INGRESS_CODES),
        ("acceptance", telemetry.PRODUCT_ACCEPTANCES),
        ("outcome", telemetry.SIGNATURE_OUTCOMES + telemetry.CHALLENGE_OUTCOMES),
        ("reason", telemetry.REFUSAL_REASONS),
        ("state", telemetry.DELIVERY_STATES + telemetry.RECEIPT_STATES),
    ],
)
def test_every_label_value_an_alert_selects_on_is_declared(
    label: str, vocabulary: tuple[str, ...]
) -> None:
    """The same drift one level down, and the one that actually bit.

    A `{code="…"}` selector naming a value the counter can never hold is an
    alert that cannot fire, indistinguishable from one that has nothing to fire
    about. Regex-selector alternations (`code=~"a|b"`) are split and each half
    checked, because a single wrong alternative is silently dropped by
    Prometheus rather than reported.
    """
    # COMMENT lines are skipped, and only for this check. A comment is prose —
    # the note above `IntegratorUnknownEndpoint` quotes the retired selector on
    # purpose, to record what went wrong — and prose that mentions a dead label
    # is documentation rather than an alert that cannot fire. The metric-NAME
    # check above deliberately does not skip them, because the retention
    # recording rule ships commented out and its alert must still resolve.
    live = "\n".join(
        line
        for line in RULES.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )
    pattern = re.compile(rf'{label}=~?"([^"]+)"')
    for match in pattern.findall(live):
        for value in match.split("|"):
            assert value in vocabulary, (
                f'{label}="{value}" is selected by an alert but is not a '
                f"declared value ({sorted(vocabulary)}). This is the exact "
                "drift that left IntegratorUnknownTargetRefusals green through "
                "every unrouted delivery"
            )


def test_the_orphan_detector_bites() -> None:
    """Sensitivity proof (ADR-0018). A check over a set that happens to be
    empty passes for the wrong reason, and so does one whose regex matches
    nothing."""
    declared = _declared()
    # The name the vocabulary change retired. It must NOT be declared, or the
    # test above would pass even if the stale alert had been left in place.
    assert "unknown_target" not in telemetry.REFUSAL_REASONS
    assert "integrator_ingress_refusals_totals" not in declared  # typo'd name
    invented = set(_METRIC.findall("expr: integrator_a_metric_nobody_publishes > 0"))
    assert invented and not (invented & declared)
