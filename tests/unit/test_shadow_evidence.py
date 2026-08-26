"""Shadow comparisons become durable evidence, never receipt state.

The destination's mirror port is deliberately read-only.  That makes a
comparison safe, but the old worker only logged aggregate counts and then read
the same receipts again on every poll.  These tests specify the missing
control-plane behaviour: one privacy-safe observation per receipt and
comparison revision, bounded retries for transient verdicts, and a unique
population report that cannot call an empty sample clean.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from dotmac_integrator.product_port import MirrorVerdict
from dotmac_integrator.shadow_evidence import (
    SafeShadowVerdict,
    ShadowObservation,
    normalize_verdict,
    should_compare,
    summarize,
)

REVISION = "image-sha256:comparison-v1"
RECEIPT_A = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
RECEIPT_B = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
EVENT_A = UUID("11111111-1111-4111-8111-111111111111")
EVENT_B = UUID("22222222-2222-4222-8222-222222222222")
EVENT_C = UUID("33333333-3333-4333-8333-333333333333")
NOW = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)


def _observation(
    *,
    receipt_id: UUID = RECEIPT_A,
    event_id: UUID = EVENT_A,
    verdict: str = "agrees",
    at: datetime = NOW,
    reasons: tuple[str, ...] = (),
    fields: tuple[str, ...] = (),
    revision: str = REVISION,
) -> ShadowObservation:
    return ShadowObservation(
        event_id=event_id,
        receipt_id=receipt_id,
        comparison_revision=revision,
        verdict=verdict,
        blocking_reasons=reasons,
        disagreeing_fields=fields,
        observed_at=at,
    )


def test_a_destination_verdict_is_reduced_to_safe_codes_only() -> None:
    safe = normalize_verdict(
        MirrorVerdict(
            verdict="field_disagreement",
            agrees=False,
            blocking_reasons=("normalized_field_disagreement",),
            disagreeing_fields=("normalized_payload.text",),
        )
    )

    assert safe.verdict == "field_disagreement"
    assert safe.blocking_reasons == ("normalized_field_disagreement",)
    assert safe.disagreeing_fields == ("normalized_payload.text",)


def test_unrecognised_destination_text_cannot_reach_the_audit_ledger() -> None:
    material = "token-value-that-must-never-be-persisted"
    safe = normalize_verdict(
        MirrorVerdict(
            verdict=material,
            agrees=False,
            blocking_reasons=(material,),
            disagreeing_fields=(material,),
        )
    )

    assert safe.verdict == "unrecognized"
    assert safe.blocking_reasons == ("unrecognized_comparison_report",)
    assert safe.disagreeing_fields == ()
    assert material not in repr(safe)


def test_the_durable_value_refuses_unsafe_construction_too() -> None:
    material = "token-value-that-must-never-be-persisted"

    with pytest.raises(ValueError) as refused:
        SafeShadowVerdict(
            verdict=material,
            blocking_reasons=(material,),
            disagreeing_fields=(material,),
        )
    assert material not in str(refused.value)


def test_an_inconsistent_agrees_flag_is_a_blocker_not_false_reassurance() -> None:
    safe = normalize_verdict(
        MirrorVerdict(verdict="agrees", agrees=False, blocking_reasons=())
    )

    assert safe.verdict == "unrecognized"
    assert safe.blocking_reasons == ("unrecognized_comparison_report",)


def test_terminal_evidence_is_not_repeated_in_one_revision() -> None:
    latest = _observation(verdict="agrees")

    assert (
        should_compare(
            latest,
            comparison_revision=REVISION,
            retry_after=timedelta(minutes=5),
            now=NOW + timedelta(days=1),
        )
        is False
    )


def test_transient_evidence_retries_only_after_the_configured_interval() -> None:
    latest = _observation(
        verdict="no_counterpart",
        reasons=("no_counterpart_observation",),
    )

    assert (
        should_compare(
            latest,
            comparison_revision=REVISION,
            retry_after=timedelta(minutes=5),
            now=NOW + timedelta(minutes=4, seconds=59),
        )
        is False
    )
    assert (
        should_compare(
            latest,
            comparison_revision=REVISION,
            retry_after=timedelta(minutes=5),
            now=NOW + timedelta(minutes=5),
        )
        is True
    )


def test_a_new_comparison_revision_re_drives_every_receipt() -> None:
    assert should_compare(
        _observation(verdict="collision", reasons=("domain_fingerprint_collision",)),
        comparison_revision="image-sha256:comparison-v2",
        retry_after=timedelta(days=1),
        now=NOW,
    )


def test_the_report_counts_each_receipt_once_using_its_latest_observation() -> None:
    old = _observation(
        event_id=EVENT_A,
        verdict="no_counterpart",
        reasons=("no_counterpart_observation",),
        at=NOW,
    )
    repaired = _observation(
        event_id=EVENT_B,
        verdict="agrees",
        at=NOW + timedelta(minutes=5),
    )
    blocker = _observation(
        receipt_id=RECEIPT_B,
        event_id=EVENT_C,
        verdict="identity_shape_mismatch",
        reasons=("identity_shape_mismatch",),
        fields=("provider_event_id",),
        at=NOW + timedelta(minutes=2),
    )

    report = summarize((old, repaired, blocker), comparison_revision=REVISION)

    assert report.unique_receipts == 2
    assert report.agreeing == 1
    assert report.verdict_counts == {
        "agrees": 1,
        "identity_shape_mismatch": 1,
    }
    assert report.blocking_reason_counts == {"identity_shape_mismatch": 1}
    assert report.disagreeing_fields == {"provider_event_id": 1}
    assert report.first_observed_at == NOW
    assert report.last_observed_at == NOW + timedelta(minutes=5)
    assert report.sample_has_no_blockers is False


def test_an_empty_population_is_never_reported_as_blocker_free() -> None:
    report = summarize((), comparison_revision=REVISION)

    assert report.unique_receipts == 0
    assert report.sample_has_no_blockers is False
    assert report.first_observed_at is None
    assert report.last_observed_at is None


def test_the_operator_report_contains_counts_not_receipt_identifiers() -> None:
    report = summarize((_observation(),), comparison_revision=REVISION).as_dict()
    rendered = repr(report)

    assert report["unique_receipts"] == 1
    assert str(RECEIPT_A) not in rendered
    assert str(EVENT_A) not in rendered
