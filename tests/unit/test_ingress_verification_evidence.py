"""The assembly observes provider-neutral verification evidence from SPI 1.2."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import dotmac_integration as integration
import pytest
from sqlalchemy import create_engine

from dotmac_integrator import ingress, telemetry


class _Counters:
    def __init__(self) -> None:
        self.verifications: list[integration.VerificationResult] = []
        self.outcomes: list[str] = []

    def record_verification(self, result: integration.VerificationResult) -> None:
        self.verifications.append(result)

    def record_ingress_outcome(self, code: str) -> None:
        self.outcomes.append(code)

    def record_challenge(self, outcome: str) -> None:
        del outcome


def test_delivery_passes_the_module_its_provider_neutral_observer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counters = _Counters()
    evidence = integration.VerificationResult(
        accepted=True,
        matched_secret_positions=(0, 1),
    )

    def fake_receive(*args: Any, **kwargs: Any) -> Any:
        del args
        observer = kwargs.get("observe_verification")
        assert observer is not None, "the assembly discarded SPI 1.2 evidence"
        observer(evidence)
        return SimpleNamespace(code=integration.IngressCode.ACCEPTED)

    monkeypatch.setattr(telemetry, "counters", counters)
    monkeypatch.setattr(integration, "receive", fake_receive)
    monkeypatch.setattr(integration, "discover", lambda: object())

    engine = create_engine("sqlite://")
    try:
        outcome = ingress.receive_delivery(
            engine,
            endpoint=object(),
            request=object(),
        )
    finally:
        engine.dispose()

    assert outcome.code is integration.IngressCode.ACCEPTED
    assert counters.verifications == [evidence]
    assert counters.outcomes == ["accepted"]
