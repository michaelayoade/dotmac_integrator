"""Machine authentication for the product query surface."""

from __future__ import annotations

from uuid import uuid4

import pytest

from dotmac_integrator.product_auth import (
    ProductAuthenticationFailed,
    ProductAuthenticator,
)
from dotmac_integrator.settings import ProductQueryCaller

REF = "file:///run/secrets/product-query/erp"
KEY = "erp-query-key-with-enough-entropy"
BINDING_ID = uuid4()


def _caller(*, scopes: tuple[str, ...] = ("integration:query",)) -> ProductQueryCaller:
    return ProductQueryCaller(
        application="dotmac_erp",
        api_key_ref=REF,
        scopes=scopes,
        binding_ids=(BINDING_ID,),
    )


def test_exact_held_key_authenticates_to_an_immutable_principal() -> None:
    authenticator = ProductAuthenticator((_caller(),), secret_lookup=lambda _: KEY)

    principal = authenticator.authenticate(KEY, required_scope="integration:query")

    assert principal.application == "dotmac_erp"
    assert principal.scopes == frozenset({"integration:query"})
    assert principal.binding_ids == frozenset({BINDING_ID})


@pytest.mark.parametrize("presented", ["", "wrong-key-with-enough-entropy"])
def test_missing_or_wrong_key_has_one_opaque_refusal(presented: str) -> None:
    authenticator = ProductAuthenticator((_caller(),), secret_lookup=lambda _: KEY)

    with pytest.raises(
        ProductAuthenticationFailed, match="authentication failed"
    ) as exc:
        authenticator.authenticate(presented, required_scope="integration:query")

    assert KEY not in str(exc.value)
    if presented:
        assert presented not in str(exc.value)


def test_a_valid_key_without_the_exact_scope_is_refused() -> None:
    authenticator = ProductAuthenticator(
        (_caller(scopes=("integration:observe",)),), secret_lookup=lambda _: KEY
    )

    with pytest.raises(ProductAuthenticationFailed, match="authentication failed"):
        authenticator.authenticate(KEY, required_scope="integration:query")


def test_an_unheld_reference_fails_closed_without_naming_material() -> None:
    authenticator = ProductAuthenticator((_caller(),), secret_lookup=lambda _: None)

    with pytest.raises(
        ProductAuthenticationFailed, match="authentication failed"
    ) as exc:
        authenticator.authenticate(KEY, required_scope="integration:query")

    assert KEY not in str(exc.value)


def test_held_keys_are_compared_with_the_constant_time_primitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compared: list[tuple[str, str]] = []

    def record_compare(presented: str, held: str) -> bool:
        compared.append((presented, held))
        return presented == held

    monkeypatch.setattr(
        "dotmac_integrator.product_auth.secrets.compare_digest", record_compare
    )
    authenticator = ProductAuthenticator((_caller(),), secret_lookup=lambda _: KEY)

    authenticator.authenticate(KEY, required_scope="integration:query")

    assert compared == [(KEY, KEY)]
