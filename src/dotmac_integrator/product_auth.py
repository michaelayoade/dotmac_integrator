"""Held-key authentication for product queries; no request-path I/O."""

from __future__ import annotations

import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Annotated, cast
from uuid import UUID

from dotmac_kernel.secret_sources import get_secret
from fastapi import Depends, Header, HTTPException, Request

from dotmac_integrator.settings import ProductQueryCaller


@dataclass(frozen=True, slots=True)
class ProductPrincipal:
    application: str
    scopes: frozenset[str]
    binding_ids: frozenset[UUID]


class ProductAuthenticationFailed(RuntimeError):
    """Opaque refusal for every authentication failure mode."""


class ProductAuthenticator:
    """Authenticate against material already held by the kernel."""

    def __init__(
        self,
        callers: Iterable[ProductQueryCaller],
        *,
        secret_lookup: Callable[[str], str | None] = get_secret,
    ) -> None:
        self._callers = tuple(callers)
        self._lookup = secret_lookup

    def authenticate(self, presented: str, *, required_scope: str) -> ProductPrincipal:
        matched: ProductQueryCaller | None = None
        for caller in self._callers:
            held = self._lookup(caller.api_key_ref)
            if held is not None and secrets.compare_digest(presented, held):
                matched = caller
        if matched is None or required_scope not in matched.scopes:
            raise ProductAuthenticationFailed("product authentication failed")
        return ProductPrincipal(
            matched.application,
            frozenset(matched.scopes),
            frozenset(matched.binding_ids),
        )


def require_product_query(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-Api-Key"),
) -> ProductPrincipal:
    authenticator = cast(
        ProductAuthenticator, request.app.state.product_query_authenticator
    )
    try:
        return authenticator.authenticate(
            x_api_key or "", required_scope="integration:query"
        )
    except ProductAuthenticationFailed as exc:
        raise HTTPException(401, "product authentication failed") from exc


ProductQueryPrincipal = Annotated[ProductPrincipal, Depends(require_product_query)]
