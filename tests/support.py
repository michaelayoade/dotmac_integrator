"""Shared fixtures for the no-database tests.

The engine is constructed but never connected — `create_engine` is lazy, and
every test in `tests/unit` is about a decision made before a query would be
issued. Anything needing a real database belongs in `tests/composition`.
"""

from __future__ import annotations

from typing import Any

from dotmac_integrator.settings import Settings

#: A DSN that parses and is never dialled. Pointing it at a real host would
#: make a guard regression show up as a connection error instead of a 200.
UNREACHABLE_DSN = "postgresql+psycopg://platform_api@127.0.0.1:1/integrator_test"


def build_settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "environment": "test",
        "deployment_id": "integrator-test",
        "database_url": UNREACHABLE_DSN,
        "migration_database_url": UNREACHABLE_DSN,
        "worker_enabled": False,
    }
    return Settings(**{**base, **overrides})
