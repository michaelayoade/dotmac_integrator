"""Health and readiness. Reporting only — never a decision.

`health_report` is the MODULE's function. This file adds the two things a
deployment knows and a module cannot: whether the process can reach its
database, and what it was composed from. It computes nothing about connector
health itself; doing so would put a second opinion beside the module's, and two
answers to "is this connector healthy" is exactly the parallel authority
ADR-0024 forbids.
"""

from __future__ import annotations

from typing import Any

import dotmac_integration
import dotmac_kernel
from sqlalchemy import text
from sqlalchemy.engine import Engine


def composition() -> dict[str, str]:
    """What this process is actually running.

    Read from the installed distributions rather than from the pins in
    `pyproject.toml`: the pin is what was requested, this is what is loaded, and
    the whole point of reporting it is to catch the case where they differ.
    """
    return {
        "dotmac_kernel": dotmac_kernel.__version__,
        "dotmac_integration": dotmac_integration.__version__,
        "schema": dotmac_integration.SCHEMA,
    }


def liveness() -> dict[str, Any]:
    """Is the process up. Touches nothing external, deliberately — a liveness
    probe that queries the database restarts a healthy process during a database
    blip, turning a recoverable outage into a crash loop."""
    return {"status": "alive"}


def readiness(engine: Engine) -> tuple[bool, dict[str, Any]]:
    """Can this process serve: database reachable, schema present.

    Returns the verdict alongside the detail so the caller owns the status code.
    A readiness probe that raises gives the orchestrator a 500 with no body,
    which reads as a crash rather than as "not ready yet".
    """
    detail: dict[str, Any] = {"composition": composition()}
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            present = conn.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.schemata "
                    "WHERE schema_name = :s)"
                ),
                {"s": dotmac_integration.SCHEMA},
            ).scalar_one()
    except Exception as exc:  # noqa: BLE001 — the reason is the payload
        detail["database"] = "unreachable"
        detail["error"] = type(exc).__name__
        return False, detail

    detail["database"] = "reachable"
    detail["schema_present"] = bool(present)
    if not present:
        # Migrations are a deploy step, never a boot step. An unmigrated
        # database is "not ready", not "start and create it".
        detail["hint"] = (
            f"schema {dotmac_integration.SCHEMA} is absent — run "
            "`alembic upgrade head` as the owner role"
        )
    return bool(present), detail
