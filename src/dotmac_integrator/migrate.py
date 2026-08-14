"""The migration entry point. `python -m dotmac_integrator.migrate upgrade heads`.

## Why the `alembic` CLI is not used directly

Alembic builds its `ScriptDirectory` from the config **before** running
`env.py`. So `config.set_main_option("version_locations", ...)` inside `env.py`
is always too late: the revision set has already been resolved, from an
`alembic.ini` that cannot name a path inside site-packages.

The failure mode is the worst kind. Alembic finds no revisions, has nothing to
do, and **exits 0**. `make migrate` reports success against a database with no
tables, and the first symptom is the application failing every query.

This module therefore constructs the `Config` itself, sets `version_locations`
from the installed distributions (see `lineage.py`), and only then invokes the
command — which is the same shape `vendor_cp` uses for the same reason.

## `heads`, plural

Two independent lineages with distinct branch labels are composed here. `head`
upgrades ONE branch and reports success, leaving the other unapplied. Every
Dotmac deployment uses `heads`; the default here is `heads` so the safe form is
the one you get by not thinking about it.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config

from dotmac_integrator.lineage import version_locations_setting

REPO_ROOT = Path(__file__).resolve().parents[2]


def build_config(database_url: str | None = None) -> Config:
    """An Alembic config with the composed lineages already resolved."""
    ini = REPO_ROOT / "alembic.ini"
    config = Config(str(ini)) if ini.exists() else Config()
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("version_locations", version_locations_setting())

    url = database_url or os.getenv("MIGRATION_DATABASE_URL")
    if not url:
        raise SystemExit(
            "MIGRATION_DATABASE_URL is unset. Migrations run as the OWNER role; "
            "there is deliberately no fallback to DATABASE_URL, which is the "
            "online platform role and cannot create a table."
        )
    config.set_main_option("sqlalchemy.url", url)
    return config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dotmac_integrator.migrate")
    parser.add_argument("action", choices=["upgrade", "downgrade", "current", "heads"])
    parser.add_argument(
        "revision",
        nargs="?",
        default="heads",
        help="default 'heads' — plural, because two lineages are composed",
    )
    args = parser.parse_args(argv)

    config = build_config()
    locations = config.get_main_option("version_locations") or ""
    if not locations.strip():
        # Refuse rather than no-op. This is the condition that made the CLI
        # silently succeed against an empty database.
        raise SystemExit("no version_locations resolved — refusing to run")

    if args.action == "upgrade":
        command.upgrade(config, args.revision)
    elif args.action == "downgrade":
        command.downgrade(config, args.revision)
    elif args.action == "current":
        command.current(config, verbose=True)
    else:
        command.heads(config, verbose=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
