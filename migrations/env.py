"""Alembic entry point. The one place DDL is legitimate.

`version_locations` is composed PROGRAMMATICALLY rather than written into
`alembic.ini`, because this deployment installs wheels: there is no `packages/`
directory to point at, and hardcoding a site-packages path would break on any
machine whose layout differs — including the container this actually runs in.

## Run as the owner, never on boot

The DSN comes from `MIGRATION_DATABASE_URL` (the owner role), not
`DATABASE_URL` (the online platform role). The online role has row DML and
schema USAGE; it deliberately cannot create a table. Pointing this at it
produces a permission error, which is the privilege split working rather than a
misconfiguration to route around.

Nothing in `dotmac_integrator.assembly` imports this module. Migrations are a
deploy step.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from dotmac_kernel.prerequisites import install_prerequisite_bindings
from sqlalchemy import engine_from_config, pool

from dotmac_integrator.migration_bindings import ASSEMBLY_PREREQUISITE_BINDINGS

# Installed at IMPORT, which is still before the revision map exists: Alembic
# walks the version directories lazily, inside `run_migrations()`. A composed
# module lineage resolving its `depends_on` from these bindings therefore sees
# them, and an assembly composing a module whose requirements it never answered
# fails loudly rather than ordering wrongly. See `migration_bindings.py`.
#
# `migrate.py` additionally exports `DOTMAC_MIGRATION_BINDINGS`, because the
# commands that build a revision map WITHOUT running this file (`heads`,
# `history`, `show`) can be reached no other way.
install_prerequisite_bindings(ASSEMBLY_PREREQUISITE_BINDINGS)

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# NOT set here — by the time `env.py` runs, Alembic has already built its
# ScriptDirectory from the config, so setting it now changes nothing. That
# mistake made `alembic upgrade heads` exit 0 having applied NOTHING.
#
# `dotmac_integrator.migrate` sets it before invoking the command. Reaching this
# file with no locations resolved means the bare `alembic` CLI was used, so it
# refuses loudly rather than reporting success against an empty database.
if not (config.get_main_option("version_locations") or "").strip():
    raise RuntimeError(
        "no version_locations resolved. This deployment installs wheels, so the "
        "lineages cannot be named in alembic.ini — run migrations through "
        "`python -m dotmac_integrator.migrate upgrade heads` (or `make "
        "migrate`), never the bare `alembic` CLI."
    )

url = os.getenv("MIGRATION_DATABASE_URL")
if not url:
    raise RuntimeError(
        "MIGRATION_DATABASE_URL is unset. Migrations run as the OWNER role; "
        "there is deliberately no fallback to DATABASE_URL, which is the online "
        "platform role and cannot create a table."
    )
config.set_main_option("sqlalchemy.url", url)

# No `target_metadata`: this assembly owns no models. Every table belongs to a
# composed module's lineage, so autogenerate is not merely unused — it would
# propose dropping every table it can see.
target_metadata = None


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Module lineages are fully schema-qualified and each owns its own
        # `mod_<code>` schema, so the default `public` search path must not be
        # relied on to resolve anything.
        include_schemas=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
