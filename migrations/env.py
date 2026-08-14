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
from sqlalchemy import engine_from_config, pool

from dotmac_integrator.lineage import version_locations_setting

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("version_locations", version_locations_setting())

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
