"""Configuration. One of the four things this assembly is allowed to own.

Every value is an overridable knob with a documented default, and nothing here
is a business decision — a business decision would be something like "how many
times may a delivery be retried", which belongs to
`dotmac_integration.ExecutionPolicy` and is deliberately absent.

The line to hold: this file may say WHERE the database is and HOW MANY worker
threads to run. It may not say what a connector is allowed to do.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="forbid"
    )

    # ── Identity ────────────────────────────────────────────────────────────
    deployment_id: str = Field(
        default="integrator-local",
        description="Names this deployment in logs and operational output.",
    )
    environment: str = Field(
        default="development",
        description="Free-form; 'production' switches on the fatal checks below.",
    )

    # ── Database ────────────────────────────────────────────────────────────
    # The ONLINE role. It is the platform role, not a tenant role: every table
    # this deployment owns is platform-plane (ADR-0023), and `app_user` is
    # REVOKEd from all of them. Pointing this at a tenant role produces a
    # permission error on the first query, which is the contract working.
    database_url: str = Field(
        default="postgresql+psycopg://platform_api@localhost:5432/integrator",
        description="Runtime DSN. Must be the PLATFORM role, never app_user.",
    )
    # Migrations run as the owner, never as the online role, and never on boot.
    migration_database_url: str = Field(
        default="postgresql+psycopg://app_admin@localhost:5432/integrator",
        description="Owner DSN used only by `alembic upgrade`, never at runtime.",
    )
    db_pool_size: int = Field(default=5, ge=1)
    db_pool_max_overflow: int = Field(default=5, ge=0)

    # ── HTTP surface ────────────────────────────────────────────────────────
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8080, ge=1, le=65535)

    # ── Worker ──────────────────────────────────────────────────────────────
    worker_enabled: bool = Field(
        default=True,
        description="Run the in-process pump. False for an API-only replica.",
    )
    worker_poll_seconds: float = Field(default=5.0, gt=0)
    worker_lease_sweep_seconds: float = Field(default=60.0, gt=0)
    worker_batch_size: int = Field(default=20, ge=1)

    # ── Held secret material (ADR-0009) ─────────────────────────────────────
    # WHICH mechanisms may be dereferenced, and WHERE each is confined. Not
    # what any secret is, and not which secrets exist — that list is the
    # `secret_refs` already stored in the module's configuration revisions.
    secret_schemes: str = Field(
        default="env,file",
        description=(
            "Comma-separated reference schemes this deployment can dereference "
            "at startup. Only 'env' and 'file' are implemented; enabling any "
            "other is refused at boot."
        ),
    )
    secret_env_prefix: str = Field(
        default="INTEGRATOR_SECRET_",
        min_length=1,
        description=(
            "`env://NAME` is refused unless NAME starts with this. A "
            "configuration revision is operator-written data and must not be "
            "able to name DATABASE_URL."
        ),
    )
    secret_file_root: str = Field(
        default="/run/secrets",
        min_length=1,
        description="`file://` references are confined to this directory.",
    )

    # ── Operator authentication ─────────────────────────────────────────────
    operator_auth_mechanism: str = Field(
        default="platform_admin",
        description=(
            "How an operator proves identity on /operations/**. "
            "'platform_admin' is the kernel's platform bearer token, adapted — "
            "it is the only implemented mechanism and it is what supplies the "
            "actor_admin_id every audit row needs."
        ),
    )
    # ── Kernel-owned knobs, MIRRORED so they can be validated and documented ─
    # The kernel reads these from the environment itself
    # (`dotmac_kernel.config.settings`); nothing here re-reads them for the
    # kernel. They are declared for two reasons: this model is `extra="forbid"`,
    # so a `.env` carrying them would otherwise fail to parse; and a loopback
    # platform host or a default signing secret in production must be fatal
    # here, where the prod-fatal list lives.
    platform_root_domain: str = Field(
        default="localhost",
        description=(
            "Host the operator surface authenticates on. KERNEL knob "
            "(PLATFORM_ROOT_DOMAIN) — mirrored for validation only."
        ),
    )
    jwt_secret: str = Field(
        default="dev-insecure-change-me",
        description=(
            "Signing secret for operator bearer tokens. KERNEL knob "
            "(JWT_SECRET) — mirrored for validation only. Never logged."
        ),
    )


#: The one implemented operator-auth mechanism. A registry rather than an enum
#: so a deployment naming an unimplemented one gets a refusal listing what
#: exists — and so adding OIDC later is a new entry, not a new branch scattered
#: through the guard (ADR-0008's shape).
OPERATOR_AUTH_MECHANISMS: tuple[str, ...] = ("platform_admin",)


def validate_settings(settings: Settings) -> list[str]:
    """Configuration checks. Everything unconditional first, prod-fatal after.

    Returned rather than raised so the caller decides — a CLI wants to print all
    of them, a boot wants to refuse on the first. Empty means acceptable.
    """
    problems: list[str] = []

    # Unconditional: a deployment whose operator surface has no working auth
    # mechanism is not a development convenience, it is an open control plane.
    if settings.operator_auth_mechanism not in OPERATOR_AUTH_MECHANISMS:
        problems.append(
            f"OPERATOR_AUTH_MECHANISM={settings.operator_auth_mechanism!r} is "
            f"not implemented; known: {list(OPERATOR_AUTH_MECHANISMS)}. There "
            "is deliberately no 'none' — an unauthenticated /operations "
            "surface can replay deliveries and enable connectors"
        )

    if settings.environment != "production":
        return problems

    if settings.deployment_id == "integrator-local":
        problems.append("DEPLOYMENT_ID is still the local default")
    if "localhost" in settings.database_url:
        problems.append("DATABASE_URL still points at localhost")
    if "@localhost" in settings.migration_database_url:
        problems.append("MIGRATION_DATABASE_URL still points at localhost")
    if settings.host == "127.0.0.1":
        problems.append(
            "HOST is loopback; a production replica behind a proxy must bind "
            "the interface the proxy reaches"
        )
    if settings.platform_root_domain.lower() in {"localhost", ""}:
        problems.append(
            "PLATFORM_ROOT_DOMAIN is still 'localhost'; the operator surface "
            "authenticates host-exact, so every operator request would be "
            "rejected — or, worse, accepted only from whatever sends that Host "
            "header"
        )
    if settings.jwt_secret == "dev-insecure-change-me":
        # Named, never printed. This branch compares; it does not log.
        problems.append(
            "JWT_SECRET is still the kernel's development default; operator "
            "bearer tokens would be forgeable by anyone who has read the kernel"
        )
    if settings.secret_file_root.startswith("/tmp"):  # noqa: S108
        problems.append(
            "SECRET_FILE_ROOT is under /tmp, which is world-writable on most "
            "hosts; mount secret material somewhere only this process can read"
        )
    return problems


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
