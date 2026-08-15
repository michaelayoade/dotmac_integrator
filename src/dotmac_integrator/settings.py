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

    # ── Observability ───────────────────────────────────────────────────────
    # The scrape endpoint is a knob, not a constant: a deployment that exports
    # through a sidecar, or one whose ingress cannot be trusted to keep
    # `/metrics` internal, turns it off without a code change.
    #
    # Note what is NOT here: the payload-retention period and the legal-policy
    # owner. Those belong to `dotmac_integration.RetentionPolicy` and are
    # Michael's decisions; an alert threshold that encoded a period would fork
    # the policy between this process and the module that enforces it. The
    # threshold lives in `deploy/alerts/ingress.rules.yml`, unset, waiting for
    # that decision.
    metrics_enabled: bool = Field(
        default=True,
        description="Expose GET /metrics in the Prometheus text format.",
    )
    metrics_path: str = Field(
        default="/metrics",
        description="Where the scrape endpoint is mounted.",
    )
    # The fleet's observability auth standard: `Authorization: Bearer
    # METRICS_TOKEN`, compared in constant time, and unauthorized answered with
    # 404 rather than 403 so the endpoint is indistinguishable from absent —
    # a 403 is an oracle telling a prober the path exists.
    #
    # Unset fails CLOSED to loopback only. A world-readable /metrics is how a
    # queue depth, a dead-letter count and an installation's operational shape
    # leave the perimeter; that this deployment's labels carry no identifier is
    # a second line of defence, not a reason to skip the first.
    metrics_token: str | None = Field(
        default=None,
        description=(
            "Bearer token for GET /metrics. Unset restricts the endpoint to "
            "loopback. Value comes from the environment; never committed."
        ),
    )


def validate_settings(settings: Settings) -> list[str]:
    """Prod-fatal checks.

    Returned rather than raised so the caller decides — a CLI wants to print all
    of them, a boot wants to refuse on the first. Empty means acceptable.
    """
    if settings.environment != "production":
        return []

    problems: list[str] = []
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
    if settings.metrics_enabled and not settings.metrics_token:
        # Fatal rather than degraded-to-loopback. A production replica binds a
        # routable interface (checked above), so "loopback only" is not a
        # fallback there — it is an endpoint nobody can scrape sitting on a
        # port anybody can reach.
        problems.append(
            "METRICS_ENABLED is on with no METRICS_TOKEN. Set the token, or "
            "set METRICS_ENABLED=false — an unauthenticated /metrics on a "
            "routable interface publishes this deployment's operational shape"
        )
    return problems


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
