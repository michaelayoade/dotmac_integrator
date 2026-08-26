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

    # ── Public ingress ──────────────────────────────────────────────────────
    ingress_enabled: bool = Field(
        default=True,
        description=(
            "Mount GET/POST /ingress/{endpoint_key}. False for a replica that "
            "runs the worker and the operator surface but takes no provider "
            "traffic — the split a deployment makes when the ingress replicas "
            "sit in a different network zone from the operator ones."
        ),
    )
    # A GENERIC cap, and it has to be: a byte limit that varied by connector
    # would be connector-specific policy, which neither this assembly nor
    # `dotmac_integration` may hold (the module says so where it defines
    # `PayloadTooLarge` — "DEFINED here, RAISED at the edge", and no engine
    # function takes a max_bytes).
    #
    # 1 MiB comfortably holds a provider webhook batch. It is a knob because
    # the right number is a deployment's, and it is enforced AS THE BODY IS
    # READ rather than measured afterwards — see `ingress.read_capped_body`.
    ingress_max_body_bytes: int = Field(
        default=1_048_576,
        ge=1,
        description=(
            "Largest inbound provider body read, enforced while streaming and "
            "before any signature check. Refused as the module's own "
            "PayloadTooLarge (413)."
        ),
    )

    # ── Receipt → product delivery ──────────────────────────────────────────
    # WHERE recorded observations land, and with what credential. Everything
    # here is transport addressing; nothing here is a business decision. In
    # particular there is no retry count, no wait and no attempt limit —
    # `dotmac_integration.ExecutionPolicy` owns those and a knob here would be a
    # second answer.
    product_port_enabled: bool = Field(
        default=False,
        description=(
            "Install a client for the destination application at startup. OFF "
            "by default: a deployment with no destination configured must fail "
            "closed and say so, never deliver nowhere and mark receipts done."
        ),
    )
    product_port_mode: str = Field(
        default="mirror",
        description=(
            "'mirror' posts to the destination's SHADOW port, which records "
            "nothing and answers with a parity verdict; 'write' posts to the "
            "port that records. Defaults to the safe one — a deployment "
            "misconfigured into shadow produces evidence, one misconfigured "
            "into write records facts nobody agreed to record."
        ),
    )
    product_port_application: str = Field(
        default="",
        description=(
            "The destination application this client serves. Checked against "
            "the application the module resolved from the capability's declared "
            "owner; a mismatch is refused rather than delivered."
        ),
    )
    product_port_base_url: str = Field(
        default="",
        description="Scheme and host of the destination, e.g. https://sub.example.com",
    )
    product_port_api_path_prefix: str = Field(
        default="/api/v1",
        description=(
            "Path the destination mounts its API under. A knob because the "
            "router's own prefix and the mounted prefix differ, and the mounted "
            "one is what a client must use."
        ),
    )
    product_port_api_key_ref: str = Field(
        default="",
        description=(
            "Reference to the machine credential presented as X-Api-Key — "
            "`env://INTEGRATOR_SECRET_...` or `file:///run/secrets/...`. A "
            "REFERENCE, never a value: it is dereferenced once at startup and "
            "held (ADR-0009), and this file is committed."
        ),
    )
    product_port_bindings: str = Field(
        default="",
        description=(
            "`<local-binding-uuid>=<destination-binding-uuid>` pairs, comma "
            "separated. The destination's port is keyed on ITS OWN capability "
            "binding UUID, which lives in ITS database and is NOT derivable "
            "from this deployment's. Supplying it is an operator act; how the "
            "value gets here is an open decision recorded in the destination's "
            "cutover document."
        ),
    )
    product_port_capabilities: str = Field(
        default="",
        description=(
            "`<capability.id.vN> = <application>/<module> : <summary>` entries, "
            "`;` separated. The capability vocabulary this deployment routes "
            "by. A STOPGAP: a capability is declared by its owning business "
            "module, and how that declaration reaches this assembly is an open "
            "decision — the Integrator may never mint one, so it is transcribed "
            "here rather than defaulted."
        ),
    )
    product_port_timeout_seconds: float = Field(
        default=15.0,
        gt=0,
        description=(
            "How long one delivery call may take. A TRANSPORT bound, not a "
            "retry decision: it must stay comfortably inside the module's own "
            "receipt lease so a call cannot outlive the claim it was made under."
        ),
    )
    product_port_shadow_revision: str = Field(
        default="",
        max_length=200,
        description=(
            "Immutable image/contract revision whose mirror evidence is being "
            "collected. Required only in mirror mode: changing it deliberately "
            "re-drives the full receipt population after a deployment change."
        ),
    )
    product_port_shadow_retry_seconds: float = Field(
        default=300.0,
        gt=0,
        description=(
            "Minimum wait before re-checking transient shadow verdicts. This "
            "bounds evidence sampling; it is not the module's delivery retry "
            "policy and never changes a receipt attempt."
        ),
    )

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


#: The one implemented operator-auth mechanism. A registry rather than an enum
#: so a deployment naming an unimplemented one gets a refusal listing what
#: exists — and so adding OIDC later is a new entry, not a new branch scattered
#: through the guard (ADR-0008's shape).
OPERATOR_AUTH_MECHANISMS: tuple[str, ...] = ("platform_admin",)

#: The two ports the destination exposes. A registry rather than a free string
#: so a typo is a refused boot naming both, instead of a deployment that quietly
#: matched neither branch — and the shadow one stays a first-class mode rather
#: than "write, but don't".
PRODUCT_PORT_MODES: tuple[str, ...] = ("mirror", "write")


def _product_port_problems(settings: Settings) -> list[str]:
    """Everything a configured destination must have before the port is built.

    Checked here rather than at the first delivery. A half-configured port that
    starts and fails per receipt burns an attempt on each one and reports it as
    a product problem; refusing at boot names the missing knob while somebody is
    watching.
    """
    if settings.product_port_mode not in PRODUCT_PORT_MODES:
        return [
            f"PRODUCT_PORT_MODE={settings.product_port_mode!r} is not one of "
            f"{list(PRODUCT_PORT_MODES)}. 'mirror' records nothing and produces "
            "parity evidence; 'write' records"
        ]
    if not settings.product_port_enabled:
        return []

    problems: list[str] = []
    required = {
        "PRODUCT_PORT_APPLICATION": settings.product_port_application,
        "PRODUCT_PORT_BASE_URL": settings.product_port_base_url,
        "PRODUCT_PORT_API_KEY_REF": settings.product_port_api_key_ref,
        "PRODUCT_PORT_BINDINGS": settings.product_port_bindings,
        "PRODUCT_PORT_CAPABILITIES": settings.product_port_capabilities,
    }
    for name, value in required.items():
        if not value.strip():
            problems.append(
                f"PRODUCT_PORT_ENABLED is on and {name} is empty; a port that "
                "cannot address the destination would fail every receipt"
            )
    if settings.product_port_mode == "mirror":
        revision = settings.product_port_shadow_revision
        if not revision.strip():
            problems.append(
                "PRODUCT_PORT_SHADOW_REVISION is required in mirror mode; "
                "without a deployment revision evidence from different code "
                "cannot be separated and a fixed comparison cannot re-drive"
            )
        elif revision != revision.strip():
            problems.append(
                "PRODUCT_PORT_SHADOW_REVISION must not have leading or trailing "
                "whitespace"
            )
    reference = settings.product_port_api_key_ref.strip()
    if reference and not reference.startswith(("env://", "file://")):
        problems.append(
            "PRODUCT_PORT_API_KEY_REF must be an `env://` or `file://` "
            "reference. It is dereferenced once at startup and held; a literal "
            "credential here would sit in a committed file and in the process "
            "environment of everything that reads this configuration"
        )
    return problems


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

    problems.extend(_product_port_problems(settings))

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
    if settings.product_port_enabled and settings.product_port_base_url.startswith(
        "http://"
    ):
        # The envelope carries a customer's message body and the request carries
        # the machine credential. Over plaintext both are readable by every hop,
        # and the credential is replayable afterwards.
        problems.append(
            "PRODUCT_PORT_BASE_URL is http://; the observation envelope carries "
            "message content and the request carries the destination "
            "credential, neither of which may cross a production network in "
            "the clear"
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
