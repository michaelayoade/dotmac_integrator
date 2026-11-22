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
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

#: The owner DSN's default. Named because `validate_settings` has to tell "still
#: the default, because this process deliberately has none" apart from "set, and
#: set to localhost" — the api and worker are given no MIGRATION_DATABASE_URL at
#: all, and refusing to start them over a value they were never meant to hold
#: would force the owner credential into the two processes that must not have it.
_DEFAULT_MIGRATION_DATABASE_URL = (
    "postgresql+psycopg://app_admin@localhost:5432/integrator"
)


#: The scope of the one scoped product-management caller per companion (D12a).
#: It is never an operator and holds no other scope.
MANAGE_SCOPE = "integration:manage"

#: Words that make a configuration key a DESTINATION key. The management caller
#: may never set one (PLAN §1d: a compromised product repointing the
#: destination would get held credentials presented to an attacker). Matched on
#: whole words after splitting on `_`, `-`, `.` and camelCase, so
#: `from_address` is a sender label while `smtp_host` and `serverUrl` are not.
EGRESS_KEY_WORDS: frozenset[str] = frozenset(
    {
        "host",
        "hostname",
        "port",
        "user",
        "username",
        "login",
        "tls",
        "ssl",
        "starttls",
        "url",
        "uri",
        "endpoint",
        "server",
        "relay",
        "proxy",
        "dsn",
        "domain",
        "ip",
        "network",
        "target",
        "targets",
        "auth",
        "password",
        "secret",
        "token",
        # TLS trust: a key that weakens or redirects certificate checking lets a
        # network attacker capture the credential without changing the host.
        "verify",
        "verification",
        "cert",
        "certs",
        "certificate",
        "certificates",
        "ca",
        "cacert",
        "insecure",
        "trust",
        "truststore",
        "security",
        "secure",
        "mx",
        "smarthost",
        "timeout",
        "fingerprint",
        "pin",
        "pem",
        "key",
        "cipher",
        "ciphers",
        "protocol",
    }
)


#: Keys refused by EXACT name (case-insensitive), not as words. `address` is the
#: SMTP connector's pinned /32 egress address, while `from_address` and
#: `reply_to_address` are sender labels that stay manageable (F-2).
EGRESS_KEY_EXACT: frozenset[str] = frozenset({"address"})


def config_key_is_egress(key: str) -> bool:
    """True when `key` names a destination, a credential or a network target."""
    if key.strip().lower() in EGRESS_KEY_EXACT:
        return True
    spaced = (
        "".join(f" {c.lower()}" if c.isupper() else c for c in key)
        .replace("_", " ")
        .replace("-", " ")
        .replace(".", " ")
    )
    return bool(set(spaced.split()) & EGRESS_KEY_WORDS)


class ManageGrant(BaseModel):
    """One structured allowlist entry for an `integration:manage` caller.

    Everything a manage caller may touch is named by a grant and arrives ONLY
    from typed settings; nothing is defaulted in code and no connector key is
    written in source. A structured entry rather than flat lists, so a later
    (data set, direction) dimension can be added as new optional fields without
    breaking configurations written today (`extra="forbid"` makes an unknown
    field a refused boot, never an ignored one).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    installation_id: UUID
    connector_key: str = Field(min_length=1)
    #: The bindings of that installation the caller may disable and enable.
    binding_ids: tuple[UUID, ...] = ()
    #: The non-egress configuration keys the caller may set.
    config_keys: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _no_egress_keys(self) -> ManageGrant:
        egress = sorted(k for k in self.config_keys if config_key_is_egress(k))
        if egress:
            raise ValueError(
                "config_keys may not name a destination, credential or "
                f"network key: {egress}"
            )
        return self


#: Outbound dispatch scope. A caller holding it is bound to exactly ONE binding.
DISPATCH_SCOPE = "integration:dispatch"


class ProductQueryCaller(BaseModel):
    """Non-secret caller identity, held-key reference and granted scopes.

    A caller holding `integration:manage` (D12a) is a different kind of
    principal: it holds that scope ALONE and is confined to its `manage_grants`.
    An empty `manage_grants` means it can do nothing. A caller without the
    manage scope may carry no grants, so they can never be silently ignored.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    application: str = Field(min_length=1, pattern=r"^[a-z0-9_.-]+$")
    api_key_ref: str = Field(min_length=1)
    scopes: tuple[str, ...] = Field(min_length=1)
    binding_ids: tuple[UUID, ...] = ()
    manage_grants: tuple[ManageGrant, ...] = ()

    @model_validator(mode="after")
    def _scope_shape(self) -> ProductQueryCaller:
        if MANAGE_SCOPE not in self.scopes:
            if self.manage_grants:
                raise ValueError(
                    f"manage_grants are valid only with the {MANAGE_SCOPE} scope"
                )
            if not self.binding_ids:
                raise ValueError("binding_ids requires at least one binding")
            return self
        if set(self.scopes) != {MANAGE_SCOPE}:
            raise ValueError(
                f"{MANAGE_SCOPE} must be the caller's only scope; use a "
                "separate caller (and key) for any other scope"
            )
        if self.binding_ids:
            raise ValueError(
                f"a {MANAGE_SCOPE} caller names bindings inside manage_grants"
            )
        installations = [g.installation_id for g in self.manage_grants]
        if len(set(installations)) != len(installations):
            raise ValueError("manage_grants name an installation more than once")
        return self

    @model_validator(mode="after")
    def _dispatch_is_one_binding(self) -> ProductQueryCaller:
        if DISPATCH_SCOPE in self.scopes:
            if len(set(self.binding_ids)) != 1:
                raise ValueError(f"{DISPATCH_SCOPE} is bound to exactly one binding id")
            if set(self.scopes) != {DISPATCH_SCOPE}:
                raise ValueError(f"{DISPATCH_SCOPE} must be the caller's only scope")
        return self


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
        default=_DEFAULT_MIGRATION_DATABASE_URL,
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
    worker_poll_seconds: float = Field(
        default=5.0,
        gt=0,
        description=(
            "Wake cadence for connector polling and receipt delivery. The "
            "module still owns retry eligibility and backoff."
        ),
    )
    worker_lease_sweep_seconds: float = Field(default=60.0, gt=0)
    worker_provision_seconds: float = Field(
        default=5.0,
        gt=0,
        description=(
            "Wake cadence for the provisioning pump. Separate from polling "
            "and delivery on purpose: a stuck fleet target must not delay "
            "receipts, and a slow poll must not delay a disconnect."
        ),
    )
    worker_batch_size: int = Field(
        default=20,
        ge=1,
        description=(
            "Maximum jobs or receipts attempted per worker pass. This is a "
            "scheduler bound, not an attempt or retry limit; the module "
            "refuses a poll page above its own absolute bound."
        ),
    )

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
    product_manage_enabled: bool = Field(
        default=False,
        description=(
            "Mount the integration:manage routes under /product/v1/manage. "
            "Needs a caller holding exactly that scope. Off by default."
        ),
    )
    # ── Outbound dispatch (B5). Every switch defaults OFF. ───────────────────
    product_dispatch_enabled: bool = Field(
        default=False,
        description=(
            "Mount POST /product/v1/dispatches for callers holding "
            "integration:dispatch, each bound to exactly one binding id."
        ),
    )
    outbound_pump_enabled: bool = Field(
        default=False,
        description=(
            "Run the outbound delivery pump (prepare, invoke, settle) and treat "
            "an expired outbound lease as AMBIGUOUS rather than retryable."
        ),
    )
    outbound_wait_seconds: float = Field(
        default=20.0,
        gt=0,
        le=20,
        description="How long the intake waits for a terminal state. At most 20.",
    )
    outbound_data_budget_seconds: int = Field(
        default=120,
        ge=1,
        description=(
            "The connector's declared budget for the send itself. The module's "
            "lease must exceed it or the pump refuses to start."
        ),
    )
    outbound_max_waiters: int = Field(
        default=32,
        ge=1,
        description=(
            "Dispatches that may wait for a terminal state at once. Past it a "
            "caller gets the current state immediately and re-posts its key."
        ),
    )
    outbound_binding_cap_per_hour: int = Field(
        default=20,
        ge=0,
        description=(
            "New dispatches accepted per binding per hour; 0 disables the cap. "
            "A re-post of an accepted dispatch_id is never counted."
        ),
    )
    outbound_max_payload_bytes: int = Field(
        default=262_144, ge=0, description="Largest accepted payload; 0 disables."
    )
    outbound_payload_retention_days: int = Field(
        default=7,
        ge=1,
        description="Days an outbound payload is kept before redaction.",
    )
    outbound_replay_evidence_retention_days: int = Field(
        default=0,
        ge=0,
        description=(
            "Days the delivery identity outlives its payload. Unset (0) refuses "
            "the pump: it is a separate legal decision with no default."
        ),
    )
    outbound_legal_policy_owner: str = Field(
        default="",
        description="Accountable owner for legal holds. Unset refuses the pump.",
    )
    operator_killswitch_routes_enabled: bool = Field(
        default=True,
        description=(
            "Mount the operator kill-switch routes (binding and installation "
            "disable, quarantine, release-quarantine) and the census under "
            "/operations. Every one carries require_operator and a required "
            "reason. ON by default (explicit exception approved by Michael: "
            "operator-only routes that only contain); set false to opt out."
        ),
    )
    product_query_enabled: bool = False
    product_provision_enabled: bool = False
    product_query_callers: tuple[ProductQueryCaller, ...] = ()
    product_contract_registry_enabled: bool = False
    product_contract_registry_url: str = ""
    product_contract_registry_expected_digest: str = ""
    product_contract_registry_api_key_ref: str = ""
    product_contract_registry_timeout_seconds: float = Field(default=15.0, gt=0)
    product_contract_registry_expected_count: int = Field(default=4, ge=1)

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
    product_port_prepare_only: bool = Field(
        default=False,
        description=(
            "Authenticate and install the destination owner's contract only. "
            "Requires WORKER_ENABLED=false; creates no destination revision or client."
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
    product_port_descriptor_url: str = Field(
        default="",
        description=(
            "Authenticated product-owned versioned descriptor URL. Its "
            "origin is used for the descriptor-owned delivery paths."
        ),
    )
    product_port_descriptor_expected_digest: str = Field(
        default="",
        description=(
            "Operator-approved SHA-256 of the product descriptor. Drift fails "
            "boot until reviewed and the pin is deliberately advanced."
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
        max_length=160,
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
            "bounds evidence sampling; it is not delivery retry policy and "
            "never changes a receipt attempt."
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
    if (
        not settings.product_port_prepare_only
        and settings.product_port_mode not in PRODUCT_PORT_MODES
    ):
        return [
            f"PRODUCT_PORT_MODE={settings.product_port_mode!r} is not one of "
            f"{list(PRODUCT_PORT_MODES)}. 'mirror' records nothing and produces "
            "parity evidence; 'write' records"
        ]
    if not (settings.product_port_enabled or settings.product_port_prepare_only):
        return []

    problems: list[str] = []
    if settings.product_port_enabled and settings.product_port_prepare_only:
        problems.append(
            "PRODUCT_PORT_ENABLED and PRODUCT_PORT_PREPARE_ONLY are mutually exclusive"
        )
    if settings.product_port_prepare_only and settings.worker_enabled:
        problems.append("PRODUCT_PORT_PREPARE_ONLY requires WORKER_ENABLED=false")
    try:
        parsed = urlsplit(settings.product_port_descriptor_url.strip())
    except ValueError:
        problems.append("PRODUCT_PORT_DESCRIPTOR_URL is not a valid URL")
        parsed = urlsplit("")
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        problems.append(
            "PRODUCT_PORT_DESCRIPTOR_URL must be an http(s) URL without "
            "credentials, query, or fragment"
        )
    if settings.environment == "production" and parsed.scheme != "https":
        # Reuse the normalized URL parsed above: the actual reader strips the
        # URL too, and URL schemes are case-insensitive. Check before holding
        # the destination credential or attempting any network request.
        problems.append(
            "PRODUCT_PORT_DESCRIPTOR_URL must use https:// in production; "
            "message content and the destination credential may not cross "
            "a production network in the clear"
        )
    required = {
        "PRODUCT_PORT_DESCRIPTOR_URL": settings.product_port_descriptor_url,
        "PRODUCT_PORT_DESCRIPTOR_EXPECTED_DIGEST": (
            settings.product_port_descriptor_expected_digest
        ),
        "PRODUCT_PORT_API_KEY_REF": settings.product_port_api_key_ref,
    }
    for name, value in required.items():
        if not value.strip():
            problems.append(
                f"Product-port preparation is configured and {name} is empty; "
                "a port that "
                "cannot address the destination would fail every receipt"
            )
    if settings.product_port_enabled and settings.product_port_mode == "mirror":
        revision = settings.product_port_shadow_revision
        if not revision.strip():
            problems.append(
                "PRODUCT_PORT_SHADOW_REVISION is required in mirror mode; "
                "without an immutable deployment revision, evidence from "
                "different code cannot be separated or deliberately re-driven"
            )
        elif revision != revision.strip():
            problems.append(
                "PRODUCT_PORT_SHADOW_REVISION must not have leading or trailing "
                "whitespace"
            )
    reference = settings.product_port_api_key_ref.strip()
    if reference and (
        not reference.startswith(("env://", "file://"))
        or not reference.partition("://")[2]
    ):
        problems.append(
            "PRODUCT_PORT_API_KEY_REF must be an `env://` or `file://` "
            "reference. It is dereferenced once at startup and held; a literal "
            "credential here would sit in a committed file and in the process "
            "environment of everything that reads this configuration"
        )
    digest = settings.product_port_descriptor_expected_digest.strip()
    if digest and (
        len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        problems.append(
            "PRODUCT_PORT_DESCRIPTOR_EXPECTED_DIGEST must be 64 lowercase hex"
        )
    return problems


def _outbound_problems(settings: Settings) -> list[str]:
    """What the outbound pump needs before it may run. Fail closed."""
    if not settings.outbound_pump_enabled:
        return []
    from dotmac_integration import DEFAULT_POLICY

    problems: list[str] = []
    if not settings.worker_enabled:
        problems.append("OUTBOUND_PUMP_ENABLED requires WORKER_ENABLED=true")
    if DEFAULT_POLICY.lease_seconds <= settings.outbound_data_budget_seconds:
        problems.append(
            "the module's lease must be longer than OUTBOUND_DATA_BUDGET_SECONDS; "
            "a send that outlasts its lease can be taken over and sent twice"
        )
    if (
        settings.outbound_replay_evidence_retention_days
        <= settings.outbound_payload_retention_days
    ):
        problems.append(
            "OUTBOUND_REPLAY_EVIDENCE_RETENTION_DAYS must be set and exceed "
            "OUTBOUND_PAYLOAD_RETENTION_DAYS"
        )
    if not settings.outbound_legal_policy_owner.strip():
        problems.append("OUTBOUND_LEGAL_POLICY_OWNER must name an accountable owner")
    return problems


def validate_settings(settings: Settings) -> list[str]:
    """Configuration checks. Everything unconditional first, prod-fatal after.

    Returned rather than raised so the caller decides — a CLI wants to print all
    of them, a boot wants to refuse on the first. Empty means acceptable.
    """
    problems: list[str] = []
    callers = settings.product_query_callers
    if settings.product_query_enabled and not callers:
        problems.append("PRODUCT_QUERY_ENABLED requires PRODUCT_QUERY_CALLERS")
    if settings.product_provision_enabled and not callers:
        problems.append("PRODUCT_PROVISION_ENABLED requires PRODUCT_QUERY_CALLERS")
    if settings.product_query_enabled and not any(
        "integration:query" in caller.scopes for caller in callers
    ):
        problems.append(
            "PRODUCT_QUERY_ENABLED requires a caller with integration:query scope"
        )
    if settings.product_manage_enabled and not any(
        MANAGE_SCOPE in caller.scopes for caller in callers
    ):
        problems.append(
            f"PRODUCT_MANAGE_ENABLED requires a caller with {MANAGE_SCOPE} scope"
        )
    if settings.product_dispatch_enabled and not any(
        DISPATCH_SCOPE in caller.scopes for caller in callers
    ):
        problems.append(
            f"PRODUCT_DISPATCH_ENABLED requires a caller with {DISPATCH_SCOPE} scope"
        )
    problems.extend(_outbound_problems(settings))
    if settings.product_provision_enabled and not any(
        "integration:provision" in caller.scopes for caller in callers
    ):
        problems.append(
            "PRODUCT_PROVISION_ENABLED requires a caller with "
            "integration:provision scope"
        )
    if (
        settings.product_query_enabled
        or settings.product_provision_enabled
        or settings.product_dispatch_enabled
    ) and not settings.product_contract_registry_enabled:
        problems.append(
            "PRODUCT_QUERY_ENABLED, PRODUCT_PROVISION_ENABLED and "
            "PRODUCT_DISPATCH_ENABLED require PRODUCT_CONTRACT_REGISTRY_ENABLED"
        )
    if len({c.application for c in callers}) != len(callers):
        problems.append("product query caller applications must be unique")
    if len({c.api_key_ref for c in callers}) != len(callers):
        problems.append("product query caller references must be unique")
    for caller in callers:
        if not caller.api_key_ref.startswith(("env://", "file://")):
            problems.append("product query api_key_ref must be env:// or file://")
        known_scopes = {
            "integration:query",
            "integration:provision",
            MANAGE_SCOPE,
            DISPATCH_SCOPE,
        }
        if (
            not set(caller.scopes) & known_scopes
            or not set(caller.scopes) <= known_scopes
        ):
            problems.append(
                "product caller requires exact integration:query, "
                "integration:provision, integration:manage and/or "
                "integration:dispatch scope"
            )
        if len(set(caller.binding_ids)) != len(caller.binding_ids):
            problems.append("product query caller binding_ids must be unique")
    if settings.product_contract_registry_enabled:
        required_registry = {
            "PRODUCT_CONTRACT_REGISTRY_URL": settings.product_contract_registry_url,
            "PRODUCT_CONTRACT_REGISTRY_EXPECTED_DIGEST": (
                settings.product_contract_registry_expected_digest
            ),
            "PRODUCT_CONTRACT_REGISTRY_API_KEY_REF": (
                settings.product_contract_registry_api_key_ref
            ),
        }
        for name, value in required_registry.items():
            if not value.strip():
                problems.append(
                    f"PRODUCT_CONTRACT_REGISTRY_ENABLED is on and {name} is empty"
                )
        reference = settings.product_contract_registry_api_key_ref.strip()
        if reference and (
            not reference.startswith(("env://", "file://"))
            or not reference.partition("://")[2]
        ):
            problems.append(
                "PRODUCT_CONTRACT_REGISTRY_API_KEY_REF must be env:// or file://"
            )
        digest = settings.product_contract_registry_expected_digest.strip()
        if digest and (
            len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
        ):
            problems.append(
                "PRODUCT_CONTRACT_REGISTRY_EXPECTED_DIGEST must be 64 lowercase hex"
            )

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
    # NOT checked when it is still the default. The api and worker services
    # deliberately have no MIGRATION_DATABASE_URL in their environment at all —
    # the online role cannot create a table, and handing those processes the
    # owner DSN to satisfy a check would give away exactly the separation the
    # check exists to protect. Only a deployment that SET this value, and set it
    # wrongly, is refused; `migrate` is the one service that sets it.
    if (
        settings.migration_database_url != _DEFAULT_MIGRATION_DATABASE_URL
        and "@localhost" in settings.migration_database_url
    ):
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
    if (
        settings.product_contract_registry_enabled
        and settings.product_contract_registry_url.startswith("http://")
    ):
        problems.append(
            "PRODUCT_CONTRACT_REGISTRY_URL is http://; the request carries a "
            "replayable product descriptor credential"
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
