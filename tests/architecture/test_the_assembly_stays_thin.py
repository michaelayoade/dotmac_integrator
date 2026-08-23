"""The assembly pins, composes, configures and operates. Nothing else.

"Thin" is a claim that decays silently. The first provider branch added here
would work, pass review as a small change, and quietly make this deployment a
second writer for a decision `dotmac-integration` already owns — the exact
parallel-authority failure ADR-0024 exists to prevent. By the time it is
obvious, several more have followed.

So the boundary is a test rather than a paragraph in the README.

## What is checked

1. Generic assembly source names no connector. The deployment manifest pins
   distributions, while runtime registration is only through the
   `dotmac_integration.connectors` entry-point group; an import or provider
   branch here would create a second integration mechanism.
2. No business-decision vocabulary. Retry counts, backoff, lease durations and
   attempt limits belong to `ExecutionPolicy`. A number here is a fork.
3. Routes hold no session and issue no query — the same adapter split the
   Starter enforces between `router.py` and `service.py`.
4. The module's decision functions are not reimplemented.
5. No DDL. Migrations are a deploy step run as the owner role.
9. The SPI 1.3 runtime boundaries are PROJECTED, never restated. A provider
   hostname or a connector's secret-binding name written into generic source
   would be a second declaration beside the manifest's, and the manifest is the
   reviewed one.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "dotmac_integrator"


def _modules() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py") if p.name != "__init__.py")


def _source_without_docstrings(path: Path) -> str:
    """Code only.

    Every check below would otherwise match this repository's own prose — these
    files discuss retry policy and connectors at length precisely because they
    do not implement them, and a text scan that cannot tell explanation from
    implementation reports the explanation.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(
            node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                body.pop(0)
    return ast.unparse(tree)


# ── 1. No connector is named in generic source ─────────────────────────────

# Providers this assembly must never know about by name. Not an exhaustive list
# of every provider in the world — it is the set named in the programme's own
# plan, which is what a well-meaning shortcut would reach for first.
FORBIDDEN_PROVIDERS = (
    "whatsapp",
    "meta",
    "twilio",
    "erpnext",
    "stripe",
    "paystack",
    "flutterwave",
    "sendgrid",
    "mailgun",
)


@pytest.mark.parametrize("provider", FORBIDDEN_PROVIDERS)
def test_no_provider_is_named_anywhere_in_the_assembly(provider: str) -> None:
    # Word boundaries, not substrings. `meta` as a substring matches `metadata`
    # and `metaclass`, and a guard that cries wolf on ordinary code gets
    # weakened by whoever hits it next — which is how a real one stops working.
    pattern = re.compile(rf"\b{re.escape(provider)}\b", re.IGNORECASE)
    for path in _modules():
        code = _source_without_docstrings(path)
        assert not pattern.search(code), (
            f"{path.name} names the provider {provider!r}. Connectors are "
            "separately released distributions discovered through the "
            "`dotmac_integration.connectors` entry-point group — this assembly "
            "composes whatever is installed and knows none of them by name."
        )


def test_discovery_is_the_only_way_a_connector_enters() -> None:
    """Entry points, never a registration call or an import.

    Asserted positively: a test that only forbids names would still pass if
    discovery were removed and connectors arrived some other way.
    """
    code = (SRC / "operations.py").read_text(encoding="utf-8")
    assert "integration.discover()" in code
    assert "ENTRY_POINT_GROUP" in code


# ── 2. No business decision ─────────────────────────────────────────────────

# Vocabulary that belongs to `dotmac_integration.ExecutionPolicy`. A literal
# assignment to any of these in this repository forks a decision that has an
# owner: the module would hold one answer and the deployment another.
POLICY_NAMES = (
    "max_attempts",
    "base_delay_seconds",
    "max_backoff_seconds",
    "lease_seconds",
    "stale_checkpoint_after_seconds",
    "retry_delay",
    "backoff",
)


@pytest.mark.parametrize("name", POLICY_NAMES)
def test_no_execution_policy_value_is_defined_here(name: str) -> None:
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
            for target in targets:
                label = (
                    target.id
                    if isinstance(target, ast.Name)
                    else getattr(target, "attr", "")
                )
                assert label != name, (
                    f"{path.name} assigns {name!r}. That is an ExecutionPolicy "
                    "field owned by dotmac-integration; setting it here gives "
                    "the deployment a second, competing answer."
                )


def test_the_assembly_never_constructs_an_execution_policy() -> None:
    for path in _modules():
        code = _source_without_docstrings(path)
        assert "ExecutionPolicy(" not in code, (
            f"{path.name} builds an ExecutionPolicy. Use the module's "
            "DEFAULT_POLICY; a deployment-authored policy is a fork."
        )


# ── 3. Routes are adapters ──────────────────────────────────────────────────


def test_routes_hold_no_session_and_issue_no_query() -> None:
    """`assembly.py` is this repository's `router.py`.

    The session, the fetch and the commit live in `operations.py`. Same split
    the Starter enforces, and for the same reason: a handler that queries grows
    logic that nothing else can reuse and no service test covers.
    """
    code = _source_without_docstrings(SRC / "assembly.py")
    for banned in ("Session(", ".execute(", "select(", ".commit()", ".query("):
        assert (
            banned not in code
        ), f"assembly.py contains {banned!r} — move it into operations.py"


# ── 4. Module decisions are not reimplemented ───────────────────────────────

# Functions `dotmac_integration` owns. Defining one HERE would shadow the
# module's and make this assembly the writer.
OWNED_BY_THE_MODULE = (
    "add_binding",
    "create_draft",
    "resolve_binding",
    "claim_delivery",
    "settle",
    "prepare",
    "invoke",
    "next_state",
    "retry_delay_seconds",
    "check_activation",
    "require_activatable",
    "mint_ingress_endpoint",
    "put_config_revision",
    "set_binding_enabled",
    "validate_secret_refs",
    "record_delivery_outcome",
    # SPI 1.3. The projection of the installed manifest set is the module's, and
    # an assembly-side one would be a second answer to "what did these
    # connectors declare" — computed from the same manifests, drifting the
    # moment the module's rules change.
    "derive_runtime_policy",
)


@pytest.mark.parametrize("name", OWNED_BY_THE_MODULE)
def test_no_module_owned_function_is_redefined(name: str) -> None:
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                assert node.name != name, (
                    f"{path.name} defines {name!r}, which dotmac-integration "
                    "owns. Call it; do not restate it."
                )


# ── 5. No DDL ───────────────────────────────────────────────────────────────


def test_the_application_never_issues_ddl() -> None:
    """Migrations run as the owner role at deploy time, never on boot.

    `migrations/env.py` is excluded — it is the deploy path, and it is the one
    place DDL is legitimate.
    """
    pattern = re.compile(r"\b(CREATE|ALTER|DROP)\s+(TABLE|SCHEMA|INDEX)\b", re.I)
    for path in _modules():
        code = _source_without_docstrings(path)
        assert not pattern.search(code), f"{path.name} issues DDL"
        assert "create_all" not in code, f"{path.name} calls create_all"


# ── Sensitivity proof (ADR-0018) ────────────────────────────────────────────


def test_the_scan_actually_reads_files() -> None:
    """Every check above iterates `_modules()`. If that returned nothing, all of
    them would pass while inspecting no code at all."""
    modules = _modules()
    assert len(modules) >= 5, modules
    names = {p.name for p in modules}
    assert {"assembly.py", "operations.py", "worker.py"} <= names, names
    for path in modules:
        assert _source_without_docstrings(path).strip(), path


def test_docstring_stripping_removes_prose_but_keeps_code() -> None:
    """The stripper is what lets these checks be strict.

    If it silently returned the whole file, the provider scan would fail on this
    repository's own explanations; if it returned nothing, every scan would pass
    vacuously. Both directions are asserted.
    """
    sample = SRC / "worker.py"
    raw = sample.read_text(encoding="utf-8")
    stripped = _source_without_docstrings(sample)

    assert "ExecutionPolicy" in raw, "fixture assumption broke"
    assert "ExecutionPolicy" not in stripped, "prose survived stripping"
    assert "class Worker" in stripped, "code did not survive stripping"


def test_the_provider_detector_bites() -> None:
    """Exercised on a planted hit AND on the word it must not confuse, so the
    boundary refinement above cannot quietly become a substring match again."""
    assert re.search(r"\bwhatsapp\b", "handler = build_whatsapp_client()", re.I) is None
    assert re.search(r"\bwhatsapp\b", "client = whatsapp.Client()", re.I)
    assert re.search(r"\bmeta\b", "columns = table.metadata.columns", re.I) is None
    assert re.search(r"\bmeta\b", "from meta import graph", re.I)


def test_the_policy_detector_bites() -> None:
    tree = ast.parse("max_attempts = 5\n")
    found = [
        t.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        for t in node.targets
        if isinstance(t, ast.Name)
    ]
    assert "max_attempts" in found


# ── 7. The body is bounded as it is READ ────────────────────────────────────

#: Every way Starlette will hand over a fully-buffered body. Each of them reads
#: the whole stream into memory and only then offers a length to check, so a
#: cap applied afterwards has already accepted the memory it was refusing.
BUFFERING_CALLS = ("request.body()", "request.json()", "request.form()")


@pytest.mark.parametrize("call", BUFFERING_CALLS)
def test_the_ingress_edge_never_buffers_before_it_caps(call: str) -> None:
    """A request-size limit measured after buffering is an amplifier for the
    denial of service it exists to prevent, and it is worse still before an
    HMAC: verifying first means buffering first, so a 10 GB body from an
    unauthenticated sender would be held in memory to discover it was not
    signed.

    The cap therefore consumes `request.stream()` and refuses on byte
    `limit + 1`. This is a source check because the mistake is a one-line
    convenience edit that every behavioural test would still pass — the
    RESULT of `await request.body()` plus a length check is identical.
    """
    for name in ("assembly.py", "ingress.py"):
        code = _source_without_docstrings(SRC / name)
        assert call not in code, (
            f"{name} calls {call}, which buffers the whole body before the cap "
            "can refuse it — read `request.stream()` instead"
        )


def test_the_ingress_edge_does_consume_the_stream() -> None:
    """Read positively. The check above would also pass over a file that read
    no body at all, which is what it would look like if someone deleted the
    cap rather than moved it."""
    code = _source_without_docstrings(SRC / "assembly.py")
    assert "request.stream()" in code
    assert "read_capped_body" in code


def test_the_buffering_detector_bites() -> None:
    """Sensitivity proof (ADR-0018). The substring scan above is only evidence
    once it has been shown to fire on the diff it is there to catch."""
    plausible = "    body = await request.body()\n    if len(body) > limit: ..."
    assert any(call in plausible for call in BUFFERING_CALLS)
    assert "request.stream()" not in plausible


def test_no_ingress_status_code_is_written_by_this_assembly() -> None:
    """An ingress status IS a retry instruction to the provider — 200 means
    "never send this again" — and only the engine knows whether the batch
    committed. `refusal_outcome` is the one place a status is chosen, and the
    edge uses it too: it constructs `PayloadTooLarge()` and passes it there
    rather than writing `413` itself."""
    code = _source_without_docstrings(SRC / "assembly.py")
    assert "refusal_outcome" in code
    for invented in ("413", "status_code=401", "status_code=503"):
        assert invented not in code, (
            f"assembly.py writes {invented!r} on the ingress path; the status "
            "belongs to `dotmac_integration.refusal_outcome`"
        )


# ── 8. Claiming is the module's, and stays the module's ─────────────────────

#: SQL that would mean this assembly had grown its own claim. Each is the
#: shortest path to reimplementing at-most-once badly: a hand-written state
#: UPDATE has no lease in its predicate, and a row lock taken here would be
#: held across the product call — the transaction-around-the-network the
#: module's three phases exist to prevent.
CLAIM_SHAPED_SQL = (
    "FOR UPDATE",
    "SKIP LOCKED",
    "state = 'processing'",
    # `attempt_count` alone is NOT here: it is a legitimate column to READ, and
    # `operations._repaired` reports it. What must not appear is an assignment
    # to it, which is the increment only the conditional UPDATE may perform.
    "attempt_count =",
    "attempt_count +",
    "leased_until =",
)


@pytest.mark.parametrize("fragment", CLAIM_SHAPED_SQL)
def test_the_assembly_does_not_reimplement_the_receipt_claim(fragment: str) -> None:
    for path in _modules():
        code = _source_without_docstrings(path)
        assert fragment not in code, (
            f"{path.name} contains {fragment!r}. Claiming belongs to "
            "`dotmac_integration.ReceiptClaims`, where `rowcount == 1` IS the "
            "claim; a second one here is a second answer to at-most-once"
        )


def test_the_pump_drives_the_modules_claim_and_orchestrator() -> None:
    """Read positively: the bans above would also pass over a file that
    delivered nothing at all."""
    code = _source_without_docstrings(SRC / "delivery.py")
    assert "integration.ReceiptClaims(" in code
    assert "integration.deliver_receipt(" in code


def _function_source(path: Path, name: str) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            and node.name == name
        ):
            return ast.unparse(node)
    raise AssertionError(f"{path.name} no longer defines {name!r}")


#: Everything that would make the shadow pass claim or settle a receipt. It is a
#: SOURCE check because the mistake is a one-line convenience — "while we're
#: here, mark it processed" — and the resulting run would look like a completed
#: cutover while every observation it touched was seen by nobody. Shadow
#: evidence is durable too, but its mutation belongs to the module's dedicated
#: service and is deliberately committed by a separate assembly helper.
SETTLING_CALLS = ("ReceiptClaims", "deliver_receipt", ".settle(", ".commit()")


@pytest.mark.parametrize("call", SETTLING_CALLS)
def test_the_shadow_pass_settles_nothing(call: str) -> None:
    """The destination's shadow port RECORDS NOTHING, so a receipt settled
    against it would be marked delivered for an observation that was never
    recorded. The pass therefore takes no claim, writes no receipt column and
    reaches no receipt settlement."""
    source = _function_source(SRC / "delivery.py", "mirror_due_receipts")
    assert call not in source, (
        f"`mirror_due_receipts` contains {call!r}. A shadow pass that changed "
        "durable state is indistinguishable from a cutover that worked"
    )


def test_shadow_evidence_is_written_only_through_the_module_service() -> None:
    helper = _function_source(SRC / "delivery.py", "_record_shadow_observation")
    assert "integration.record_shadow_observation" in helper
    assert ".commit()" in helper
    assert not any(
        call in helper for call in ("ReceiptClaims", "deliver_receipt", ".settle(")
    )


def test_shadow_source_provenance_uses_the_module_resolver() -> None:
    source = _function_source(SRC / "delivery.py", "_shadow_request")
    assert "integration.resolve_product_observation_source" in source
    assert "ConnectorInstallation" not in source
    assert "CapabilityBinding" not in source


def test_shadow_source_resolver_guard_bites_on_a_local_join() -> None:
    plausible = "select(ConnectorInstallation).join(CapabilityBinding)"
    assert "ConnectorInstallation" in plausible
    assert "CapabilityBinding" in plausible


def test_product_wire_selection_uses_only_the_descriptor_protocol_version() -> None:
    source = _function_source(SRC / "product_port.py", "build_product_document")
    assert "_PRODUCT_DOCUMENT_BUILDERS" in source
    for product_fact in ("application", "capability_id", "connector_key"):
        assert product_fact not in source


def test_product_wire_selection_guard_bites_on_a_capability_branch() -> None:
    plausible = "if request.destination.capability_id == 'some.contract.v1':"
    assert "capability_id" in plausible


def test_the_delivery_pump_refuses_a_non_writing_port() -> None:
    """Read positively: the bans above would also pass over a shadow pass that
    did nothing at all, and they say nothing about the WRITE pump."""
    source = _function_source(SRC / "delivery.py", "deliver_due_receipts")
    assert "product_port_writes()" in source
    assert "ShadowPortInstalled" in source


def test_the_settling_detector_bites() -> None:
    """Sensitivity proof (ADR-0018). The scan is only evidence once it has been
    shown to fire on the diff it exists to catch."""
    plausible = "store = integration.ReceiptClaims(lambda: Session(engine))"
    assert any(call in plausible for call in SETTLING_CALLS)
    assert _function_source(SRC / "delivery.py", "deliver_due_receipts").count(
        "ReceiptClaims"
    ), "the detector must be able to see a real settling call in this file"


def test_the_claim_detector_bites() -> None:
    """Sensitivity proof (ADR-0018)."""
    plausible = (
        "db.execute(text(\"UPDATE inbox_receipts SET state = 'processing' \"\n"
        '    "WHERE id = :id FOR UPDATE"))'
    )
    assert any(fragment in plausible for fragment in CLAIM_SHAPED_SQL)


# ── 9. The runtime boundaries are projected, never restated ────────────────

#: A connector declares its exact provider hosts in its own manifest, and
#: `dotmac_integration.derive_runtime_policy` projects the union. A DNS literal
#: in this repository would be a second egress list — one an operator could
#: widen without installing a reviewed connector release, which is the exact
#: move `EgressDeclaration` refuses by taking no installation-provided hosts.
#:
#: Anchored on a dotted lower-case name inside a string literal. Deliberately
#: not a general "looks like a hostname" scan: `pyproject.toml`, a media type
#: and a dotted import path all read that way, and a detector that fires on
#: ordinary code gets weakened by whoever hits it next.
_EGRESS_SHAPED_LITERAL = re.compile(
    r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*\."
    r"(?:com|net|org|io|co|dev|app|cloud|ng)\b"
)


def _string_literals(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    literals: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            literals.append(node.value)
    return literals


def test_no_egress_host_is_written_into_the_projection() -> None:
    """`runtime_policy.py` reads hosts; it never names one."""
    for literal in _string_literals(SRC / "runtime_policy.py"):
        assert not _EGRESS_SHAPED_LITERAL.search(literal), (
            f"runtime_policy.py contains the host-shaped literal {literal!r}. "
            "The egress union is projected from the installed manifests through "
            "`derive_runtime_policy`; a host named here would be a second "
            "allowlist this repository has to keep in sync with the connector "
            "releases it does not own."
        )


def test_the_projection_is_the_modules_and_the_verdicts_are_reported() -> None:
    """Read positively.

    The bans above would pass over a file that projected nothing at all. This
    asserts the three module-owned calls are actually made — the projection
    itself, and both capability refusals whose VERDICT this deployment reports
    instead of raising, because declaring a capability is a product decision and
    this assembly may never mint one.
    """
    code = _source_without_docstrings(SRC / "runtime_policy.py")
    for call in (
        "integration.derive_runtime_policy",
        "integration.require_implements_only_declared",
        "integration.require_no_orphans",
    ):
        assert call in code, f"runtime_policy.py never calls {call}"


def test_the_egress_literal_detector_bites() -> None:
    """Sensitivity proof (ADR-0018). The scan is evidence only once it has been
    shown to fire on the diff it exists to catch — here, somebody hardcoding the
    provider host a connector already declares."""
    plausible = 'ALLOWED_EGRESS = ("graph.facebook.com",)'
    assert _EGRESS_SHAPED_LITERAL.search(plausible)
    assert not _EGRESS_SHAPED_LITERAL.search("dotmac_integration.runtime_policy")
    assert not _EGRESS_SHAPED_LITERAL.search("text/plain; charset=utf-8")
