"""The deployment descriptor says what this assembly's AGENTS.md already says.

`deploy/product.toml` is checked in, so a reviewer reads it — but a reviewer
reads a hundred things, and the two properties that matter most here are exactly
the two that are invisible unless something asserts them: that the owner
credential is absent from the runtime role, and that the image is a digest.

Skipped rather than failed when the foundation is not INSTALLED — which is a
different statement from the one this docstring used to make, and the difference
matters. `dotmac-deployment-foundation` IS published: the newest tag is
`dotmac-deployment-foundation-v0.2.0a2`, and `.github/workflows/
deployment-conformance.yml` pins exactly that. What is still true is that this
assembly does not DEPEND on it: it is a build-time gate installed by the
conformance job from the private index, not a runtime dependency in
`pyproject.toml`. So a plain `make test-unit` has no such package and skips,
while the conformance job sets
`DOTMAC_DEPLOYMENT_FOUNDATION_REQUIRED=1` and a missing package is a hard
failure there.

This assembly consumes published wheels and never a second checkout of the
Starter (rule 3); vendoring a copy to make the test run would be the fork this
whole programme exists to end.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

# A skip is not a gate — so the skip is CONDITIONAL and the condition is
# explicit. Setting `DOTMAC_DEPLOYMENT_FOUNDATION_REQUIRED=1` turns a missing
# package from a quiet skip into a hard failure, and the conformance job sets
# it. Before the distribution is published the skip is honest: the package
# genuinely is not installable, and failing every build over that would teach
# people to ignore red. After it is published, a silent skip would mean the
# descriptor stopped being checked and nothing said so — which is the shape of
# every defect in this branch's own review.
_REQUIRED = os.environ.get("DOTMAC_DEPLOYMENT_FOUNDATION_REQUIRED") == "1"
try:
    import dotmac_deployment_foundation  # noqa: F401
except ImportError as exc:  # pragma: no cover - exercised by the env var
    if _REQUIRED:
        raise AssertionError(
            "DOTMAC_DEPLOYMENT_FOUNDATION_REQUIRED=1 but the package is not "
            f"importable: {exc}. Either the pin is wrong or the install step "
            "did not run — both are failures, not skips."
        ) from exc
    pytest.skip(
        "dotmac-deployment-foundation is not published yet; set "
        "DOTMAC_DEPLOYMENT_FOUNDATION_REQUIRED=1 to make this a failure",
        allow_module_level=True,
    )

from dotmac_deployment_foundation.conformance import check_all  # noqa: E402
from dotmac_deployment_foundation.errors import SpecError  # noqa: E402
from dotmac_deployment_foundation.spec import ProductDeploymentSpec  # noqa: E402

from dotmac_integrator.lineage import version_locations  # noqa: E402

DESCRIPTOR = Path(__file__).resolve().parents[2] / "deploy" / "product.toml"
OWNER_MATERIAL = "MIGRATION_DATABASE_URL"


@pytest.fixture(scope="module")
def spec() -> ProductDeploymentSpec:
    return ProductDeploymentSpec.load(DESCRIPTOR)


# ── the conformance ratchet ─────────────────────────────────────────────────
#
# The descriptor is NOT conformance-clean, and pretending otherwise is exactly
# the failure this branch was reviewed for. The findings below are listed
# EXACTLY — not as a subset — so the list fails in both directions: a new
# finding fails here, and a finding that gets fixed without this list shrinking
# fails here too. That is the two-directional ratchet `AGENTS.md` rule 25
# requires of a temporary deviation.
#
# They are placeholders because no image has been built for this descriptor to
# pin, and the discharge condition is stated rather than left to intent.
#
# An earlier revision of this comment said "every entry must be gone before this
# adapter merges". That requirement could never be met, and the reason is
# ordering rather than effort: `release-image.yml` runs on merged `main` and IS
# what produces the digest, so demanding a real digest before the merge that
# lets the image be built is circular. Left as written it would have been
# discharged the only way a circular gate ever is — by someone deciding it did
# not really mean it.
#
# So the honest sequence is recorded instead. This list is the two-directional
# ratchet: a NEW finding fails here, and a finding fixed without shrinking this
# list fails here too. It shrinks to empty in the change that writes the real
# image digest and the real assembly manifest digest into `deploy/product.toml`
# — the same change that must set `require-real-digests` back to its `true`
# default in `.github/workflows/deployment-conformance.yml`. Those two edits
# belong together and neither is complete alone.
KNOWN_UNRESOLVED = (
    "image.reference is pinned to the placeholder",
    "assembly.manifest_digest is the placeholder",
)


def test_the_descriptor_parses(spec: ProductDeploymentSpec) -> None:
    assert spec.product == "dotmac_integrator"
    assert spec.role_codes == ("api",)


def test_no_runtime_role_holds_the_migration_owner_material(
    spec: ProductDeploymentSpec,
) -> None:
    """AGENTS.md rule 5, stated as an assertion.

    `MIGRATION_DATABASE_URL` is the owner role; `DATABASE_URL` is the online
    platform role and cannot create a table. A runtime role holding the owner
    credential can create, alter and drop any table for the life of the
    deployment, and a compromised web process can read it.
    """
    assert spec.migration.owner_material == OWNER_MATERIAL
    for role in spec.roles:
        assert OWNER_MATERIAL not in role.materials, role.code
    assert OWNER_MATERIAL not in spec.runtime_materials


def test_the_image_is_pinned_by_digest(spec: ProductDeploymentSpec) -> None:
    """Inventory defect D14.

    The release workflow states it deploys by digest; the compose file it
    deploys read `${INTEGRATOR_TAG:-latest}`, so the stated contract was
    unimplementable. Here the reference is the digest itself.
    """
    assert "@sha256:" in spec.image
    assert ":latest" not in spec.image


def test_liveness_is_separate_from_readiness(spec: ProductDeploymentSpec) -> None:
    """`assembly.py:185-192` implements both; the descriptor must not conflate them.

    Liveness answers whether the process is alive and touches nothing. Readiness
    runs `SELECT 1` plus a schema check and returns 503 until the schema is
    present — the state between a first deploy's image landing and its migration
    finishing.
    """
    api = spec.role("api")
    assert api.live is not None and api.ready is not None
    assert api.live.path == "/health/live"
    assert api.ready.path == "/health/ready"
    assert api.live.path != api.ready.path


#: `revision = "..."` as a released Alembic migration writes it — the same
#: pattern, and the same reasoning, as `migration_bindings._REVISION_ASSIGNMENT`.
_REVISION = re.compile(r"^revision\s*(?::\s*str\s*)?=\s*[\"']([^\"']+)[\"']", re.M)

#: The whole right-hand side of a `down_revision` assignment, which may be
#: `None`, one string, or a tuple of them. Captured loosely and mined for
#: quoted names below rather than parsed, because every form that matters here
#: is "which revision ids does this name".
_DOWN_REVISION = re.compile(r"^down_revision[^=]*=\s*(.+)$", re.M)

_QUOTED = re.compile(r"[\"']([^\"']+)[\"']")


def _lineage_head(directory: Path) -> str:
    """The one revision in `directory` that nothing in `directory` descends from.

    Parsed, never imported: importing a revision module EXECUTES it, and a
    module lineage is entitled to resolve `depends_on` at import time through
    machinery this check must not depend on being configured. That is the same
    choice `migration_bindings.composed_revision_ids` makes, for the same reason.

    `down_revision` targets outside this directory are ignored rather than
    followed, and that is what makes this correct across the composed set: the
    `ig` lineage's root carries a literal edge to the kernel's
    `0001_initial_tenant_schema`, and following it would merge two lineages
    Alembic deliberately keeps as separate branches with separate heads.
    """
    revisions: set[str] = set()
    parents: set[str] = set()
    for path in sorted(directory.glob("*.py")):
        if path.name.startswith("__"):
            continue
        text = path.read_text(encoding="utf-8")
        found = _REVISION.search(text)
        if found is None:
            continue
        revisions.add(found.group(1))
        for assignment in _DOWN_REVISION.findall(text):
            parents.update(_QUOTED.findall(assignment))
    heads = revisions - parents
    assert len(heads) == 1, f"{directory} has {len(heads)} heads: {sorted(heads)}"
    return heads.pop()


def test_both_composed_lineages_are_named(spec: ProductDeploymentSpec) -> None:
    """`upgrade heads` is plural, and a partial upgrade still exits 0.

    Two lineages are composed. Naming only one would make a lineage that
    silently did not advance invisible to every check there is.
    """
    assert len(spec.migration.expected_heads) == 2


def test_the_declared_heads_are_the_installed_lineage_heads() -> None:
    """The declared heads are DERIVED from the installed wheels, not asserted.

    This test previously named `ig_0011_replay_retention` as a literal, and the
    literal went stale exactly as a literal does: the pin moved a13 -> a17 and
    the `ig` lineage advanced four revisions (ig_0012 delivery evidence, ig_0013
    delivery result, ig_0014 polling evidence, ig_0015 descriptor contract)
    while both the descriptor and this assertion kept naming the a13 head. A
    check that agrees with a stale descriptor is not a check.

    The failure it would have let through is not cosmetic. `verify_heads`
    compares `expected_heads` against what `heads_command` prints, so a stale
    declaration makes a CORRECTLY migrated deployment fail its own gate — a
    false alarm on every deploy, which is the reliable way to teach an operator
    to skip the gate.

    So the expected value is read from the lineages this deployment actually
    composes, through the same `version_locations()` the migration itself uses.
    Now the descriptor is what must keep up, and a pin bump that forgets to
    re-derive `expected_heads` fails here rather than in production.
    """
    spec = ProductDeploymentSpec.load(DESCRIPTOR)
    installed = {_lineage_head(Path(d)) for d in version_locations()}
    assert set(spec.migration.expected_heads) == installed, (
        "deploy/product.toml names heads that are not the heads of the "
        f"installed lineages. Declared {sorted(spec.migration.expected_heads)}, "
        f"installed {sorted(installed)}. Re-derive expected_heads at the pin "
        "bump that moved them."
    )


def test_metrics_material_is_declared(spec: ProductDeploymentSpec) -> None:
    """Inventory defect D15.

    `ENVIRONMENT=production` makes `METRICS_TOKEN` prod-fatal and the compose
    file never set it, so the shipped defaults refused to boot. Declaring it
    makes a missing material a render-time fact.
    """
    assert "METRICS_TOKEN" in spec.runtime_materials
    assert "METRICS_TOKEN" in spec.role("api").materials


def test_egress_is_declared_empty_rather_than_omitted(
    spec: ProductDeploymentSpec,
) -> None:
    """Rule 32: an EMPTY egress is an explicit deny-all, an OMITTED one is a hole.

    The real host set is projected at boot from the installed connector
    manifests. A second allowlist here could be widened without installing a
    reviewed connector release, so this list must stay empty forever — and the
    assertion is what stops somebody helpfully filling it in.
    """
    assert spec.egress_hosts == ()


# ── sensitivity proofs (ADR-0018) ───────────────────────────────────────────


def test_the_real_descriptor_loads_cleanly() -> None:
    """The negative control.

    Without it, both refusal tests below would pass on a loader that rejects
    everything — which is the most common way a pair of refusal tests stops
    meaning anything.
    """
    assert ProductDeploymentSpec.load(DESCRIPTOR).product == "dotmac_integrator"


def test_giving_the_runtime_role_the_owner_material_is_refused() -> None:
    text = DESCRIPTOR.read_text(encoding="utf-8").replace(
        '  "SECRET_ENV_PREFIX",\n]',
        '  "SECRET_ENV_PREFIX",\n  "MIGRATION_DATABASE_URL",\n]',
    )
    with pytest.raises(SpecError) as caught:
        ProductDeploymentSpec.loads(text, source="<planted>")
    assert "MIGRATION_DATABASE_URL" in str(caught.value)


def test_a_mutable_image_tag_is_refused() -> None:
    text = DESCRIPTOR.read_text(encoding="utf-8").replace(
        "registry.dotmac.io/dotmac/integrator@sha256:"
        "0000000000000000000000000000000000000000000000000000000000000000",
        "registry.dotmac.io/dotmac/integrator:latest",
    )
    with pytest.raises(SpecError):
        ProductDeploymentSpec.loads(text, source="<planted>")


def test_conformance_findings_are_exactly_the_known_unresolved_ones() -> None:
    """Not `== []`, and not a subset — an exact match in both directions.

    A subset assertion passes when a finding is fixed and the list is not
    updated, so the list stops describing anything. An exact match makes the
    ratchet visible: fixing a finding is a diff that removes a line here.
    """
    from dotmac_deployment_foundation.spec import ProductDeploymentSpec

    findings = check_all(ProductDeploymentSpec.load(DESCRIPTOR))
    matched = [
        finding
        for finding in findings
        if any(known in finding for known in KNOWN_UNRESOLVED)
    ]
    unexpected = [finding for finding in findings if finding not in matched]
    assert unexpected == [], f"new conformance finding(s): {unexpected}"
    assert len(matched) == len(KNOWN_UNRESOLVED), (
        f"{len(KNOWN_UNRESOLVED)} known finding(s) declared but {len(matched)} "
        "observed — a fixed finding must be removed from KNOWN_UNRESOLVED in "
        "the same change that fixes it"
    )
