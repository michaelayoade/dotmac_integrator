"""Guards on the image release lane.

The lane's guarantees are structural — they live in which job does what, and in
what order. YAML cannot state them, so they are stated here.

Each guard exists because the opposite is a plausible, well-meant edit:

* dropping the second freshness check reads like removing a duplicate;
* rebuilding in `publish` reads like avoiding an artefact round-trip;
* auditing once reads like not repeating yourself;
* pulling the published TAG rather than its DIGEST reads like the same thing.

Every one of those would publish or bless something nobody approved.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LANE = PROJECT_ROOT / ".github/workflows/release-image.yml"
GUARD = PROJECT_ROOT / "scripts/assert_current_main.sh"


def _lane() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(LANE.read_text(encoding="utf-8"))
    return loaded


def _steps(job: str) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = _lane()["jobs"][job]["steps"]
    return steps


def _run_text(job: str) -> str:
    return "\n".join(str(step.get("run", "")) for step in _steps(job))


def test_the_freshness_guard_refuses_a_moved_main() -> None:
    """An approval is a decision about a SHA, not about a run id."""

    result = subprocess.run(
        ["bash", str(GUARD), "a" * 40, "b" * 40],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "not the current protected main" in result.stderr + result.stdout


def test_the_freshness_guard_passes_on_the_current_tip() -> None:
    """Sensitivity: a guard that refused everything would satisfy the test above
    while making every release impossible, so prove it also accepts.
    """

    result = subprocess.run(
        ["bash", str(GUARD), "c" * 40, "c" * 40],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0


@pytest.mark.parametrize("job", ["build", "publish"])
def test_both_jobs_assert_main_freshness(job: str) -> None:
    """`publish` waits behind a protected environment, possibly for hours.

    Without its own call, commits landing during that wait are silently absent
    from a release claiming to be current, and the tag points at a SHA that is
    no longer the tip.
    """

    assert "assert_current_main.sh" in _run_text(job)


def test_only_the_build_job_builds() -> None:
    """Nothing may be rebuilt after approval.

    A rebuild is a different artefact even from an identical tree — timestamps
    move, a base image may have been re-pushed, a resolver may see a new patch
    release. `publish` must load and push the bytes `build` audited.
    """

    lane = _lane()
    building = {
        job
        for job, spec in lane["jobs"].items()
        for step in spec["steps"]
        if "build-push-action" in str(step.get("uses", ""))
    }

    assert building == {"build"}
    assert "docker load" in _run_text("publish")


def test_the_audit_runs_before_and_after_publication() -> None:
    """The second run is not ceremony.

    It is the first moment anything proves the registry holds what was approved,
    rather than what someone else pushed to the same tag while the approval sat
    pending.
    """

    assert "audit_image.sh" in _run_text("build")
    assert "audit_image.sh" in _run_text("verify")


def test_verification_pulls_by_digest_not_by_tag() -> None:
    """A tag can be moved; a digest cannot.

    Pulling the tag back would re-prove nothing, because the thing being
    established is precisely that the registry holds the approved artefact.
    """

    verify = _run_text("verify")

    assert "@${{ needs.publish.outputs.digest }}" in verify


def test_the_tag_is_written_only_after_verification() -> None:
    """A tag is the pinnable oracle. It must not exist for an artefact whose
    published bytes were never audited.
    """

    lane = _lane()
    tagging = {
        job
        for job, spec in lane["jobs"].items()
        if "git push origin" in "\n".join(str(s.get("run", "")) for s in spec["steps"])
    }

    assert tagging == {"verify"}
    assert lane["jobs"]["verify"]["needs"] == "publish"


@pytest.mark.parametrize("job", ["publish", "verify"])
def test_every_credentialed_job_is_environment_gated(job: str) -> None:
    """The registry credential exists only inside the protected environment."""

    assert _lane()["jobs"][job].get("environment") == "registry-release"


def test_the_build_job_holds_no_publish_credential() -> None:
    """`build` runs on every dispatch, before anyone has approved anything."""

    assert "FORGEJO_PUBLISH_TOKEN" not in _run_text("build")
    assert _lane()["jobs"]["build"].get("environment") is None


def test_a_published_version_cannot_be_republished() -> None:
    """Immutability is enforced where it is cheap — before the build."""

    assert "ls-remote --exit-code --tags" in _run_text("build")


def test_the_dispatched_version_must_match_package_metadata() -> None:
    """A lane that derives the tag can publish a version nobody typed; one that
    trusts the input can publish a version the package does not claim.
    """

    assert "pyproject version" in _run_text("build")


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not present")
def test_the_audit_script_is_executable() -> None:
    """CI invokes it as `./scripts/audit_image.sh`, not `bash …`."""

    assert (PROJECT_ROOT / "scripts/audit_image.sh").stat().st_mode & 0o111
