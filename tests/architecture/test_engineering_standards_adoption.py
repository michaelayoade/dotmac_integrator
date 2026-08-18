"""The Integrator cannot silently leave fleet engineering governance."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / ".dotmac/standards-profile.json"
WORKFLOW_PATH = ROOT / ".github/workflows/engineering-standards.yml"
GOVERNANCE_URL = "https://github.com/michaelayoade/dotmac_governance"
ACTION_RE = re.compile(
    r"uses:\s+michaelayoade/dotmac_governance/"
    r"\.github/actions/standards-check@([0-9a-f]{40})"
)


def _violations(profile_text: str, workflow_text: str) -> tuple[str, ...]:
    profile = json.loads(profile_text)
    governance = profile.get("governance_model", {})
    repository = profile.get("repository", {})
    match = ACTION_RE.search(workflow_text)
    workflow_revision = match.group(1) if match else None
    profile_revision = governance.get("revision")

    checks = {
        "profile schema is not 9": profile.get("schema_version") == 9,
        "repository identity drifted": repository
        == {
            "canonical_url": "https://github.com/michaelayoade/dotmac_integrator",
            "default_branch": "main",
        },
        "enforcement is not required": profile.get("enforcement_mode") == "required",
        "Governance source is not an accepted immutable pin": governance.get("kind")
        == "pinned"
        and governance.get("canonical_url") == GOVERNANCE_URL
        and governance.get("status") == "accepted"
        and isinstance(profile_revision, str)
        and re.fullmatch(r"[0-9a-f]{40}", profile_revision) is not None,
        "required Governance action is missing": workflow_revision is not None,
        "workflow and profile revisions disagree": workflow_revision
        == profile_revision,
        "workflow does not run on pull requests": "pull_request:" in workflow_text,
        "workflow does not run on main pushes": "branches: [main]" in workflow_text,
    }
    return tuple(message for message, holds in checks.items() if not holds)


def test_engineering_governance_is_pinned_and_required() -> None:
    assert (
        _violations(
            PROFILE_PATH.read_text(encoding="utf-8"),
            WORKFLOW_PATH.read_text(encoding="utf-8"),
        )
        == ()
    )


def test_the_pin_guard_bites_on_workflow_drift() -> None:
    profile_text = PROFILE_PATH.read_text(encoding="utf-8")
    workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert ACTION_RE.search(workflow_text), "the sensitivity mutation needs a real pin"
    drifted = ACTION_RE.sub(
        "uses: michaelayoade/dotmac_governance/"
        ".github/actions/standards-check@" + "0" * 40,
        workflow_text,
        count=1,
    )

    assert "workflow and profile revisions disagree" in _violations(
        profile_text, drifted
    )
