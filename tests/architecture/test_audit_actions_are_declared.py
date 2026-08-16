"""Audit vocabulary is declared in one place, in both directions.

ADR-0008's rule, applied locally. `dotmac_integration` declares its three
`integration.*` actions on its module manifest and a Starter registry refuses an
undeclared one at the write. This assembly composes a released wheel and cannot
add to that manifest, so it owns a SEPARATE prefix — and the same discipline has
to be reproduced here or the `integrator.*` vocabulary becomes whatever string
literals happen to be in the file.

Both directions matter and they fail differently:

* an action written but not declared cannot be reviewed or deprecated, because
  nothing lists it;
* an action declared but never written is dead vocabulary that reads like a
  working trail — someone searching the ledger for it concludes the event never
  happened, rather than that it was never recorded.
"""

from __future__ import annotations

import ast
from pathlib import Path

from dotmac_integrator.operations import (
    INTEGRATOR_AUDIT_ACTION_PREFIX,
    INTEGRATOR_AUDIT_ACTIONS,
)

SRC = Path(__file__).resolve().parents[2] / "src" / "dotmac_integrator"


def _written_actions() -> set[str]:
    """Every string literal passed as `action=` anywhere in the assembly."""
    written: set[str] = set()
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg != "action":
                    continue
                if isinstance(keyword.value, ast.Constant) and isinstance(
                    keyword.value.value, str
                ):
                    written.add(keyword.value.value)
    return written


def test_every_written_action_is_declared() -> None:
    undeclared = sorted(_written_actions() - set(INTEGRATOR_AUDIT_ACTIONS))
    assert not undeclared, (
        f"{undeclared} are written but not declared in "
        "`INTEGRATOR_AUDIT_ACTIONS`. A code with no declaration cannot be "
        "reviewed or deprecated"
    )


def test_every_declared_action_has_a_writer() -> None:
    orphans = sorted(set(INTEGRATOR_AUDIT_ACTIONS) - _written_actions())
    assert not orphans, (
        f"{orphans} are declared with no writer. Dead vocabulary reads like a "
        "working trail: someone searching for it concludes the event did not "
        "happen rather than that it was never recorded"
    )


def test_the_assembly_never_writes_the_modules_vocabulary() -> None:
    """`integration.*` belongs to `dotmac-integration`'s manifest.

    Writing one from here would make this deployment a second author of someone
    else's registry — the exact failure hard rule 12 exists to prevent. The
    assembly's own operations use its own prefix.
    """
    trespass = sorted(a for a in _written_actions() if a.startswith("integration."))
    assert not trespass, trespass
    assert all(
        action.startswith(f"{INTEGRATOR_AUDIT_ACTION_PREFIX}.")
        for action in INTEGRATOR_AUDIT_ACTIONS
    )


def test_the_scan_actually_finds_actions() -> None:
    """Sensitivity proof: both directions above are set differences, and two
    empty sets satisfy either one."""
    assert INTEGRATOR_AUDIT_ACTIONS
    found = _written_actions()
    assert found, "the AST scan found no `action=` literal at all"
    assert "integrator.installation.enabled" in found


def test_the_scan_bites_on_a_planted_undeclared_action(tmp_path: Path) -> None:
    planted = tmp_path / "planted.py"
    planted.write_text(
        'record(db, action="integrator.something.undeclared", entity_type="x")\n',
        encoding="utf-8",
    )
    tree = ast.parse(planted.read_text(encoding="utf-8"))
    found = {
        keyword.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for keyword in node.keywords
        if keyword.arg == "action"
        and isinstance(keyword.value, ast.Constant)
        and isinstance(keyword.value.value, str)
    }
    assert found == {"integrator.something.undeclared"}
    assert found - set(INTEGRATOR_AUDIT_ACTIONS)
